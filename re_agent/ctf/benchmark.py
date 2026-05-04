"""
Three-mode benchmark with real pre-pass.

v0.6.8: auto-brain uses prepare_llm_state (profile/evidence/memory/context).
MockBrain for CI (no real API).
"""

import json
import time
import sys
import tempfile
from pathlib import Path
from dataclasses import dataclass, field


CHALLENGES_DIR = Path(__file__).parent.parent.parent / "tests" / "challenges"


@dataclass
class BenchmarkStats:
    attempted: int = 0
    verified: int = 0
    false_positive: int = 0
    avg_tokens: float = 0.0
    avg_seconds: float = 0.0
    solver_breakdown: dict[str, int] = field(default_factory=dict)
    memory_hit_usage_rate: float = 0.0
    errors: list[str] = field(default_factory=list)


def run_benchmark(modes=None, brain_name="deepseek") -> dict:
    modes = modes or ["auto-no-brain", "auto-brain"]
    results = {}
    for mode in modes:
        stats = _run_mode(mode, brain_name)
        results[mode] = {
            "attempted": stats.attempted, "verified": stats.verified,
            "false_positive": stats.false_positive,
            "avg_tokens": stats.avg_tokens, "avg_seconds": stats.avg_seconds,
            "solver_breakdown": stats.solver_breakdown,
            "memory_hit_usage_rate": stats.memory_hit_usage_rate,
            "errors": stats.errors,
        }
    if "auto-no-brain" in results and "auto-brain" in results:
        nb = results["auto-no-brain"]
        ab = results["auto-brain"]
        results["comparison"] = {
            "verified_delta": ab["verified"] - nb["verified"],
            "false_positive_delta": ab["false_positive"] - nb["false_positive"],
            "memory_hit_usage_rate": ab.get("memory_hit_usage_rate", 0),
        }
    return results


def _run_mode(mode, brain_name):
    stats = BenchmarkStats()
    dirs = sorted([d for d in CHALLENGES_DIR.iterdir() if d.is_dir() and d.name != "build"])
    for challenge_dir in dirs:
        expected_file = challenge_dir / "expected.json"
        if not expected_file.exists():
            continue
        expected = json.loads(expected_file.read_text())
        binary = _find_binary(challenge_dir)
        if not binary:
            stats.errors.append(f"{challenge_dir.name}: no binary")
            continue
        try:
            started = time.time()
            if mode == "auto-no-brain":
                result = _run_auto_no_brain(binary, expected)
            elif mode == "auto-brain":
                result = _run_auto_brain(binary, expected, brain_name)
            else:
                continue
            elapsed = time.time() - started
            stats.attempted += 1; stats.avg_seconds += elapsed
            if result.get("verified"):
                stats.verified += 1
                stats.solver_breakdown[result.get("method", "?")] = \
                    stats.solver_breakdown.get(result.get("method", "?"), 0) + 1
            if result.get("flagged_but_wrong"):
                stats.false_positive += 1
            if result.get("tokens"):
                stats.avg_tokens += result["tokens"]
                stats.memory_hit_usage_rate += bool(result.get("memory_refs"))
        except Exception as e:
            stats.errors.append(f"{challenge_dir.name}: {e}")
    if stats.attempted > 0:
        stats.avg_seconds /= stats.attempted
        stats.avg_tokens /= stats.attempted
        stats.memory_hit_usage_rate /= stats.attempted
    return stats


def _run_auto_no_brain(binary, expected):
    from re_agent.ctf.pipeline import solve_challenge
    out = Path(tempfile.mkdtemp(prefix="bench_"))
    try:
        r = solve_challenge(sample_path=str(binary), output_dir=str(out),
                            flag_regex=expected.get("flag_regex", r"flag\{[^}]+\}"),
                            skip_ghidra=True, timeout=expected.get("max_seconds", 60),
                            validate=expected.get("must_verify", False))
        return {"verified": r.verified, "method": r.method, "best_flag": r.best_flag,
                "tokens": 0, "flagged_but_wrong": False}
    except Exception:
        return {"verified": False, "method": "", "tokens": 0, "flagged_but_wrong": False}


def prepare_llm_state(binary, expected, out, memory_db):
    """Build rich state with pre-pass: profile + evidence + memory + context bundles."""
    from re_agent.ctf.pipeline import run_analysis
    from re_agent.ctf.profiler import build_profile
    from re_agent.core.evidence import EvidenceGraph
    from re_agent.ctf.context_bundle import build_evidence_brief

    analysis = run_analysis(sample_path=str(binary), output_dir=str(out),
                            skip_ghidra=expected.get("skip_ghidra", True))
    profile = build_profile(analysis)
    evidence = EvidenceGraph.from_analysis(analysis)

    memory_hits = []
    if memory_db:
        try:
            from re_agent.memory.store import MemoryStore
            from re_agent.memory.retriever import MemoryRetriever
            store = MemoryStore(memory_db)
            retriever = MemoryRetriever(store)
            memory_hits = retriever.retrieve_for_profile({
                "tags": profile.tags, "comparison_hints": profile.comparison_hints,
                "encoding_hints": profile.encoding_hints, "crypto_hints": profile.crypto_hints,
            }, top_k=3)
            store.close()
        except Exception:
            pass

    brief = build_evidence_brief(profile)
    return {
        "run_id": out.name, "sample_path": str(binary),
        "output_dir": str(out), "profile": profile,
        "evidence_brief": brief.model_dump(),
        "memory_hits": memory_hits[:5],
        "context_bundles": [],
        "observations": [],
        "budget_seconds": expected.get("max_seconds", 60),
    }


def _run_auto_brain(binary, expected, brain_name):
    """Run with rich pre-pass: profile + evidence + memory."""
    out = Path(tempfile.mkdtemp(prefix="bench_brain_"))
    brain = _get_brain(brain_name)

    from re_agent.brain.context_builder import BrainContextBuilder
    from re_agent.ctf.llm_runtime import LLMReverseRuntime
    from re_agent.brain.policy import RuntimePolicy

    builder = BrainContextBuilder(token_budget=4096)
    policy = RuntimePolicy(allow_dynamic=True, max_steps=expected.get("max_steps", 3))
    state = prepare_llm_state(binary, expected, out,
                              expected.get("memory_db", "memory.db"))
    runtime = LLMReverseRuntime(brain=brain, tool_executor=None,
                                 context_builder=builder,
                                 max_steps=policy.max_steps, policy=policy)
    result = runtime.run(state)

    tokens = sum(e.get("context", {}).get("estimated_tokens", 0)
                 for e in result.get("llm_trace", []))
    memory_refs = sorted({
        ref for e in result.get("llm_trace", [])
        for a in e.get("brain_result", {}).get("actions", [])
        for ref in a.get("memory_refs", [])
    })

    return {
        "verified": bool(result.get("solved")),
        "method": result.get("winning_candidate", {}).get("source", "auto_brain"),
        "tokens": tokens, "flagged_but_wrong": False,
        "memory_refs": memory_refs,
    }


def _get_brain(name):
    if name == "mock":
        from .mock_brain import MockBrain
        return MockBrain()
    if name == "deepseek":
        from re_agent.brain.deepseek import DeepSeekBrain
        return DeepSeekBrain()
    from re_agent.brain.deepseek import OpenAIBrain
    return OpenAIBrain()


def _find_binary(challenge_dir):
    build_dir = CHALLENGES_DIR / "build"
    for c in [build_dir / challenge_dir.name, build_dir / (challenge_dir.name + ".exe")]:
        if c.exists():
            return c
    return None


def print_benchmark_report(results):
    print(f"\n{'='*70}")
    print("Auto-Reverse Three-Mode Benchmark")
    print(f"{'='*70}")
    print(f"{'Metric':<30} {'no-brain':>12} {'brain':>12}")
    print("-" * 70)
    for mode_name, mode_data in results.items():
        if mode_name == "comparison":
            continue
        print(f"{mode_name+' verified':<30} {str(mode_data.get('verified',0)):>12}")
        print(f"{mode_name+' avg_tokens':<30} {str(int(mode_data.get('avg_tokens',0))):>12}")
        print(f"{mode_name+' avg_seconds':<30} {str(round(mode_data.get('avg_seconds',0),1)):>12}")
    if results.get("comparison"):
        c = results["comparison"]
        print("-" * 70)
        print(f"{'brain verified delta':<30} {str(c.get('verified_delta',0)):>12}")
        print(f"{'memory_hit_rate':<30} {str(round(c.get('memory_hit_usage_rate',0)*100)):>9}%")
    print(f"{'='*70}")

if __name__ == "__main__":
    print_benchmark_report(run_benchmark(["auto-no-brain"]))
