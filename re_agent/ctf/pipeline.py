"""
CTF 求解 Pipeline (v2)

核心流程: Triage -> Profile -> Evidence -> Memory -> Plan -> Execute -> Verify -> Reflect
"""

import json
import uuid
from pathlib import Path
from datetime import datetime

from ..pipeline import run_analysis
from ..core.evidence import EvidenceGraph
from ..core.runlog import SolveTrace, TraceEvent
from .models import SolveResult, SolverRun
from .profiler import build_profile
from .validator import FlagValidator
from .strategy import DeterministicPlanner, LLMPlanner, PlanMerger
from .solvers.base import SolverContext
from .solvers.static_flag import StaticFlagSolver
from .solvers.encoding import EncodingSolver
from .solvers.z3_constraints import Z3ConstraintSolver
from .solvers.z3_extractor import Z3ExtractorSolver
from .solvers.angr_path import AngrPathSolver
from .solvers.dynamic_trace import DynamicTraceSolver
from .solvers.brute_force import BruteForceSolver
from .solvers.patcher import PatcherSolver


SOLVER_MAP = {
    "static_flag": StaticFlagSolver,
    "encoding": EncodingSolver,
    "decoding": EncodingSolver,
    "dynamic_trace": DynamicTraceSolver,
    "z3_extractor": Z3ExtractorSolver,
    "z3_constraints": Z3ConstraintSolver,
    "angr_path": AngrPathSolver,
    "brute_force": BruteForceSolver,
    "patcher": PatcherSolver,
}

DEFAULT_SOLVERS = [cls() for cls in [
    StaticFlagSolver, EncodingSolver, DynamicTraceSolver,
    Z3ExtractorSolver, Z3ConstraintSolver, AngrPathSolver,
    PatcherSolver, BruteForceSolver,
]]


def solve_challenge(
    sample_path: str,
    output_dir: str,
    flag_regex: str,
    skip_ghidra: bool = True,
    timeout: int = 120,
    validate: bool = True,
    enable_memory: bool = True,
    enable_llm_planner: bool = False,
    write_reflection: bool = True,
) -> SolveResult:

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
    out = Path(output_dir) / run_id
    out.mkdir(parents=True, exist_ok=True)

    artifacts_dir = out / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    trace = SolveTrace(out, run_id)
    trace.log_start(sample_path, {
        "flag_regex": flag_regex, "timeout": timeout,
        "validate": validate, "enable_memory": enable_memory,
    })

    # ── 1. Static Triage ──
    analysis = run_analysis(
        sample_path=sample_path,
        output_dir=str(artifacts_dir),
        skip_ghidra=skip_ghidra,
    )

    # ── 2. Profile + Evidence (rich: from tool artifacts) ──
    profile = build_profile(analysis)
    evidence = EvidenceGraph.from_analysis(analysis)  # enriched with R2/Ghidra xref

    (out / "profile.json").write_text(
        json.dumps(_profile_to_dict(profile), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # ── 3. Memory Retrieval ──
    memory_hits = []
    if enable_memory:
        try:
            from ..memory.store import MemoryStore
            from ..memory.retriever import MemoryRetriever
            store = MemoryStore("memory.db")
            retriever = MemoryRetriever(store)
            memory_hits = retriever.retrieve_for_profile(_profile_to_dict(profile), top_k=5)
            store.close()
        except Exception:
            pass

    # ── 4. Planning ──
    deterministic = DeterministicPlanner()
    base_plan = deterministic.build(profile)

    llm_plan = None
    if enable_llm_planner:
        llm = LLMPlanner()
        llm_plan = llm.build(profile, memory_hits)

    merger = PlanMerger()
    plan = merger.merge(base_plan, llm_plan, max_total_seconds=timeout)

    # ── 5. Execution ──
    ctx = SolverContext(
        profile=profile,
        output_dir=artifacts_dir,
        flag_regex=flag_regex,
        timeout=timeout,
        evidence=evidence,
        memory_hits=memory_hits,
    )

    all_candidates: list[dict] = []
    solver_runs: list[SolverRun] = []
    solver_instances = {s.name: s for s in DEFAULT_SOLVERS}
    step_index = 0

    for step in plan.steps:
        step_index += 1
        trace.log_solver_start(step_index, step.name, step.budget_seconds)

        solver_cls = SOLVER_MAP.get(step.name)
        if solver_cls is None:
            trace.log_solver_skip(step_index, step.name, "solver not available")
            solver_runs.append(SolverRun(solver=step.name, status="skipped", score=0))
            continue

        solver = solver_instances.get(step.name) or solver_cls()
        solver_score = solver.score(ctx)
        if solver_score <= 0:
            trace.log_solver_skip(step_index, step.name, f"score={solver_score:.2f} <= 0")
            solver_runs.append(SolverRun(solver=step.name, status="skipped", score=solver_score))
            continue

        run_status: str = "ok"
        run_error: str | None = None
        candidates: list = []

        try:
            candidates = solver.solve(ctx)
        except Exception as e:
            run_status = "error"
            run_error = str(e)
            trace.log_solver_error(step_index, step.name, str(e))

        solver_candidates = [
            {"value": c.value, "source": c.source,
             "confidence": c.confidence, "evidence": c.evidence, "verified": False}
            for c in candidates
        ]
        all_candidates.extend(solver_candidates)
        trace.log_solver_done(step_index, step.name, [c["value"] for c in solver_candidates[:10]])

        solver_runs.append(SolverRun(
            solver=step.name, status=run_status, score=solver_score,
            candidates=solver_candidates, error=run_error,
        ))

        # ── 实时验证 ──
        if validate and solver_candidates:
            validator = FlagValidator(timeout=min(timeout, 15))
            for c in solver_candidates:
                vr = validator.validate(Path(sample_path), c["value"], output_dir=artifacts_dir)
                c.setdefault("evidence", [])
                if isinstance(vr.evidence, list):
                    c["evidence"].extend(vr.evidence)
                if vr.accepted:
                    c["verified"] = True
                    c["confidence"] = max(c["confidence"], 0.97)
                    c["validation_mode"] = vr.mode
                    trace.log_verification(step_index, c["value"], True, vr.mode)
    result = _finalize_result(
        sha256=analysis.sample.sha256, winning=c,
        all_candidates=all_candidates, solver_runs=solver_runs,
        trace=trace, out=out, profile=profile,
        write_reflection=write_reflection, enable_memory=enable_memory,
    )
    result.result_path = str(out / "solve_result.json")
    _write_manifest(out, profile, result)
    return result

    # ── 6. 未解出 ──
    trace.log_solve_end(step_index, False, "", None)
    result = _finalize_result(
        sha256=analysis.sample.sha256, winning=None,
        all_candidates=all_candidates, solver_runs=solver_runs,
        trace=trace, out=out, profile=profile,
        write_reflection=write_reflection, enable_memory=enable_memory,
    )
    result.result_path = str(out / "solve_result.json")
    _write_manifest(out, profile, result)
    return result


# ── helpers ──

def _finalize_result(
    sha256: str, winning: dict | None,
    all_candidates: list[dict], solver_runs: list[SolverRun],
    trace: SolveTrace, out: Path, profile,
    write_reflection: bool, enable_memory: bool,
) -> SolveResult:
    solved = winning is not None
    method = winning["source"] if winning else ""
    summary = "solved by " + method if solved else _build_summary(all_candidates, solver_runs)

    result = SolveResult(
        status="solved" if solved else "unsolved",
        sha256=sha256, verified=solved,
        winning_candidate=winning, method=method,
        candidates=all_candidates, solver_runs=solver_runs,
        summary=summary,
    )

    # Report
    trace.write_report(
        profile=_profile_to_dict(profile),
        result={"status": result.status, "verified": result.verified,
                "method": result.method, "winning_candidate": winning,
                "candidates": result.candidates},
        solver_runs=[{"solver": r.solver, "status": r.status,
                      "score": r.score, "candidates": r.candidates}
                     for r in solver_runs],
    )

    # Learning report
    try:
        from .learning import generate_learning_report
        generate_learning_report(
            profile=_profile_to_dict(profile),
            solve_result={"verified": solved, "method": method,
                          "winning_candidate": winning},
            solver_runs=[{"solver": r.solver, "status": r.status}
                         for r in solver_runs],
            output_dir=out,
        )
    except Exception:
        pass

    # Reproducer
    if solved and winning:
        _write_reproducer(out, winning)

    # Reflection
    if write_reflection and solved:
        _reflect(profile, winning, solver_runs, enable_memory)

    # Save result JSON
    (out / "solve_result.json").write_text(
        json.dumps({
            "status": result.status, "sha256": result.sha256,
            "verified": result.verified, "best_flag": result.best_flag,
            "method": result.method, "summary": result.summary,
            "winning_candidate": winning,
            "candidates": result.candidates,
            "solver_runs": [{"solver": r.solver, "status": r.status,
                             "score": r.score, "candidates": r.candidates,
                             "error": r.error} for r in solver_runs],
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # Candidates
    (out / "candidates.json").write_text(
        json.dumps(all_candidates, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return result


def _build_summary(all_candidates: list[dict], solver_runs: list[SolverRun]) -> str:
    ok = sum(1 for r in solver_runs if r.status == "ok")
    sources = sorted({c.get("source", "?") for c in all_candidates})
    return f"{ok}/{len(solver_runs)} solvers; candidates from {', '.join(sources)}; not solved"


def _write_reproducer(out: Path, winning: dict):
    body = f'''import subprocess, sys

candidate = {winning["value"]!r}
mode = "{winning.get("validation_mode", "argv")}"

if mode == "argv":
    p = subprocess.run(["./sample", candidate], capture_output=True, timeout=10)
else:
    p = subprocess.run(["./sample"], input=(candidate + "\\n").encode(),
                       capture_output=True, timeout=10)
print(p.stdout.decode(errors="replace"))
print(p.stderr.decode(errors="replace"))
sys.exit(0 if p.returncode == 0 else 1)
'''
    (out / "reproduce.py").write_text(body, encoding="utf-8")


def _write_manifest(out: Path, profile, result: SolveResult):
    (out / "manifest.json").write_text(json.dumps({
        "run_id": out.name,
        "timestamp": datetime.now().isoformat(),
        "sha256": result.sha256,
        "status": result.status,
        "verified": result.verified,
        "method": result.method,
        "best_flag": result.best_flag,
    }, ensure_ascii=False, indent=2), encoding="utf-8")


def _reflect(profile, winning, solver_runs, enable_memory):
    """Auto-generate SelfLesson (NEVER store raw flag value)"""
    try:
        from ..memory.schema import SelfLesson
        from ..memory.store import MemoryStore
        signals = set()
        signals.update(profile.tags)
        signals.update(profile.comparison_hints)
        signals.update(profile.crypto_hints)
        signals.update(profile.encoding_hints)

        # Build recipe WITHOUT raw flag
        winning_source = winning.get("source", "?") if winning else "?"
        recipe = [
            f"{winning_source} produced a candidate",
            f"candidate validated through {winning.get('validation_mode', 'unknown')}" if winning else "",
            "flag length: " + str(len(winning.get('value', ''))) if winning else "",
        ]

        lesson = SelfLesson(
            id=f"lesson_{uuid.uuid4().hex[:12]}",
            challenge_sha256=profile.sha256,
            solved=True, verified=True,
            winning_solver=winning_source,
            input_channel=winning.get("validation_mode", "unknown") if winning else "",
            key_signals=sorted(signals),
            failed_attempts=[r.solver for r in solver_runs if r.status == "error"],
            successful_recipe=recipe,
            generalized_pattern=f"{winning_source}: {', '.join(sorted(signals)[:5])}",
            confidence=0.8,
        )
        store = MemoryStore("memory.db")
        store.add_self_lesson(lesson)
        store.close()
    except Exception:
        pass


def _profile_to_dict(profile) -> dict:
    return {
        "file_type": profile.file_type,
        "architecture": profile.architecture,
        "tags": profile.tags,
        "input_channels": profile.input_channels,
        "comparison_hints": profile.comparison_hints,
        "crypto_hints": profile.crypto_hints,
        "encoding_hints": profile.encoding_hints,
        "protections": profile.protections,
        "success_strings": profile.success_strings,
        "failure_strings": profile.failure_strings,
        "solver_hints": profile.solver_hints,
        "sha256": profile.sha256,
    }
