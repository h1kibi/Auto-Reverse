"""
CTF Solve Pipeline v2.2 (v0.5.2 consistency)

Full SolveConfig integration, redaction, max_candidates, config_dump.
"""

import json
import uuid
from pathlib import Path
from datetime import datetime

from ..pipeline import run_analysis
from ..core.evidence import EvidenceGraph
from ..core.runlog import SolveTrace
from .models import SolveResult, SolverRun
from .profiler import build_profile
from .validator import FlagValidator, RedactionMode, redact_candidate
from .strategy import DeterministicPlanner, LLMPlanner, PlanMerger
from .solve_config import SolveConfig
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
    "static_flag": StaticFlagSolver, "encoding": EncodingSolver,
    "decoding": EncodingSolver, "dynamic_trace": DynamicTraceSolver,
    "z3_extractor": Z3ExtractorSolver, "z3_constraints": Z3ConstraintSolver,
    "angr_path": AngrPathSolver, "brute_force": BruteForceSolver,
    "patcher": PatcherSolver,
}

DEFAULT_SOLVERS = [cls() for cls in [
    StaticFlagSolver, EncodingSolver, DynamicTraceSolver,
    Z3ExtractorSolver, Z3ConstraintSolver, AngrPathSolver,
    PatcherSolver, BruteForceSolver,
]]


def _solver_enabled(name, config):
    if name == "dynamic_trace" and not config.enable_dynamic: return False
    if name == "angr_path" and not config.enable_angr: return False
    if name in ("z3_constraints", "z3_extractor") and not config.enable_z3: return False
    return True


def _rank_candidates(candidates):
    return sorted(candidates, key=lambda c: (c.get("verified", False), c.get("confidence", 0.0)), reverse=True)


def _redact_candidates_list(candidates, mode):
    if mode == RedactionMode.NONE: return candidates
    return [{**c, "value": redact_candidate(str(c.get("value", "")), mode)} for c in candidates]


def solve_challenge(
    sample_path, output_dir, flag_regex,
    skip_ghidra=True, timeout=120, validate=True,
    enable_memory=True, enable_llm_planner=False,
    write_reflection=True, config=None,
):
    config = config or SolveConfig(
        flag_regex=flag_regex, skip_ghidra=skip_ghidra,
        max_total_seconds=timeout, verify=validate,
        enable_memory=enable_memory, enable_llm_planner=enable_llm_planner,
        write_reflection=write_reflection,
    )
    redaction = RedactionMode.LOGS if config.redact_candidates_in_logs else RedactionMode.NONE

    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
    out = Path(output_dir) / run_id
    out.mkdir(parents=True, exist_ok=True)
    artifacts_dir = out / "artifacts"; artifacts_dir.mkdir(parents=True, exist_ok=True)
    trace = SolveTrace(out, run_id)
    trace.log_start(sample_path, {"flag_regex": config.flag_regex,
                    "timeout": config.max_total_seconds, "verify": config.verify})

    analysis = run_analysis(sample_path=sample_path, output_dir=str(artifacts_dir),
                            skip_ghidra=config.skip_ghidra)
    profile = build_profile(analysis)
    evidence = EvidenceGraph.from_analysis(analysis)
    (out / "profile.json").write_text(json.dumps(
        _profile_dict(profile), ensure_ascii=False, indent=2), encoding="utf-8")
    from ..version import __version__
    (out / "config_dump.json").write_text(json.dumps({
        "version": __version__,
        "flag_regex": config.flag_regex, "skip_ghidra": config.skip_ghidra,
        "max_total_seconds": config.max_total_seconds, "max_solver_seconds": config.max_solver_seconds,
        "enable_dynamic": config.enable_dynamic, "enable_angr": config.enable_angr,
        "enable_z3": config.enable_z3, "enable_memory": config.enable_memory,
        "allowed_input_channels": config.allowed_input_channels,
        "max_candidates": config.max_candidates,
        "redact_candidates_in_logs": config.redact_candidates_in_logs,
        "memory_db_path": config.memory_db_path,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    memory_hits = []
    if config.enable_memory:
        try:
            from ..memory.store import MemoryStore
            from ..memory.retriever import MemoryRetriever
            store = MemoryStore(config.memory_db_path)
            retriever = MemoryRetriever(store)
            memory_hits = retriever.retrieve_for_profile(_profile_dict(profile), top_k=5)
            store.close()
        except Exception:
            pass

    deterministic = DeterministicPlanner()
    base_plan = deterministic.build(profile)
    llm_plan = LLMPlanner().build(profile, memory_hits) if (config.enable_llm_planner) else None
    plan = PlanMerger().merge(base_plan, llm_plan, config.max_total_seconds)

    ctx = SolverContext(profile=profile, output_dir=artifacts_dir,
                        flag_regex=config.flag_regex, timeout=config.max_total_seconds,
                        evidence=evidence, memory_hits=memory_hits)

    all_candidates, solver_runs = [], []
    solver_instances = {s.name: s for s in DEFAULT_SOLVERS}
    step_index = 0
    validator = FlagValidator(timeout=min(config.max_total_seconds, 15), redaction=redaction)

    for step in plan.steps:
        step_index += 1
        trace.log_solver_start(step_index, step.name, step.budget_seconds)
        if not _solver_enabled(step.name, config):
            trace.log_solver_skip(step_index, step.name, "disabled by config")
            solver_runs.append(SolverRun(solver=step.name, status="skipped", score=0))
            continue
        solver_cls = SOLVER_MAP.get(step.name)
        if solver_cls is None:
            trace.log_solver_skip(step_index, step.name, "solver not available")
            solver_runs.append(SolverRun(solver=step.name, status="skipped", score=0))
            continue
        solver = solver_instances.get(step.name) or solver_cls()
        score_val = solver.score(ctx)
        if score_val <= 0:
            trace.log_solver_skip(step_index, step.name, f"score={score_val:.2f}")
            solver_runs.append(SolverRun(solver=step.name, status="skipped", score=score_val))
            continue
        run_status, run_error, candidates = "ok", None, []
        try:
            candidates = solver.solve(ctx)
        except Exception as e:
            run_status, run_error = "error", str(e)
            trace.log_solver_error(step_index, step.name, str(e))
        solver_candidates = [{"value": c.value, "source": c.source,
                               "confidence": c.confidence, "evidence": c.evidence,
                               "verified": False} for c in candidates]
        all_candidates.extend(solver_candidates)
        all_candidates = _rank_candidates(all_candidates)[:config.max_candidates]
        trace.log_solver_done(step_index, step.name,
            [redact_candidate(c["value"], redaction) for c in solver_candidates[:10]])
        solver_runs.append(SolverRun(solver=step.name, status=run_status, score=score_val,
                                      candidates=solver_candidates, error=run_error))
        if config.verify and solver_candidates:
            for c in _rank_candidates(solver_candidates)[:config.max_candidates]:
                vr = validator.validate(Path(sample_path), c["value"],
                                        output_dir=artifacts_dir,
                                        modes=config.allowed_input_channels)
                c.setdefault("evidence", []); c["evidence"].extend(vr.evidence or [])
                if vr.accepted:
                    c["verified"] = True; c["confidence"] = max(c["confidence"], 0.97)
                    c["validation_mode"] = vr.mode
                    trace.log_verification(step_index,
                        redact_candidate(c["value"], redaction), True, vr.mode)
                    return _finalize(analysis.sample.sha256, c, all_candidates,
                                     solver_runs, trace, out, profile, config, redaction)

    trace.log_solve_end(step_index, False, "", None)
    return _finalize(analysis.sample.sha256, None, all_candidates,
                     solver_runs, trace, out, profile, config, redaction)


def _finalize(sha256, winning, all_candidates, solver_runs, trace, out, profile, config, redaction):
    solved = winning is not None
    method = winning["source"] if winning else ""
    summary = ("solved by " + method) if solved else _summary(all_candidates, solver_runs)
    stored_winning = {**winning, "value": redact_candidate(winning["value"], redaction)} if winning else None

    result = SolveResult(status="solved" if solved else "unsolved", sha256=sha256,
                         verified=solved, winning_candidate=stored_winning,
                         method=method, candidates=all_candidates,
                         solver_runs=solver_runs, summary=summary)
    result.result_path = str(out / "solve_result.json")

    # Redacted outputs
    public_candidates = _redact_candidates_list(_rank_candidates(all_candidates)[:config.max_candidates], redaction)
    public_runs = [{"solver": r.solver, "status": r.status, "score": r.score,
                     "candidates": _redact_candidates_list(r.candidates or [], redaction),
                     "error": r.error} for r in solver_runs]

    trace.write_report(profile=_profile_dict(profile),
                       result={"status": result.status, "verified": result.verified,
                               "method": result.method, "winning_candidate": stored_winning,
                               "candidates": public_candidates},
                       solver_runs=public_runs)

    try:
        from .learning import generate_learning_report
        generate_learning_report(profile=_profile_dict(profile),
            solve_result={"verified": solved, "method": method, "winning_candidate": stored_winning},
            solver_runs=[{"solver": r["solver"], "status": r["status"]} for r in public_runs],
            output_dir=out)
    except Exception:
        pass

    (out / "manifest.json").write_text(json.dumps({
        "run_id": out.name, "timestamp": datetime.now().isoformat(),
        "sha256": sha256, "status": result.status,
        "verified": result.verified, "method": result.method,
        "best_flag": redact_candidate(result.best_flag or "", redaction),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "solve_result.json").write_text(json.dumps({
        "status": result.status, "sha256": result.sha256,
        "verified": result.verified,
        "best_flag": redact_candidate(result.best_flag or "", redaction),
        "method": result.method, "summary": result.summary,
        "winning_candidate": stored_winning,
        "candidates": public_candidates, "solver_runs": public_runs,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "candidates.json").write_text(json.dumps(
        public_candidates, ensure_ascii=False, indent=2), encoding="utf-8")

    if solved and winning and config.write_reflection:
        _reflect(profile, winning, solver_runs, config)

    return result


def _reflect(profile, winning, solver_runs, config):
    if not config.enable_memory: return
    try:
        from ..memory.schema import SelfLesson
        from ..memory.store import MemoryStore
        signals = set(profile.tags) | set(profile.comparison_hints) | set(profile.crypto_hints) | set(profile.encoding_hints)
        lesson = SelfLesson(
            id=f"lesson_{uuid.uuid4().hex[:12]}",
            challenge_sha256=profile.sha256, solved=True, verified=True,
            winning_solver=winning.get("source", ""),
            input_channel=winning.get("validation_mode", "unknown"),
            key_signals=sorted(signals),
            failed_attempts=[r.solver for r in solver_runs if r.status == "error"],
            successful_recipe=[f"{winning.get('source','?')} produced a verified candidate"],
            generalized_pattern=f"{winning.get('source','?')}: {','.join(sorted(signals)[:5])}",
            confidence=0.8)
        store = MemoryStore(config.memory_db_path)
        store.add_self_lesson(lesson)
        store.close()
    except Exception:
        pass


def _profile_dict(profile):
    return {"file_type": profile.file_type, "architecture": profile.architecture,
            "tags": profile.tags, "input_channels": profile.input_channels,
            "comparison_hints": profile.comparison_hints, "crypto_hints": profile.crypto_hints,
            "encoding_hints": profile.encoding_hints, "protections": profile.protections,
            "success_strings": profile.success_strings, "failure_strings": profile.failure_strings,
            "solver_hints": profile.solver_hints, "sha256": profile.sha256}


def _summary(all_candidates, solver_runs):
    ok = sum(1 for r in solver_runs if r.status == "ok")
    sources = sorted({c.get("source", "?") for c in all_candidates})
    return f"{ok}/{len(solver_runs)} solvers; candidates from {','.join(sources)}; not solved"
