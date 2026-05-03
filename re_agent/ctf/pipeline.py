"""
CTF 求解 Pipeline

核心流程：分析 -> 画像 -> 求解 -> 验证 -> 输出
"""

import json
from pathlib import Path

from ..pipeline import run_analysis
from .models import SolveResult
from .profiler import build_profile
from .validator import FlagValidator
from .solvers.base import SolverContext
from .solvers.static_flag import StaticFlagSolver


DEFAULT_SOLVERS = [
    StaticFlagSolver(),
]


def solve_challenge(
    sample_path: str,
    output_dir: str,
    flag_regex: str,
    skip_ghidra: bool = True,
    timeout: int = 120,
    validate: bool = True,
) -> SolveResult:
    """一键求解 CTF 挑战"""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # 1. 静态分析
    analysis = run_analysis(
        sample_path=sample_path,
        output_dir=str(out),
        skip_ghidra=skip_ghidra,
    )

    # 2. 构建挑战画像
    profile = build_profile(analysis)

    ctx = SolverContext(
        profile=profile,
        output_dir=out,
        flag_regex=flag_regex,
        timeout=timeout,
    )

    # 3. 执行求解器
    candidates = []
    trace = []

    for solver in sorted(DEFAULT_SOLVERS, key=lambda s: s.score(ctx), reverse=True):
        score = solver.score(ctx)
        trace.append({"solver": solver.name, "score": score, "event": "start"})

        if score <= 0:
            continue

        try:
            got = solver.solve(ctx)
            candidates.extend(got)
            trace.append({
                "solver": solver.name,
                "event": "candidates",
                "count": len(got),
                "values": [x.value for x in got],
            })
        except Exception as e:
            trace.append({
                "solver": solver.name,
                "event": "error",
                "error": str(e),
            })

    # 4. 验证候选 flag
    if validate and candidates:
        validator = FlagValidator(timeout=min(timeout, 15))
        for c in candidates:
            vr = validator.validate(Path(sample_path), c.value)
            c.evidence.extend(vr.evidence)
            if vr.accepted:
                c.verified = True
                c.confidence = max(c.confidence, 0.97)

    solved = any(c.verified for c in candidates)

    result = SolveResult(
        status="solved" if solved else "unsolved",
        sha256=analysis.sample.sha256,
        candidates=candidates,
        method="static_flag",
        summary="Static flag scan completed",
    )

    _save_solve_result(out, result, trace)
    return result


def _save_solve_result(out: Path, result: SolveResult, trace: list[dict]) -> None:
    """保存求解结果"""
    payload = {
        "status": result.status,
        "sha256": result.sha256,
        "best_flag": result.best_flag,
        "method": result.method,
        "summary": result.summary,
        "candidates": [
            {
                "value": c.value,
                "source": c.source,
                "confidence": c.confidence,
                "verified": c.verified,
                "evidence": c.evidence,
            }
            for c in result.candidates
        ],
        "trace": trace,
    }

    (out / "solve_result.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
