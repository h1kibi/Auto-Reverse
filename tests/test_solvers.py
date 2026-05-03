"""
CTF 求解器回归测试

测试 StaticFlagSolver 和 Validator 的核心逻辑
"""

import json
from pathlib import Path

from re_agent.ctf.models import FlagCandidate, ChallengeProfile, SolveResult
from re_agent.ctf.solvers.base import SolverContext
from re_agent.ctf.solvers.static_flag import StaticFlagSolver, _dedup


def test_static_flag_solver_direct_match():
    """测试直接匹配 flag"""
    solver = StaticFlagSolver()

    profile = ChallengeProfile(
        sample_path=Path("test.bin"),
        sha256="a" * 64,
        strings=[
            "some random string",
            "flag{this_is_the_flag}",
            "another string",
        ],
    )

    ctx = SolverContext(
        profile=profile,
        output_dir=Path("/tmp"),
        flag_regex=r"flag\{[^}]+\}",
    )

    candidates = solver.solve(ctx)

    assert len(candidates) == 1
    assert candidates[0].value == "flag{this_is_the_flag}"
    assert candidates[0].confidence == 0.95
    assert candidates[0].source == "static_flag"


def test_static_flag_solver_base64():
    """测试 base64 编码 flag"""
    import base64

    solver = StaticFlagSolver()

    flag = "flag{base64_encoded}"
    encoded = base64.b64encode(flag.encode()).decode()

    profile = ChallengeProfile(
        sample_path=Path("test.bin"),
        sha256="a" * 64,
        strings=[encoded],
    )

    ctx = SolverContext(
        profile=profile,
        output_dir=Path("/tmp"),
        flag_regex=r"flag\{[^}]+\}",
    )

    candidates = solver.solve(ctx)

    assert len(candidates) == 1
    assert candidates[0].value == flag
    assert candidates[0].confidence == 0.85


def test_static_flag_solver_hex():
    """测试 hex 编码 flag"""
    solver = StaticFlagSolver()

    flag = "flag{hex_test}"
    encoded = flag.encode().hex()

    profile = ChallengeProfile(
        sample_path=Path("test.bin"),
        sha256="a" * 64,
        strings=[encoded],
    )

    ctx = SolverContext(
        profile=profile,
        output_dir=Path("/tmp"),
        flag_regex=r"flag\{[^}]+\}",
    )

    candidates = solver.solve(ctx)

    assert len(candidates) == 1
    assert candidates[0].value == flag


def test_static_flag_solver_no_match():
    """测试无匹配"""
    solver = StaticFlagSolver()

    profile = ChallengeProfile(
        sample_path=Path("test.bin"),
        sha256="a" * 64,
        strings=["no flag here", "just normal text"],
    )

    ctx = SolverContext(
        profile=profile,
        output_dir=Path("/tmp"),
        flag_regex=r"flag\{[^}]+\}",
    )

    candidates = solver.solve(ctx)

    assert len(candidates) == 0


def test_static_flag_solver_multiple():
    """测试多个 flag"""
    solver = StaticFlagSolver()

    profile = ChallengeProfile(
        sample_path=Path("test.bin"),
        sha256="a" * 64,
        strings=[
            "flag{first_flag}",
            "flag{second_flag}",
            "not a flag",
        ],
    )

    ctx = SolverContext(
        profile=profile,
        output_dir=Path("/tmp"),
        flag_regex=r"flag\{[^}]+\}",
    )

    candidates = solver.solve(ctx)

    assert len(candidates) == 2
    values = [c.value for c in candidates]
    assert "flag{first_flag}" in values
    assert "flag{second_flag}" in values


def test_dedup_candidates():
    """测试去重"""
    candidates = [
        FlagCandidate(value="flag{test}", source="solver1", confidence=0.9),
        FlagCandidate(value="flag{test}", source="solver2", confidence=0.8),
        FlagCandidate(value="flag{other}", source="solver1", confidence=0.7),
    ]

    result = _dedup(candidates)

    assert len(result) == 2
    # 高置信度的排前面
    assert result[0].value == "flag{test}"
    assert result[0].confidence == 0.9


def test_solve_result_best_flag():
    """测试 SolveResult.best_flag"""
    result = SolveResult(
        status="solved",
        sha256="a" * 64,
        candidates=[
            FlagCandidate(value="flag{low}", source="test", confidence=0.5),
            FlagCandidate(value="flag{high}", source="test", confidence=0.9, verified=True),
            FlagCandidate(value="flag{mid}", source="test", confidence=0.7),
        ],
    )

    assert result.best_flag == "flag{high}"


def test_solve_result_best_flag_no_verified():
    """测试无验证时选最高置信度"""
    result = SolveResult(
        status="unsolved",
        sha256="a" * 64,
        candidates=[
            FlagCandidate(value="flag{low}", source="test", confidence=0.5),
            FlagCandidate(value="flag{high}", source="test", confidence=0.9),
        ],
    )

    assert result.best_flag == "flag{high}"


def test_solve_result_no_candidates():
    """测试无候选"""
    result = SolveResult(
        status="unsolved",
        sha256="a" * 64,
    )

    assert result.best_flag is None
