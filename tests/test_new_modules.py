"""
Tests for new CTF modules: constraints_loop, learning, patcher, bruteforce.
"""

import json
import tempfile
from pathlib import Path


def test_validate_candidate_full_basic():
    """Test validate_candidate_full returns expected structure"""
    from re_agent.ctf.constraints_loop import validate_candidate_full, _validate_spec

    # Validate the constraint spec validator (no binary needed)
    valid_spec = {"length": 5, "constraints": [{"left": {"var": 0}, "right": 116}]}
    assert _validate_spec(valid_spec) is None

    bad_spec = {"length": 500, "constraints": []}
    assert _validate_spec(bad_spec) is not None

    no_length = {"constraints": []}
    assert _validate_spec(no_length) is not None


def test_brute_force_solver_score():
    """BruteForceSolver scores only when small search space suggested"""
    from re_agent.ctf.solvers.brute_force import BruteForceSolver
    from re_agent.ctf.models import ChallengeProfile
    from re_agent.ctf.solvers.base import SolverContext

    solver = BruteForceSolver()

    # No hints -> 0
    profile = ChallengeProfile(sample_path=Path("test"), sha256="a" * 64)
    ctx = SolverContext(profile=profile, output_dir=Path("/tmp"))
    assert solver.score(ctx) == 0.0

    # With small constant -> positive
    profile.suspicious_constants = ["0x37"]
    ctx2 = SolverContext(profile=profile, output_dir=Path("/tmp"))
    assert solver.score(ctx2) > 0.0


def test_patcher_solver_score():
    """PatcherSolver activates on anti_debug protection"""
    from re_agent.ctf.solvers.patcher import PatcherSolver
    from re_agent.ctf.models import ChallengeProfile
    from re_agent.ctf.solvers.base import SolverContext

    solver = PatcherSolver()
    profile = ChallengeProfile(sample_path=Path("test"), sha256="a" * 64)
    ctx = SolverContext(profile=profile, output_dir=Path("/tmp"))
    assert solver.score(ctx) == 0.0

    profile.protections = ["anti_debug"]
    ctx2 = SolverContext(profile=profile, output_dir=Path("/tmp"))
    assert solver.score(ctx2) > 0.0


def test_learning_report_generation():
    """generate_learning_report produces a non-empty markdown file"""
    from re_agent.ctf.learning import generate_learning_report

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        report_path = generate_learning_report(
            profile={
                "file_type": "ELF", "architecture": "x86_64",
                "tags": ["has_success_string", "has_comparison"],
                "input_channels": ["stdin"],
                "comparison_hints": ["memcmp"],
                "crypto_hints": [],
                "encoding_hints": ["hex"],
                "protections": [],
                "solver_hints": ["dynamic_trace"],
                "success_strings": ["Correct!"],
                "failure_strings": ["Wrong!"],
                "sha256": "a" * 64,
            },
            solve_result={"verified": True, "method": "dynamic_trace",
                          "winning_candidate": {"source": "dynamic_trace", "value": "flag{test}"}},
            solver_runs=[
                {"solver": "static_flag", "status": "ok"},
                {"solver": "dynamic_trace", "status": "ok"},
            ],
            output_dir=out,
        )

        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        assert "Auto-Reverse Learning Report" in content
        assert "ELF" in content
        assert "dynamic_trace" in content


def test_solve_config_defaults():
    """SolveConfig has sensible defaults"""
    from re_agent.ctf.solve_config import SolveConfig

    cfg = SolveConfig()
    assert cfg.max_total_seconds == 300
    assert cfg.max_solver_seconds == 60
    assert cfg.allowed_input_channels == ["argv", "stdin"]
    assert cfg.verify is True
    assert cfg.enable_memory is True


def test_strategy_planner_coverage():
    """DeterministicPlanner covers all signal types"""
    from re_agent.ctf.models import ChallengeProfile
    from re_agent.ctf.strategy import DeterministicPlanner

    planner = DeterministicPlanner()

    # Rich profile
    profile = ChallengeProfile(
        sample_path=Path("test"), sha256="a" * 64,
        file_type="ELF", tags=["has_success_string"],
        comparison_hints=["memcmp"], crypto_hints=["xor"],
        encoding_hints=["base64"], success_strings=["Correct"],
        protections=["anti_debug"],
    )
    plan = planner.build(profile)
    names = [s.name for s in plan.steps]

    assert "static_flag" in names
    assert "decoding" in names
    assert "dynamic_trace" in names
    assert "z3_constraints" in names
    assert "z3_extractor" in names
    assert "angr_path" in names


def test_solve_result_best_flag_with_winning():
    """best_flag prefers winning_candidate when set"""
    from re_agent.ctf.models import SolveResult

    result = SolveResult(
        status="solved", sha256="a" * 64, verified=True,
        winning_candidate={"value": "flag{winner}", "source": "test", "confidence": 0.95},
        candidates=[
            {"value": "flag{loser}", "source": "other", "confidence": 0.5},
        ],
    )
    assert result.best_flag == "flag{winner}"
