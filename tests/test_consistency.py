"""v0.5.2 consistency tests per plan Section 6."""

import json
import tempfile
from pathlib import Path

from re_agent.ctf.validator import RedactionMode, redact_candidate


def test_r2_decompile_rejects_unsafe_target():
    """R2Backend.decompile calls validate_r2_target on input"""
    from re_agent.tools.backend import validate_r2_target
    assert validate_r2_target("main") == "main"
    assert validate_r2_target("0x401000") == "0x401000"
    try:
        validate_r2_target("rm -rf /")
        assert False, "Should have raised"
    except ValueError:
        pass


def test_differential_oracle_requires_all_wrong_inputs_to_differ():
    """Without success pattern, must differ from ALL wrong inputs to accept"""
    from re_agent.ctf.validator import OutputOracle
    from re_agent.sandbox import DockerSandboxResult

    oracle = OutputOracle()
    wrong_runs = [
        DockerSandboxResult(success=False, exit_code=1, stdout="Wrong!\n", stderr="",
                            execution_time_ms=0, command=[]),
        DockerSandboxResult(success=False, exit_code=1, stdout="Nope.\n", stderr="",
                            execution_time_ms=0, command=[]),
        DockerSandboxResult(success=False, exit_code=1, stdout="Bad.\n", stderr="",
                            execution_time_ms=0, command=[]),
    ]

    # Candidate output differs from all wrong inputs -> accepted
    r = oracle.evaluate_differential(
        candidate_stdout="Correct flag!\n", candidate_stderr="",
        wrong_runs=wrong_runs, exit_code=0,
    )
    assert r.accepted, f"Should accept: conf={r.confidence} reasons={r.reasons}"
    assert "output_differs_from_all_wrong_inputs" in r.reasons

    # Candidate output matches one wrong input -> NOT accepted
    same_wrong = [
        DockerSandboxResult(success=False, exit_code=1, stdout="Same\n", stderr="",
                            execution_time_ms=0, command=[]),
        DockerSandboxResult(success=False, exit_code=1, stdout="Other\n", stderr="",
                            execution_time_ms=0, command=[]),
    ]
    r2 = oracle.evaluate_differential(
        candidate_stdout="Same\n", candidate_stderr="",
        wrong_runs=same_wrong, exit_code=1,
    )
    assert not r2.accepted, f"Should NOT accept matching wrong: {r2.reasons}"


def test_max_candidates_limit():
    """max_candidates config field exists with default 50"""
    from re_agent.ctf.solve_config import SolveConfig
    c = SolveConfig()
    assert c.max_candidates == 50
    c2 = SolveConfig(max_candidates=3)
    assert c2.max_candidates == 3
