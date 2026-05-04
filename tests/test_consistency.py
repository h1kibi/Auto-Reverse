"""v0.5.2 consistency tests per plan Section 6."""

import json
import tempfile
from pathlib import Path

from re_agent.ctf.validator import RedactionMode, redact_candidate


def test_r2_decompile_calls_target_validator(monkeypatch, tmp_path):
    """R2Backend.decompile() actually calls validate_r2_target"""
    from re_agent.tools import backend

    called = {"value": False}

    def fake_validate(value):
        called["value"] = True
        raise ValueError("blocked")

    monkeypatch.setattr(backend, "validate_r2_target", fake_validate)

    b = backend.R2Backend()
    b.sample_path = str(tmp_path / "sample")
    (tmp_path / "sample").write_bytes(b"\x7fELF")

    assert b.decompile("unsafe;cmd") == ""
    assert called["value"]


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
