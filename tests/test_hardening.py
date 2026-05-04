"""v0.5.1 hardening tests per plan Section 5."""
import json
import tempfile
from pathlib import Path


def test_sandbox_stdin_bytes_no_text_mode():
    """Sandbox run_exec uses text=False with bytes stdin / _decode_output"""
    from re_agent.sandbox import DockerSandbox, _decode_output, DockerSandboxConfig
    import inspect
    src = inspect.getsource(DockerSandbox.run_exec)
    assert "text=False" in src
    assert "_decode_output" in src
    # bytes input path
    config = DockerSandboxConfig(timeout=1)
    sandbox = DockerSandbox(config)
    # Verify _decode_output handles bytes/None/str
    assert _decode_output(b"hello") == "hello"
    assert _decode_output(None) == ""
    assert _decode_output("str") == "str"


def test_dynamic_trace_no_host_fallback():
    """DynamicTraceSolver has no direct subprocess fallback on host"""
    from re_agent.ctf.solvers.dynamic_trace import DynamicTraceSolver
    import inspect
    src = inspect.getsource(DynamicTraceSolver._run_ltrace_sandbox)
    assert "subprocess.run" not in src  # sandbox-only, no direct host subprocess


def test_solve_config_disables_dynamic_solver():
    """enable_dynamic=False skips dynamic_trace solver"""
    from re_agent.ctf.pipeline import _solver_enabled
    from re_agent.ctf.solve_config import SolveConfig

    cfg = SolveConfig(enable_dynamic=False)
    assert _solver_enabled("dynamic_trace", cfg) is False

    cfg2 = SolveConfig(enable_angr=False)
    assert _solver_enabled("angr_path", cfg2) is False

    cfg3 = SolveConfig()
    assert _solver_enabled("static_flag", cfg3) is True


def test_redaction_hides_candidate_in_output():
    """RedactionMode.LOGS replaces raw flag value with [REDACTED]"""
    from re_agent.ctf.validator import RedactionMode, redact_candidate

    flag = "flag{secret_value_123}"
    result = redact_candidate(flag, RedactionMode.LOGS)
    assert "flag{" not in result
    assert "[REDACTED" in result
    assert "len=" in result
    assert "sha256=" in result

    result_none = redact_candidate(flag, RedactionMode.NONE)
    assert flag in result_none


def test_snapshot_is_deterministic():
    """Same EvidenceGraph data produces same snapshot_id"""
    from re_agent.core.evidence import EvidenceGraph, StringNode, ImportNode

    g1 = EvidenceGraph("sha1")
    g1.add_string(StringNode("a", "flag{test}"))
    g1.add_import(ImportNode("strcmp"))
    sid1 = g1.snapshot_id()

    g2 = EvidenceGraph("sha1")
    g2.add_string(StringNode("a", "flag{test}"))
    g2.add_import(ImportNode("strcmp"))
    sid2 = g2.snapshot_id()

    assert sid1 == sid2

    # created_at should NOT be in snapshot
    snap = g1.to_snapshot()
    assert "created_at" not in snap
    assert "schema_version" in snap


def test_validator_differential_can_accept_without_success_string():
    """Differential oracle can accept when output differs from wrong input"""
    from re_agent.ctf.validator import OutputOracle

    oracle = OutputOracle()
    r = oracle.evaluate_differential(
        candidate_stdout="Data: ABC123\n", candidate_stderr="",
        wrong_stdout="Wrong!\n", wrong_stderr="",
        exit_code=0,
    )
    assert r.accepted
    assert "output_differs_from_wrong_input" in r.reasons
    assert r.confidence > 0.3
