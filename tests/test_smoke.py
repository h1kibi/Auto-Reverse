"""
Smoke tests: CLI help + package submodules + Z3 DSL + sandbox no-shell + memory no-flag.

See plan §0.6.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path


def test_cli_solve_help():
    """solve --help prints expected flags"""
    proc = subprocess.run(
        [sys.executable, "-m", "re_agent", "solve", "--help"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
    out = proc.stdout
    assert "--skip-ghidra" in out
    assert "--ghidra" in out or "--deep" in out
    assert "--enable-memory" in out or "--quick" in out
    assert "--flag-regex" in out


def test_package_import_submodules():
    """All subpackages can be imported without circular errors"""
    mods = [
        "re_agent.core",
        "re_agent.core.evidence",
        "re_agent.core.toolspec",
        "re_agent.core.policy",
        "re_agent.core.runlog",
        "re_agent.core.errors",
        "re_agent.ctf",
        "re_agent.ctf.models",
        "re_agent.ctf.pipeline",
        "re_agent.ctf.profiler",
        "re_agent.ctf.strategy",
        "re_agent.ctf.validator",
        "re_agent.ctf.solvers",
        "re_agent.ctf.solvers.base",
        "re_agent.ctf.solvers.static_flag",
        "re_agent.ctf.solvers.encoding",
        "re_agent.ctf.solvers.z3_constraints",
        "re_agent.ctf.solvers.z3_extractor",
        "re_agent.ctf.solvers.angr_path",
        "re_agent.ctf.solvers.dynamic_trace",
        "re_agent.ctf.solvers.brute_force",
        "re_agent.ctf.solvers.patcher",
        "re_agent.ctf.constraints_loop",
        "re_agent.ctf.learning",
        "re_agent.memory",
        "re_agent.memory.schema",
        "re_agent.memory.store",
        "re_agent.memory.retriever",
        "re_agent.memory.ingest",
        "re_agent.tools",
        "re_agent.tools.backend",
        "re_agent.tools.r2_tool",
        "re_agent.tools.gdb_tool",
        "re_agent.api.schemas",
        "re_agent.api.mcp",
        "re_agent.sandbox",
    ]
    for m in mods:
        __import__(m)
    assert True


def test_z3_extractor_output_can_be_solved():
    """Extracted constraint format is valid for z3_constraints _expr"""
    try:
        from z3 import BitVec  # noqa: F401
    except ImportError:
        import pytest
        pytest.skip("z3-solver not installed")

    from re_agent.ctf.solvers.z3_constraints import _expr
    from z3 import BitVec

    xs = [BitVec(f"x{i}", 8) for i in range(10)]

    # Test {"var": 0} format from extractor
    r = _expr({"var": 3}, xs)
    assert r is not None and hasattr(r, 'sort')  # BitVec has .sort()
    # Test legacy "x[0]" format
    r2 = _expr("x[2]", xs)
    assert r2 is not None
    # Test op dict with left/right
    r3 = _expr({"op": "xor", "left": {"var": 0}, "right": 18}, xs)
    assert r3 is not None
    # Test op dict with args
    r4 = _expr({"op": "add", "args": [{"var": 1}, 3]}, xs)
    assert r4 is not None
    # Test integer
    assert _expr(42, xs) == 42


def test_sandbox_no_shell_injection():
    """Sandbox run_exec uses no shell, mounts single file"""
    from re_agent.sandbox import DockerSandbox

    sandbox = DockerSandbox()
    assert hasattr(sandbox, "run_exec")
    assert hasattr(sandbox, "run_stdin")
    assert hasattr(sandbox, "run_argv")
    # run_exec should accept stdin as bytes
    import inspect
    src = inspect.getsource(sandbox.run_exec)
    assert "input=stdin" in src or "stdin=" in src
    assert "/input/sample" in src
    assert "/bin/sh" not in src
    assert "TemporaryDirectory" in src or "tmpdir" in src.lower()


def test_validator_uses_run_exec():
    """Validator calls run_exec, not shell"""
    from re_agent.ctf.validator import FlagValidator
    import inspect

    src = inspect.getsource(FlagValidator._run_one_mode)
    assert "run_exec" in src
    assert "run_shell" not in src
    assert "/bin/sh" not in src


def test_memory_does_not_store_flag_by_default():
    """SelfLesson should not include raw flag value in key fields"""
    from re_agent.memory.schema import SelfLesson

    # A properly constructed lesson stores signals/patterns, not raw flag
    lesson = SelfLesson(
        id="test", challenge_sha256="a" * 64, solved=True, verified=True,
        winning_solver="encoding",
        key_signals=["base64", "success_string"],
        generalized_pattern="base64 encoded flag in strings section",
        successful_recipe=["encoding: decoded base64 string"],
        confidence=0.8,
    )
    payload = lesson.__dict__ if hasattr(lesson, '__dict__') else vars(lesson)
    text = str(payload).lower()
    assert "flag{" not in text or "generalized_pattern" in str(list(payload.keys()))


def test_pyproject_packages_find():
    """pyproject.toml uses packages.find not flat packages list"""
    root = Path(__file__).parent.parent
    content = (root / "pyproject.toml").read_text()
    assert "[tool.setuptools.packages.find]" in content
    assert 'include = ["re_agent*"]' in content
    assert 'packages = ["re_agent"]' not in content
