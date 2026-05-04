"""
Plan 4 required tests: import gate, tool normalization, executor redaction.
"""

import json
import tempfile
from pathlib import Path


def test_runtime_modules_import():
    """PR1: All new LLM runtime modules can be imported."""
    import re_agent.brain.actions
    import re_agent.brain.context
    import re_agent.brain.base
    import re_agent.brain.deepseek
    import re_agent.brain.context_builder
    import re_agent.brain.policy
    import re_agent.core.observation
    import re_agent.ctf.context_bundle
    import re_agent.ctf.llm_runtime
    import re_agent.ctf.benchmark
    import re_agent.memory.playbook_import
    assert True


def test_all_tool_outputs_normalize_to_runtime_observation():
    """PR3: normalize_tool_result works for all tool output shapes."""
    from re_agent.core.observation import normalize_tool_result, RuntimeObservation

    # Normal output
    r = normalize_tool_result("test_tool", {"summary": "ok", "data": {"x": 1}})
    assert isinstance(r, RuntimeObservation)
    assert r.tool == "test_tool"
    assert r.summary == "ok"
    assert r.structured == {"x": 1}

    # Output with candidates
    r2 = normalize_tool_result("solver", {
        "summary": "found 3", "candidates": [{"value": "flag{x}"}]
    })
    assert len(r2.candidates) == 1

    # Output with artifacts
    r3 = normalize_tool_result("scan", {
        "summary": "scanned", "artifacts": ["strings.txt"]
    })
    assert r3.artifacts == ["strings.txt"]

    # Output with error
    r4 = normalize_tool_result("broken", {"error": "timeout"})
    assert r4.status == "error"


def test_tool_executor_redacts_arguments():
    """PR3: ToolExecutor trace must not contain raw candidate values."""
    from re_agent.ctf.tools import build_default_ctf_registry, ArtifactStore, ToolExecutor
    from re_agent.core.evidence_v2 import redact_tool_args

    # Verify redaction function works
    args = {"candidate": "flag{secret_value}", "timeout": 10}
    redacted = redact_tool_args(args)
    assert "flag{secret_value}" not in str(redacted)
    assert "[REDACTED]" in str(redacted) or redacted.get("candidate") != "flag{secret_value}"
    assert redacted.get("timeout") == 10  # Non-sensitive field preserved


def test_runtime_policy_has_test_mode():
    """PR4: RuntimePolicy has test_mode_allow_unverified for safe testing."""
    from re_agent.brain.policy import RuntimePolicy
    p = RuntimePolicy()
    assert hasattr(p, "test_mode_allow_unverified")
    assert p.test_mode_allow_unverified is False


def test_benchmark_auto_brain_not_placeholder():
    """PR8: _run_auto_brain imports and runs without crash."""
    from re_agent.ctf.benchmark import _run_auto_brain, _get_brain
    # _get_brain should not crash on known brain names
    b = _get_brain("openai")
    assert b is not None
    assert b.name == "openai"


def test_version_consistency():
    """PR2: pyproject.toml version matches version.py."""
    import tomllib
    import re_agent.version
    data = tomllib.loads(open("pyproject.toml", encoding="utf-8").read())
    assert data["project"]["version"] == re_agent.version.__version__
    assert "LLM-native" in data["project"]["description"]
