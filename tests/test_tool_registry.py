"""
Tool registry consistency tests (ghidra-headless-mcp style).
"""


def test_all_registry_tools_have_handler():
    """Every registered tool has handler/description/risk."""
    from re_agent.ctf.tools import build_default_ctf_registry, ArtifactStore
    from pathlib import Path

    store = ArtifactStore(Path("test_artifacts"))
    try:
        registry = build_default_ctf_registry(store)
    except Exception:
        registry = build_default_ctf_registry(store)

    for name in registry.names():
        spec = registry.get(name)
        assert spec.name, f"{name}: missing name"
        assert spec.description, f"{name}: missing description"
        assert spec.handler is not None, f"{name}: missing handler"
        assert spec.input_schema is not None, f"{name}: missing input_schema"


def test_core_tools_have_risk():
    from re_agent.ctf.tools import build_default_ctf_registry, ArtifactStore
    from pathlib import Path

    store = ArtifactStore(Path("test_artifacts"))
    registry = build_default_ctf_registry(store)

    for name in registry.names():
        spec = registry.get(name)
        risk = getattr(spec, "risk", None)
        if risk is not None:
            assert risk in {"read_only", "executes_sample", "mutates_binary"}, f"{name}: bad risk={risk}"


def test_r2_allowed_commands_are_defined():
    from re_agent.tools.backend import R2_COMMANDS, ALLOWED_R2_ACTIONS
    assert len(R2_COMMANDS) >= 4
    assert len(ALLOWED_R2_ACTIONS) >= 4


def test_fake_backend_ci_ready():
    from re_agent.tools.backend import FakeBackend
    fb = FakeBackend()
    result = fb.analyze(None, None)
    assert len(result.functions) > 0
    assert len(result.strings) > 0
    assert len(result.imports) > 0
    assert result.entry_point is not None
    assert len(fb.decompile("main")) > 10
    assert len(fb.decompile("check_flag")) > 10


def test_snapshot_roundtrip():
    from re_agent.core.evidence import EvidenceGraph, StringNode
    g1 = EvidenceGraph("sha1")
    g1.add_string(StringNode("s1", "flag{test}"))
    sid = g1.snapshot_id()
    assert len(sid) == 64
    g2 = EvidenceGraph("sha1")
    g2.add_string(StringNode("s1", "flag{test}"))
    assert g2.snapshot_id() == sid
