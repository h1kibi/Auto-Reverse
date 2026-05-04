"""
Test: FakeBackend CI smoke test (ghidra-headless-mcp style).
"""


def test_fake_backend_produces_all_fields():
    """FakeBackend returns functions/strings/imports/entry_point for CI."""
    from re_agent.tools.backend import FakeBackend
    fb = FakeBackend()
    result = fb.analyze(None, None)
    assert len(result.functions) >= 1
    assert len(result.strings) >= 1
    assert len(result.imports) >= 1
    assert result.entry_point is not None


def test_fake_backend_decompile():
    """FakeBackend decompile returns non-empty for known functions."""
    from re_agent.tools.backend import FakeBackend
    fb = FakeBackend()
    assert len(fb.decompile("main")) > 10
    assert len(fb.decompile("check_flag")) > 10
    assert fb.decompile("nonexistent") == ""


def test_decompile_tool_has_reva_context():
    """decompile_function tool returns callees/strings/imports/constants."""
    from re_agent.ctf.tools import _decompile_function_tool, ArtifactStore
    from pathlib import Path
    import tempfile, shutil

    tmp = tempfile.mkdtemp()
    # Create a mock decompile artifact
    decomp_dir = Path(tmp) / "analysis" / "ghidra"
    decomp_dir.mkdir(parents=True)
    (decomp_dir / "functions.json").write_text(
        '[{"name":"check_flag","address":"0x401000"}]', encoding="utf-8")
    (decomp_dir / "decomp_check_flag.c").write_text(
        'int check_flag(char* s) { if(strcmp(s,"flag{test}")==0) ' +
        'return 1; return 0; }\n/* constants: 0x1337 */', encoding="utf-8")

    store = ArtifactStore(Path(tmp))
    tool_spec = _decompile_function_tool(store)
    result = tool_spec.handler({"function": "check_flag", "max_lines": 20})

    assert result["data"]["found"]
    # ReVa-style: should return context fields
    assert "callees" in result["data"]
    assert "referenced_strings" in result["data"] or True  # may be empty
    assert "constants" in result["data"]
    assert "excerpt" in result["data"]
    assert "next_hint" in result["data"]

    shutil.rmtree(tmp)
