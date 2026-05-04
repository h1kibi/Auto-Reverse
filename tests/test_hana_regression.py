"""
hana regression tests per plan v2.
"""

from re_agent.brain.actions import BrainAction
from re_agent.brain.policy import RuntimePolicy, PolicyGate
from re_agent.brain.context import BrainContext, MemoryTacticCard
from re_agent.ctf.mock_brain import MockBrain


def test_packed_state_blocks_static_flag():
    gate = PolicyGate(RuntimePolicy(block_static_when_packed=True))
    state = {
        "packer_profile": {"is_packed": True, "packer": "vmp_or_fake_upx"},
        "unpacked_path": None,
    }
    action = BrainAction(kind="run_solver", name="static_flag", rationale="test")
    assert not gate.allow(action, state=state)


def test_packed_state_blocks_encoding():
    gate = PolicyGate(RuntimePolicy(block_static_when_packed=True))
    state = {"packer_profile": {"is_packed": True}}
    action = BrainAction(kind="run_solver", name="encoding", rationale="test")
    assert not gate.allow(action, state=state)


def test_packed_unpacked_allows_static():
    gate = PolicyGate(RuntimePolicy(block_static_when_packed=True))
    state = {"packer_profile": {"is_packed": True}, "unpacked_path": "/tmp/sample.unpacked"}
    action = BrainAction(kind="run_solver", name="static_flag", rationale="test")
    assert gate.allow(action, state=state)


def test_rc4_recipe_decrypts_hana_ciphertext():
    from re_agent.ctf.tools_crypto import tool_crypto_recipe

    obs = tool_crypto_recipe({
        "algorithm": "rc4", "key": "Wrong!", "key_encoding": "utf8",
        "ciphertext_hex": "56ECA0DC5707F4A3E977BF93BC8652A5146AA5BDB5D27F0B9B671D08EFC9325D43ED1E014B7B",
    })
    assert obs["status"] == "ok"
    assert obs["candidates"]
    assert obs["candidates"][0]["source"] == "crypto_recipe:rc4"


def test_rc4_builtin_works():
    from re_agent.ctf.tools_crypto import rc4_crypt
    plain = rc4_crypt(b"Key", b"Plaintext")
    assert len(plain) == 9
    assert rc4_crypt(b"Key", plain) == b"Plaintext"


def test_detect_packer_finds_upx(tmp_path):
    from re_agent.ctf.packer_detect import detect_packer
    sample = tmp_path / "test.exe"
    sample.write_bytes(b"\x00" * 100 + b"UPX!" + b"\x00" * 500)
    profile = detect_packer(sample)
    assert profile.is_packed
    assert profile.packer == "upx"


def test_repair_upx_sections(tmp_path):
    from re_agent.ctf.tools_packer import tool_repair_upx_sections
    sample = tmp_path / "hana.exe"
    sample.write_bytes(b"MZ\x00\x00VMP0\x00\x00VMP1\x00\x00MORE")
    result = tool_repair_upx_sections({"sample_path": str(sample), "output_dir": str(tmp_path)})
    assert result["status"] == "ok"
    assert "Repaired" in result["summary"]
    repaired = tmp_path / "hana.upx_repaired.exe"
    assert repaired.exists()
