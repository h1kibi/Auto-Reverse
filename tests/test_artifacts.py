"""测试 artifact 路径工具"""
from re_agent.artifacts import sample_artifact_dir, safe_filename, compute_sha256


def test_sample_artifact_dir():
    sha = "a" * 64
    path = sample_artifact_dir("artifacts/results", sha)
    assert str(path).endswith(f"artifacts/results/aa/{sha}")


def test_sample_artifact_dir_short():
    sha = "abcdef1234567890" * 4  # 64 chars
    path = sample_artifact_dir("/tmp/results", sha)
    assert str(path) == f"/tmp/results/ab/{sha}"


def test_safe_filename():
    assert safe_filename("../../evil.exe") == "evil.exe"
    assert safe_filename("normal_file.bin") == "normal_file.bin"
    assert safe_filename("a b/c?.exe") == "a_b_c_.exe"


def test_safe_filename_preserves_extension():
    result = safe_filename("malware.exe")
    assert result == "malware.exe"
    assert result.endswith(".exe")
