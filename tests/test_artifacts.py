"""测试 artifact 路径工具"""
import os
from re_agent.artifacts import sample_artifact_dir, safe_filename, compute_sha256


def test_sample_artifact_dir():
    sha = "a" * 64
    path = sample_artifact_dir("artifacts/results", sha)
    path_str = str(path)
    # 兼容 Windows 和 Linux 路径
    assert "aa" in path_str
    assert sha in path_str


def test_sample_artifact_dir_short():
    sha = "abcdef1234567890" * 4  # 64 chars
    path = sample_artifact_dir("/tmp/results", sha)
    path_str = str(path)
    assert "ab" in path_str
    assert sha in path_str


def test_safe_filename():
    assert safe_filename("../../evil.exe") == "evil.exe"
    assert safe_filename("normal_file.bin") == "normal_file.bin"


def test_safe_filename_preserves_extension():
    result = safe_filename("malware.exe")
    assert result == "malware.exe"
    assert result.endswith(".exe")
