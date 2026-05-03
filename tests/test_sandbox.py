"""测试 Docker 沙箱"""
from unittest.mock import patch, MagicMock
from pathlib import Path

from re_agent.sandbox import DockerSandbox, DockerSandboxConfig, _shell_quote


def test_shell_quote_single_quote():
    """测试单引号转义"""
    assert _shell_quote("a'b") == "'a'\"'\"'b'"
    assert _shell_quote("normal") == "'normal'"
    assert _shell_quote("a b c") == "'a b c'"


def test_run_argv_renders_sample_path(tmp_path):
    """测试 argv 模式渲染 placeholder"""
    sandbox = DockerSandbox(DockerSandboxConfig(timeout=5))

    sample = tmp_path / "challenge"
    sample.write_text("test")
    output = tmp_path / "out"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="ok",
            stderr="",
        )

        result = sandbox.run_argv(
            sample_path=sample,
            output_dir=output,
            argv=["/bin/echo", "{sample}"],
        )

        # 检查 docker_cmd 包含 /bin/sh -lc
        call_args = mock_run.call_args[0][0]
        assert "/bin/sh" in call_args
        assert "-lc" in call_args

        # 检查 shell_cmd 中 sample 被替换
        shell_cmd_idx = call_args.index("-lc") + 1
        shell_cmd = call_args[shell_cmd_idx]
        assert f"/samples/{sample.name}" in shell_cmd


def test_run_shell_uses_sh_lc(tmp_path):
    """测试 shell 模式使用 /bin/sh -lc"""
    sandbox = DockerSandbox(DockerSandboxConfig(timeout=5))

    sample = tmp_path / "challenge"
    sample.write_text("test")
    output = tmp_path / "out"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="ok",
            stderr="",
        )

        result = sandbox.run_shell(
            sample_path=sample,
            output_dir=output,
            shell_cmd="echo hello",
        )

        call_args = mock_run.call_args[0][0]
        assert call_args[-3] == "/bin/sh"
        assert call_args[-2] == "-lc"
        assert call_args[-1] == "echo hello"


def test_run_shell_renders_placeholder(tmp_path):
    """测试 shell 模式渲染 placeholder"""
    sandbox = DockerSandbox(DockerSandboxConfig(timeout=5))

    sample = tmp_path / "challenge"
    sample.write_text("test")
    output = tmp_path / "out"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="ok",
            stderr="",
        )

        result = sandbox.run_shell(
            sample_path=sample,
            output_dir=output,
            shell_cmd="cat {sample} > {out}/result.txt",
        )

        call_args = mock_run.call_args[0][0]
        shell_cmd = call_args[-1]
        assert f"/samples/{sample.name}" in shell_cmd
        assert "/out/result.txt" in shell_cmd


def test_run_tool_compatible(tmp_path):
    """测试 run_tool 兼容旧接口"""
    sandbox = DockerSandbox(DockerSandboxConfig(timeout=5))

    sample = tmp_path / "challenge"
    sample.write_text("test")
    output = tmp_path / "out"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="ok",
            stderr="",
        )

        result = sandbox.run_tool(
            sample_path=sample,
            output_dir=output,
            command_template=["strace", "-o", "{out}/strace.log", "{sample}"],
        )

        assert result.success
        call_args = mock_run.call_args[0][0]
        assert "/bin/sh" in call_args


def test_sample_not_found(tmp_path):
    """测试样本不存在"""
    sandbox = DockerSandbox(DockerSandboxConfig(timeout=5))

    sample = tmp_path / "nonexistent"
    output = tmp_path / "out"

    result = sandbox.run_argv(
        sample_path=sample,
        output_dir=output,
        argv=["/bin/echo", "{sample}"],
    )

    assert not result.success
    assert "not found" in result.stderr.lower()
