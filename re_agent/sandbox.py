"""
Docker 沙箱 - 安全执行动态分析

安全规则 (no-shell execution):
- 单文件 mount: 只 mount sample 文件, 不 mount parent dir
- argv 用 list 传入, 不用 shell 拼接
- stdin 用 subprocess bytes 传入
- 绝不使用 /bin/sh -lc 执行样本
- --network none / --read-only / --cap-drop ALL
"""

import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DockerSandboxConfig:
    image: str = "reverse-agent-sandbox:latest"
    timeout: int = 60
    memory_mb: int = 256
    cpus: float = 1.0
    pids_limit: int = 128
    enable_network: bool = False
    capture_output: bool = True
    extra_env: dict[str, str] = field(default_factory=dict)


@dataclass
class DockerSandboxResult:
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: int
    command: list[str]
    error: str | None = None


def _copy_single_sample(sample_path: Path, tmpdir: Path) -> Path:
    safe_sample = tmpdir / "sample"
    shutil.copy2(sample_path, safe_sample)
    safe_sample.chmod(0o755)
    return safe_sample


class DockerSandbox:
    """Docker 沙箱执行器 - 单文件安全隔离, 无 shell 执行"""

    def __init__(self, config: DockerSandboxConfig | None = None):
        self.config = config or DockerSandboxConfig()

    def run_exec(
        self,
        sample_path: str | Path,
        argv: list[str] | None = None,
        stdin: bytes | None = None,
        timeout: int | None = None,
        output_dir: Path | None = None,
    ) -> DockerSandboxResult:
        """安全执行: 只接受 argv list + stdin bytes, 没有 shell"""
        sample = Path(sample_path).resolve()
        output = (output_dir or Path.cwd() / "sandbox_out").resolve()
        output.mkdir(parents=True, exist_ok=True)
        argv = (argv or []).copy()
        timeout = timeout or self.config.timeout

        if not sample.exists():
            return DockerSandboxResult(
                success=False, exit_code=-1, stdout="", stderr=f"Sample not found: {sample}",
                execution_time_ms=0, command=[], error="Sample not found",
            )

        with tempfile.TemporaryDirectory(prefix="auto_reverse_sandbox_") as td:
            tmpdir = Path(td)
            safe_sample = _copy_single_sample(sample, tmpdir)

            rendered = []
            for arg in argv:
                rendered.append(
                    arg.replace("{sample}", "/input/sample")
                       .replace("{sample_name}", sample.name)
                       .replace("{out}", "/out")
                )

            cmd = [
                "docker", "run", "--rm",
                "--network", "bridge" if self.config.enable_network else "none",
                "--read-only",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", str(self.config.pids_limit),
                "--memory", f"{self.config.memory_mb}m",
                "--cpus", str(self.config.cpus),
                "--user", "65534:65534",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "--mount", f"type=bind,src={safe_sample},dst=/input/sample,readonly",
                "--mount", f"type=bind,src={output},dst=/out",
                "--workdir", "/tmp",
                self.config.image,
                "/input/sample",
                *rendered,
            ]

            for key, value in self.config.extra_env.items():
                cmd.insert(-len(rendered) - 1, "-e")
                cmd.insert(-len(rendered) - 1, f"{key}={value}")

            start = time.time()
            try:
                proc = subprocess.run(
                    cmd,
                    input=stdin,
                    capture_output=self.config.capture_output,
                    text=True,
                    timeout=timeout + 10,
                    check=False,
                )
                return DockerSandboxResult(
                    success=proc.returncode == 0,
                    exit_code=proc.returncode,
                    stdout=proc.stdout or "",
                    stderr=proc.stderr or "",
                    execution_time_ms=int((time.time() - start) * 1000),
                    command=cmd,
                )
            except subprocess.TimeoutExpired as e:
                return DockerSandboxResult(
                    success=False, exit_code=-1,
                    stdout=e.stdout or "", stderr=e.stderr or "",
                    execution_time_ms=int((time.time() - start) * 1000),
                    command=cmd, error="timeout",
                )
            except FileNotFoundError:
                return DockerSandboxResult(
                    success=False, exit_code=-1,
                    stdout="", stderr="docker not found. Please install Docker.",
                    execution_time_ms=int((time.time() - start) * 1000),
                    command=cmd, error="docker not found",
                )

    def run_argv(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        argv: list[str],
    ) -> DockerSandboxResult:
        """argv 模式 - 使用 run_exec"""
        return self.run_exec(
            sample_path=sample_path,
            argv=argv,
            output_dir=Path(output_dir),
        )

    def run_stdin(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        stdin_content: str,
    ) -> DockerSandboxResult:
        """stdin 模式 - 使用 run_exec"""
        return self.run_exec(
            sample_path=sample_path,
            argv=[],
            stdin=(stdin_content + "\n").encode(),
            output_dir=Path(output_dir),
        )

    def run_tool(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        command_template: list[str],
    ) -> DockerSandboxResult:
        """兼容旧接口"""
        return self.run_exec(
            sample_path=sample_path,
            argv=command_template,
            output_dir=Path(output_dir),
        )

    def run_tool_with_sample(
        self,
        sample_path: str | Path,
        tool_argv: list[str],
        stdin: bytes | None = None,
        output_dir: Path | None = None,
    ) -> DockerSandboxResult:
        """在容器内执行工具 + 样本: 把 tool_argv 作为容器命令运行"""
        sample = Path(sample_path).resolve()
        output = (output_dir or Path.cwd() / "sandbox_out").resolve()
        output.mkdir(parents=True, exist_ok=True)

        if not sample.exists():
            return DockerSandboxResult(
                success=False, exit_code=-1, stdout="", stderr=f"Sample not found: {sample}",
                execution_time_ms=0, command=[], error="Sample not found",
            )

        with tempfile.TemporaryDirectory(prefix="auto_reverse_sandbox_") as td:
            tmpdir = Path(td)
            safe_sample = _copy_single_sample(sample, tmpdir)

            rendered = []
            for arg in tool_argv:
                rendered.append(
                    arg.replace("/input/sample", "/input/sample")
                       .replace("{sample}", "/input/sample")
                       .replace("{out}", "/out")
                )

            cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--read-only",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", str(self.config.pids_limit),
                "--memory", f"{self.config.memory_mb}m",
                "--cpus", str(self.config.cpus),
                "--user", "65534:65534",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "--mount", f"type=bind,src={safe_sample},dst=/input/sample,readonly",
                "--mount", f"type=bind,src={output},dst=/out",
                "--workdir", "/tmp",
                self.config.image,
                *rendered,
            ]

            start = time.time()
            try:
                proc = subprocess.run(
                    cmd,
                    input=stdin,
                    capture_output=self.config.capture_output,
                    text=True,
                    timeout=self.config.timeout + 10,
                    check=False,
                )
                return DockerSandboxResult(
                    success=proc.returncode == 0,
                    exit_code=proc.returncode,
                    stdout=proc.stdout or "",
                    stderr=proc.stderr or "",
                    execution_time_ms=int((time.time() - start) * 1000),
                    command=cmd,
                )
            except subprocess.TimeoutExpired as e:
                return DockerSandboxResult(
                    success=False, exit_code=-1,
                    stdout=e.stdout or "", stderr=e.stderr or "",
                    execution_time_ms=int((time.time() - start) * 1000),
                    command=cmd, error="timeout",
                )
            except FileNotFoundError:
                return DockerSandboxResult(
                    success=False, exit_code=-1,
                    stdout="", stderr="docker not found.",
                    execution_time_ms=0, command=cmd, error="docker not found",
                )
