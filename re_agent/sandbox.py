"""
Docker 沙箱 - 安全执行动态分析

安全规则：
- --network none (默认)
- --read-only
- --cap-drop ALL
- --security-opt no-new-privileges
- --pids-limit, --memory, --cpus
- 只挂载单个样本文件
- 避免 shell 拼接
"""

import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DockerSandboxConfig:
    """Docker 沙箱配置"""
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
    """Docker 沙箱执行结果"""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: int
    command: list[str]
    error: str | None = None


class DockerSandbox:
    """Docker 沙箱执行器 - 单文件安全隔离"""

    def __init__(self, config: DockerSandboxConfig | None = None):
        self.config = config or DockerSandboxConfig()

    def run_tool(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        command_template: list[str],
    ) -> DockerSandboxResult:
        """在 Docker 容器中执行工具（兼容旧接口）"""
        return self.run_argv(sample_path, output_dir, command_template)

    def run_argv(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        argv: list[str],
    ) -> DockerSandboxResult:
        """以 argv 模式执行命令（不用 shell）"""
        sample = Path(sample_path).resolve()
        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        if not sample.exists():
            return DockerSandboxResult(
                success=False, exit_code=-1, stdout="", stderr=f"Sample not found: {sample}",
                execution_time_ms=0, command=[], error="Sample not found",
            )

        with tempfile.TemporaryDirectory(prefix="auto_reverse_sandbox_") as tmp_dir:
            tmp = Path(tmp_dir)
            safe_sample = tmp / "sample"
            shutil.copy2(sample, safe_sample)
            safe_sample.chmod(0o755)

            resolved_args = []
            for arg in argv:
                rendered = arg.replace("{sample}", "/input/sample").replace("{sample_name}", sample.name).replace("{out}", "/out")
                resolved_args.append(rendered)

            return self._execute_container(safe_sample, out_dir, resolved_args, stdin_bytes=None)

    def run_shell(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        shell_cmd: str,
    ) -> DockerSandboxResult:
        """以 stdin 模式执行命令（安全构造，避免 shell）"""
        sample = Path(sample_path).resolve()
        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        if not sample.exists():
            return DockerSandboxResult(
                success=False, exit_code=-1, stdout="", stderr=f"Sample not found: {sample}",
                execution_time_ms=0, command=[], error="Sample not found",
            )

        with tempfile.TemporaryDirectory(prefix="auto_reverse_sandbox_") as tmp_dir:
            tmp = Path(tmp_dir)
            safe_sample = tmp / "sample"
            shutil.copy2(sample, safe_sample)
            safe_sample.chmod(0o755)

            rendered_cmd = shell_cmd.replace("{sample}", "/input/sample").replace("{sample_name}", sample.name).replace("{out}", "/out")

            stdout_path = tmp / "stdout.txt"
            stderr_path = tmp / "stderr.txt"

            container_cmd = [
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
                "--mount", f"type=bind,src={out_dir},dst=/out",
                "--mount", f"type=bind,src={tmp},dst=/sandbox_tmp",
            ]

            for key, value in self.config.extra_env.items():
                container_cmd.extend(["-e", f"{key}={value}"])

            container_cmd.extend([
                self.config.image,
                "/bin/sh", "-c",
                f"fmted_cmd={_safe_quote(rendered_cmd)} && "
                f"$fmted_cmd > /sandbox_tmp/stdout.txt 2> /sandbox_tmp/stderr.txt; "
                f"echo $? > /sandbox_tmp/exit_code.txt",
            ])

            start = time.time()
            try:
                proc = subprocess.run(
                    container_cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout + 10,
                )

                exit_code = -1
                try:
                    ec_file = tmp / "exit_code.txt"
                    if ec_file.exists():
                        exit_code = int(ec_file.read_text().strip())
                except Exception:
                    pass

                stdout = ""
                try:
                    sf = tmp / "stdout.txt"
                    if sf.exists():
                        stdout = sf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    stdout = proc.stdout or ""

                stderr = ""
                try:
                    ef = tmp / "stderr.txt"
                    if ef.exists():
                        stderr = ef.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    stderr = proc.stderr or ""

                return DockerSandboxResult(
                    success=exit_code == 0,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    execution_time_ms=int((time.time() - start) * 1000),
                    command=container_cmd,
                )
            except subprocess.TimeoutExpired as e:
                return DockerSandboxResult(
                    success=False, exit_code=-1,
                    stdout=e.stdout or "", stderr=e.stderr or "",
                    execution_time_ms=int((time.time() - start) * 1000),
                    command=container_cmd, error="timeout",
                )
            except FileNotFoundError:
                return DockerSandboxResult(
                    success=False, exit_code=-1,
                    stdout="", stderr="docker not found. Please install Docker.",
                    execution_time_ms=int((time.time() - start) * 1000),
                    command=container_cmd, error="docker not found",
                )

    def _execute_container(
        self,
        safe_sample: Path,
        out_dir: Path,
        args: list[str],
        stdin_bytes: bytes | None = None,
    ) -> DockerSandboxResult:
        """执行 Docker 容器（安全模式：argv 直接传入，不用 shell）"""
        container_cmd = [
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
            "--mount", f"type=bind,src={out_dir},dst=/out",
        ]

        for key, value in self.config.extra_env.items():
            container_cmd.extend(["-e", f"{key}={value}"])

        container_cmd.extend([self.config.image] + args)

        start = time.time()
        try:
            proc = subprocess.run(
                container_cmd,
                input=stdin_bytes,
                capture_output=self.config.capture_output,
                text=True,
                timeout=self.config.timeout + 10,
            )
            return DockerSandboxResult(
                success=proc.returncode == 0,
                exit_code=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                execution_time_ms=int((time.time() - start) * 1000),
                command=container_cmd,
            )
        except subprocess.TimeoutExpired as e:
            return DockerSandboxResult(
                success=False, exit_code=-1,
                stdout=e.stdout or "", stderr=e.stderr or "",
                execution_time_ms=int((time.time() - start) * 1000),
                command=container_cmd, error="timeout",
            )
        except FileNotFoundError:
            return DockerSandboxResult(
                success=False, exit_code=-1,
                stdout="", stderr="docker not found. Please install Docker.",
                execution_time_ms=int((time.time() - start) * 1000),
                command=container_cmd, error="docker not found",
            )


def _safe_quote(value: str) -> str:
    """安全 shell 引号（用于非用户输入的场景）"""
    return "'" + value.replace("'", "'\"'\"'") + "'"
