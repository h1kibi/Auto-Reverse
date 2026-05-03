"""
Docker 沙箱 - 安全执行动态分析

安全规则：
- --network none (默认)
- --read-only
- --cap-drop ALL
- --security-opt no-new-privileges
- --pids-limit, --memory, --cpus
"""

import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DockerSandboxConfig:
    """Docker 沙箱配置"""
    image: str = "reverse-agent-sandbox:latest"
    timeout: int = 60
    memory_mb: int = 512
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
    """Docker 沙箱执行器"""

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
        """以 argv 模式执行命令"""
        rendered = self._render_args(sample_path, output_dir, argv)
        shell_cmd = " ".join(_shell_quote(x) for x in rendered)
        return self._execute(sample_path, output_dir, shell_cmd)

    def run_shell(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        shell_cmd: str,
    ) -> DockerSandboxResult:
        """以 shell 模式执行命令"""
        rendered_cmd = self._render_shell_args(sample_path, output_dir, shell_cmd)
        return self._execute(sample_path, output_dir, rendered_cmd)

    def _render_args(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        argv: list[str],
    ) -> list[str]:
        """渲染 argv 中的 placeholder"""
        sample = Path(sample_path).resolve()
        return [
            arg.replace("{sample}", f"/samples/{sample.name}")
               .replace("{sample_name}", sample.name)
               .replace("{out}", "/out")
            for arg in argv
        ]

    def _render_shell_args(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        shell_cmd: str,
    ) -> str:
        """渲染 shell_cmd 中的 placeholder"""
        sample = Path(sample_path).resolve()
        return (
            shell_cmd
            .replace("{sample}", f"/samples/{sample.name}")
            .replace("{sample_name}", sample.name)
            .replace("{out}", "/out")
        )

    def _execute(
        self,
        sample_path: str | Path,
        output_dir: str | Path,
        shell_cmd: str,
    ) -> DockerSandboxResult:
        """执行 Docker 命令"""
        sample = Path(sample_path).resolve()
        output = Path(output_dir).resolve()
        output.mkdir(parents=True, exist_ok=True)

        if not sample.exists():
            return DockerSandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Sample not found: {sample}",
                execution_time_ms=0,
                command=[],
                error="Sample not found",
            )

        container_name = f"reverse-agent-{uuid.uuid4().hex[:12]}"

        # 构建 docker run 命令
        docker_cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--network", "bridge" if self.config.enable_network else "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.config.pids_limit),
            "--memory", f"{self.config.memory_mb}m",
            "--cpus", str(self.config.cpus),
            "--user", "65534:65534",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "-v", f"{sample.parent}:/samples:ro",
            "-v", f"{output}:/out:rw",
        ]

        # 添加环境变量
        for key, value in self.config.extra_env.items():
            docker_cmd.extend(["-e", f"{key}={value}"])

        # 使用 /bin/sh -lc 执行命令
        docker_cmd.extend([
            self.config.image,
            "/bin/sh", "-lc",
            shell_cmd,
        ])

        start = time.time()
        try:
            proc = subprocess.run(
                docker_cmd,
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
                command=docker_cmd,
            )
        except subprocess.TimeoutExpired as e:
            return DockerSandboxResult(
                success=False,
                exit_code=-1,
                stdout=e.stdout or "",
                stderr=e.stderr or "",
                execution_time_ms=int((time.time() - start) * 1000),
                command=docker_cmd,
                error="timeout",
            )
        except FileNotFoundError:
            return DockerSandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="docker not found. Please install Docker.",
                execution_time_ms=int((time.time() - start) * 1000),
                command=docker_cmd,
                error="docker not found",
            )


def _shell_quote(value: str) -> str:
    """Shell 引号转义"""
    return "'" + value.replace("'", "'\"'\"'") + "'"
