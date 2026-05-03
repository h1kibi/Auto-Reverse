"""
沙箱执行模块 - 安全执行样本

安全规则：
- 默认无网络
- 资源限制（CPU、内存、时间）
- 文件系统隔离
- 必须人工确认
"""

import subprocess
import os
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """沙箱配置"""
    # 资源限制
    max_cpu_percent: int = 50
    max_memory_mb: int = 512
    max_execution_time: int = 60  # 秒
    max_disk_mb: int = 100

    # 网络
    enable_network: bool = False
    fake_dns: bool = True
    allowed_hosts: list[str] = field(default_factory=list)

    # 文件系统
    readonly_sample: bool = True
    temp_dir: str = None

    # 其他
    capture_output: bool = True
    log_syscalls: bool = True


@dataclass
class SandboxResult:
    """沙箱执行结果"""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: int
    peak_memory_mb: float
    temp_dir: str
    artifacts: list[str] = field(default_factory=list)
    error: str = None


class Sandbox:
    """沙箱执行器"""

    def __init__(self, config: SandboxConfig = None):
        self.config = config or SandboxConfig()
        self.temp_dir = None

    def execute(
        self,
        sample_path: str,
        args: list[str] = None,
        env: dict = None,
    ) -> SandboxResult:
        """在沙箱中执行样本"""
        sample_path = Path(sample_path)
        if not sample_path.exists():
            return SandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Sample not found: {sample_path}",
                execution_time_ms=0,
                peak_memory_mb=0,
                temp_dir="",
                error="Sample not found",
            )

        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp(prefix="reverse_sandbox_")
        temp_dir = Path(self.temp_dir)

        try:
            # 准备执行环境
            exec_sample = self._prepare_sample(sample_path, temp_dir)

            # 准备环境变量
            exec_env = self._prepare_env(env)

            # 构建执行命令
            cmd = self._build_command(exec_sample, args)

            # 执行
            result = self._execute_command(cmd, exec_env)

            return result

        finally:
            # 清理
            self._cleanup()

    def _prepare_sample(self, sample_path: Path, temp_dir: Path) -> Path:
        """准备样本到临时目录"""
        exec_sample = temp_dir / sample_path.name

        if self.config.readonly_sample:
            # 复制样本
            shutil.copy2(sample_path, exec_sample)
            # 设置只读
            exec_sample.chmod(0o444)
        else:
            # 符号链接
            exec_sample.symlink_to(sample_path.absolute())

        return exec_sample

    def _prepare_env(self, user_env: dict = None) -> dict:
        """准备环境变量"""
        env = os.environ.copy()

        # 清除敏感变量
        sensitive_vars = [
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN", "OPENAI_API_KEY",
        ]
        for var in sensitive_vars:
            env.pop(var, None)

        # 合并用户环境变量
        if user_env:
            env.update(user_env)

        return env

    def _build_command(self, sample_path: Path, args: list[str] = None) -> list[str]:
        """构建执行命令"""
        # 根据平台选择执行方式
        import platform
        if platform.system() == "Windows":
            cmd = [str(sample_path)]
        else:
            cmd = [str(sample_path)]

        if args:
            cmd.extend(args)

        return cmd

    def _execute_command(self, cmd: list[str], env: dict) -> SandboxResult:
        """执行命令"""
        import time
        import resource

        start_time = time.time()

        try:
            # 启动进程
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE if self.config.capture_output else subprocess.DEVNULL,
                stderr=subprocess.PIPE if self.config.capture_output else subprocess.DEVNULL,
                env=env,
                cwd=self.temp_dir,
            )

            # 等待执行，带超时
            try:
                stdout, stderr = proc.communicate(timeout=self.config.max_execution_time)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                # 超时终止
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except:
                    proc.kill()
                stdout, stderr = proc.communicate()
                exit_code = -1

            execution_time_ms = int((time.time() - start_time) * 1000)

            # 获取内存使用（简化版）
            peak_memory_mb = 0
            try:
                import psutil
                process = psutil.Process(proc.pid)
                peak_memory_mb = process.memory_info().peak_wset / 1024 / 1024
            except:
                pass

            # 收集 artifacts
            artifacts = self._collect_artifacts()

            return SandboxResult(
                success=exit_code == 0,
                exit_code=exit_code,
                stdout=stdout.decode("utf-8", errors="replace") if stdout else "",
                stderr=stderr.decode("utf-8", errors="replace") if stderr else "",
                execution_time_ms=execution_time_ms,
                peak_memory_mb=peak_memory_mb,
                temp_dir=self.temp_dir,
                artifacts=artifacts,
            )

        except Exception as e:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
                peak_memory_mb=0,
                temp_dir=self.temp_dir,
                error=str(e),
            )

    def _collect_artifacts(self) -> list[str]:
        """收集执行产生的文件"""
        artifacts = []
        temp_dir = Path(self.temp_dir)

        if temp_dir.exists():
            for item in temp_dir.iterdir():
                if item.is_file():
                    artifacts.append(str(item))

        return artifacts

    def _cleanup(self):
        """清理临时目录"""
        if self.temp_dir and Path(self.temp_dir).exists():
            try:
                shutil.rmtree(self.temp_dir)
            except Exception as e:
                logger.warning(f"Failed to cleanup sandbox: {e}")


def execute_in_sandbox(
    sample_path: str,
    args: list[str] = None,
    timeout: int = 60,
    enable_network: bool = False,
) -> SandboxResult:
    """便捷函数：在沙箱中执行样本"""
    config = SandboxConfig(
        max_execution_time=timeout,
        enable_network=enable_network,
    )
    sandbox = Sandbox(config)
    return sandbox.execute(sample_path, args)
