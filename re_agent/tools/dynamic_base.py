"""
动态分析工具基类
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
import time
import logging

logger = logging.getLogger(__name__)


@dataclass
class DynamicResult:
    """动态分析结果"""
    tool: str
    status: str  # success, failed, timeout, killed
    stdout: str = ""
    stderr: str = ""
    artifacts: list[dict] = field(default_factory=list)
    summary: str = ""
    errors: list[str] = field(default_factory=list)
    runtime_ms: int = 0
    pid: Optional[int] = None
    exit_code: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "status": self.status,
            "stdout": self.stdout[:10000],  # 限制大小
            "stderr": self.stderr[:5000],
            "artifacts": self.artifacts,
            "summary": self.summary,
            "errors": self.errors,
            "runtime_ms": self.runtime_ms,
            "pid": self.pid,
            "exit_code": self.exit_code,
        }


class BaseDynamicTool(ABC):
    """动态分析工具基类"""

    name: str = "base"
    requires_confirmation: bool = True  # 是否需要人工确认

    def __init__(self, output_dir: str = "artifacts/dynamic"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def run(
        self,
        sample_path: str,
        timeout: int = 60,
        args: list[str] = None,
        env: dict = None,
    ) -> DynamicResult:
        """执行动态分析"""
        pass

    def _run_command(
        self,
        cmd: list[str],
        timeout: int = 60,
        env: dict = None,
    ) -> tuple[str, str, int]:
        """执行系统命令"""
        import subprocess
        import os

        try:
            # 合并环境变量
            process_env = os.environ.copy()
            if env:
                process_env.update(env)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=process_env,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout}s", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1
        except Exception as e:
            return "", str(e), -1

    def _save_artifact(self, name: str, content: str) -> str:
        """保存 artifact 文件"""
        file_path = self.output_dir / name
        file_path.write_text(content, encoding="utf-8")
        return str(file_path)

    def _time_execution(self, func):
        """测量执行时间"""
        start = time.time()
        result = func()
        elapsed_ms = int((time.time() - start) * 1000)
        return result, elapsed_ms
