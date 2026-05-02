"""
工具基类 - 所有工具适配器的基础
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
import time
import logging

from ..schema import ToolResult, Artifact, ToolStatus, ArtifactType

logger = logging.getLogger(__name__)


class BaseTool(ABC):
    """工具基类"""

    name: str = "base"
    version: str = "0.1.0"

    def __init__(self, output_dir: str = "artifacts"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def run(self, sample_path: str, sample_sha256: str) -> ToolResult:
        """执行工具分析"""
        pass

    def _create_artifact(
        self,
        artifact_type: ArtifactType,
        content: str,
        name: str,
        address: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> Artifact:
        """创建 artifact 文件并返回 Artifact 对象"""
        # 生成文件名
        safe_name = name.replace("/", "_").replace("\\", "_").replace(":", "_")
        file_name = f"{artifact_type.value}_{safe_name}.txt"
        file_path = self.output_dir / file_name

        # 写入内容
        file_path.write_text(content, encoding="utf-8")

        return Artifact(
            type=artifact_type,
            path=str(file_path),
            name=name,
            address=address,
            metadata=metadata or {},
        )

    def _run_command(self, cmd: list[str], timeout: int = 60) -> tuple[str, str, int]:
        """执行系统命令"""
        import subprocess

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout}s", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1
        except Exception as e:
            return "", str(e), -1

    def _time_execution(self, func):
        """测量执行时间"""
        start = time.time()
        result = func()
        elapsed_ms = int((time.time() - start) * 1000)
        return result, elapsed_ms
