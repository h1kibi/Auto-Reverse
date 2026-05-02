"""
file 工具适配器 - 文件类型识别
"""

from .base import BaseTool
from ..schema import ToolResult, ToolStatus, ArtifactType


class FileTool(BaseTool):
    """file 命令适配器"""

    name = "file"
    version = "0.1.0"

    def run(self, sample_path: str, sample_sha256: str) -> ToolResult:
        def _execute():
            stdout, stderr, rc = self._run_command(["file", sample_path])
            if rc != 0:
                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.FAILED,
                    summary=f"file command failed: {stderr}",
                    errors=[stderr],
                )

            # 解析输出
            file_info = stdout.strip()
            artifact = self._create_artifact(
                artifact_type=ArtifactType.FILE_INFO,
                content=file_info,
                name="file_info",
                metadata={"raw_output": file_info},
            )

            return ToolResult(
                tool=self.name,
                version=self.version,
                sample_sha256=sample_sha256,
                status=ToolStatus.SUCCESS,
                artifacts=[artifact],
                summary=file_info,
            )

        result, elapsed_ms = self._time_execution(_execute)
        result.runtime_ms = elapsed_ms
        return result
