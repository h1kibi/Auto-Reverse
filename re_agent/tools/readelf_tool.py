"""
readelf 工具适配器 - ELF 文件信息提取
"""

from .base import BaseTool
from ..schema import ToolResult, ToolStatus, ArtifactType


class ReadelfTool(BaseTool):
    """readelf 命令适配器"""

    name = "readelf"
    version = "0.1.0"

    def run(self, sample_path: str, sample_sha256: str) -> ToolResult:
        def _execute():
            artifacts = []
            errors = []

            # 1. 获取文件头信息
            header_out, header_err, header_rc = self._run_command(
                ["readelf", "-h", sample_path]
            )
            if header_rc == 0:
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.FILE_INFO,
                    content=header_out,
                    name="elf_header",
                    metadata={"section": "header"},
                )
                artifacts.append(artifact)
            else:
                errors.append(f"readelf -h failed: {header_err}")

            # 2. 获取节信息
            sections_out, sections_err, sections_rc = self._run_command(
                ["readelf", "-S", sample_path]
            )
            if sections_rc == 0:
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.SECTIONS,
                    content=sections_out,
                    name="sections",
                    metadata={"section": "sections"},
                )
                artifacts.append(artifact)
            else:
                errors.append(f"readelf -S failed: {sections_err}")

            # 3. 获取符号表
            symbols_out, symbols_err, symbols_rc = self._run_command(
                ["readelf", "-s", sample_path]
            )
            if symbols_rc == 0:
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.FUNCTIONS,
                    content=symbols_out,
                    name="symbols",
                    metadata={"section": "symbols"},
                )
                artifacts.append(artifact)
            else:
                errors.append(f"readelf -s failed: {symbols_err}")

            # 4. 获取导入表
            imports_out, imports_err, imports_rc = self._run_command(
                ["readelf", "-d", sample_path]
            )
            if imports_rc == 0:
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.IMPORTS,
                    content=imports_out,
                    name="dynamic_deps",
                    metadata={"section": "dynamic"},
                )
                artifacts.append(artifact)
            else:
                errors.append(f"readelf -d failed: {imports_err}")

            # 生成摘要
            summary_parts = [f"readelf analysis completed with {len(artifacts)} artifacts"]
            if header_rc == 0:
                # 提取关键信息
                for line in header_out.split("\n"):
                    if "Class:" in line or "Machine:" in line or "Entry point" in line:
                        summary_parts.append(line.strip())

            status = ToolStatus.SUCCESS if not errors else ToolStatus.PARTIAL
            return ToolResult(
                tool=self.name,
                version=self.version,
                sample_sha256=sample_sha256,
                status=status,
                artifacts=artifacts,
                summary="\n".join(summary_parts),
                errors=errors,
            )

        result, elapsed_ms = self._time_execution(_execute)
        result.runtime_ms = elapsed_ms
        return result
