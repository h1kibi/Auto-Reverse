"""
objdump 工具适配器 - 反汇编和段信息
"""

from .base import BaseTool
from ..schema import ToolResult, ToolStatus, ArtifactType


class ObjdumpTool(BaseTool):
    """objdump 命令适配器"""

    name = "objdump"
    version = "0.1.0"

    def run(self, sample_path: str, sample_sha256: str) -> ToolResult:
        def _execute():
            artifacts = []
            errors = []

            # 1. 获取段头信息
            headers_out, headers_err, headers_rc = self._run_command(
                ["objdump", "-h", sample_path]
            )
            if headers_rc == 0:
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.SECTIONS,
                    content=headers_out,
                    name="section_headers",
                    metadata={"command": "objdump -h"},
                )
                artifacts.append(artifact)
            else:
                errors.append(f"objdump -h failed: {headers_err}")

            # 2. 获取符号表
            symbols_out, symbols_err, symbols_rc = self._run_command(
                ["objdump", "-t", sample_path]
            )
            if symbols_rc == 0:
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.FUNCTIONS,
                    content=symbols_out,
                    name="symbol_table",
                    metadata={"command": "objdump -t"},
                )
                artifacts.append(artifact)
            else:
                errors.append(f"objdump -t failed: {symbols_err}")

            # 3. 获取反汇编（仅代码段）
            disasm_out, disasm_err, disasm_rc = self._run_command(
                ["objdump", "-d", "--no-show-raw-insn", sample_path],
                timeout=120,
            )
            if disasm_rc == 0:
                # 只保存前50000行，避免过大
                lines = disasm_out.split("\n")
                truncated = lines[:50000]
                content = "\n".join(truncated)
                if len(lines) > 50000:
                    content += f"\n... (truncated, total {len(lines)} lines)"

                artifact = self._create_artifact(
                    artifact_type=ArtifactType.DISASSEMBLY,
                    content=content,
                    name="disassembly",
                    metadata={
                        "command": "objdump -d",
                        "total_lines": len(lines),
                        "truncated": len(lines) > 50000,
                    },
                )
                artifacts.append(artifact)
            else:
                errors.append(f"objdump -d failed: {disasm_err}")

            # 4. 获取重定位信息
            reloc_out, reloc_err, reloc_rc = self._run_command(
                ["objdump", "-r", sample_path]
            )
            if reloc_rc == 0:
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.IMPORTS,
                    content=reloc_out,
                    name="relocations",
                    metadata={"command": "objdump -r"},
                )
                artifacts.append(artifact)
            else:
                errors.append(f"objdump -r failed: {reloc_err}")

            # 生成摘要
            summary_parts = [f"objdump analysis completed with {len(artifacts)} artifacts"]
            if headers_rc == 0:
                # 提取段信息摘要
                for line in headers_out.split("\n"):
                    if ".text" in line or ".data" in line or ".rodata" in line:
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
