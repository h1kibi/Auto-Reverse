"""
PE 文件分析工具 - Windows 原生支持

使用 pefile 库分析 Windows PE 文件
"""

from .base import BaseTool
from ..schema import ToolResult, ToolStatus, ArtifactType

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


class PEFileTool(BaseTool):
    """PE 文件分析工具（Windows 原生）"""

    name = "pefile"
    version = "0.1.0"

    def run(self, sample_path: str, sample_sha256: str) -> ToolResult:
        def _execute():
            if not HAS_PEFILE:
                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.FAILED,
                    summary="pefile not installed. Run: pip install pefile",
                    errors=["pefile module not found"],
                )

            try:
                pe = pefile.PE(sample_path)
            except pefile.PEFormatError as e:
                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.FAILED,
                    summary=f"Not a valid PE file: {e}",
                    errors=[str(e)],
                )

            artifacts = []
            summary_parts = []

            # 1. PE 基本信息
            pe_info = self._get_pe_info(pe)
            artifact = self._create_artifact(
                artifact_type=ArtifactType.FILE_INFO,
                content=pe_info["text"],
                name="pe_info",
                metadata=pe_info["metadata"],
            )
            artifacts.append(artifact)
            summary_parts.append(pe_info["summary"])

            # 2. 导入表
            imports_text, imports_summary = self._get_imports(pe)
            if imports_text:
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.IMPORTS,
                    content=imports_text,
                    name="pe_imports",
                    metadata={"type": "imports"},
                )
                artifacts.append(artifact)
                summary_parts.append(imports_summary)

            # 3. 导出表
            exports_text, exports_summary = self._get_exports(pe)
            if exports_text:
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.FUNCTIONS,
                    content=exports_text,
                    name="pe_exports",
                    metadata={"type": "exports"},
                )
                artifacts.append(artifact)
                summary_parts.append(exports_summary)

            # 4. 节信息
            sections_text = self._get_sections(pe)
            artifact = self._create_artifact(
                artifact_type=ArtifactType.SECTIONS,
                content=sections_text,
                name="pe_sections",
                metadata={"type": "sections"},
            )
            artifacts.append(artifact)

            pe.close()

            return ToolResult(
                tool=self.name,
                version=self.version,
                sample_sha256=sample_sha256,
                status=ToolStatus.SUCCESS,
                artifacts=artifacts,
                summary="\n".join(summary_parts),
            )

        result, elapsed_ms = self._time_execution(_execute)
        result.runtime_ms = elapsed_ms
        return result

    def _get_pe_info(self, pe) -> dict:
        """获取 PE 基本信息"""
        lines = []
        metadata = {}

        # 文件头
        machine = pe.FILE_HEADER.Machine
        machine_map = {0x14c: "i386", 0x8664: "AMD64", 0x1c0: "ARM", 0xaa64: "ARM64"}
        arch = machine_map.get(machine, f"Unknown (0x{machine:x})")

        # 特征
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        is_exe = bool(pe.FILE_HEADER.Characteristics & 0x0002)
        is_sys = bool(pe.FILE_HEADER.Characteristics & 0x1000)

        file_type = "DLL" if is_dll else "SYS" if is_sys else "EXE" if is_exe else "Unknown"

        # 子系统
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        subsystem_map = {
            1: "Native", 2: "Windows GUI", 3: "Windows Console",
            5: "OS/2 Console", 7: "POSIX Console",
        }
        subsystem_str = subsystem_map.get(subsystem, f"Unknown ({subsystem})")

        lines.append(f"Architecture: {arch}")
        lines.append(f"File Type: {file_type}")
        lines.append(f"Subsystem: {subsystem_str}")
        lines.append(f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
        lines.append(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
        lines.append(f"Section Alignment: 0x{pe.OPTIONAL_HEADER.SectionAlignment:x}")
        lines.append(f"File Alignment: 0x{pe.OPTIONAL_HEADER.FileAlignment:x}")
        lines.append(f"Size of Image: 0x{pe.OPTIONAL_HEADER.SizeOfImage:x}")
        lines.append(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        lines.append(f"Timestamp: 0x{pe.FILE_HEADER.TimeDateStamp:x}")

        # 时间戳转换
        from datetime import datetime
        try:
            ts = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
            lines.append(f"Compile Time: {ts.isoformat()}")
        except:
            pass

        metadata = {
            "architecture": arch,
            "file_type": file_type,
            "subsystem": subsystem_str,
            "is_dll": is_dll,
            "is_exe": is_exe,
        }

        summary = f"PE {file_type}, {arch}, {subsystem_str} subsystem"

        return {
            "text": "\n".join(lines),
            "metadata": metadata,
            "summary": summary,
        }

    def _get_imports(self, pe) -> tuple[str, str]:
        """获取导入表"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return None, "No imports found"

        lines = []
        dll_count = 0
        func_count = 0

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace')
            lines.append(f"\n[{dll_name}]")
            dll_count += 1

            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='replace')
                    lines.append(f"  {func_name}")
                    func_count += 1
                else:
                    lines.append(f"  ordinal_{imp.ordinal}")

        summary = f"Imports: {dll_count} DLLs, {func_count} functions"
        return "\n".join(lines), summary

    def _get_exports(self, pe) -> tuple[str, str]:
        """获取导出表"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return None, "No exports found"

        lines = []
        export_count = 0

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                name = exp.name.decode('utf-8', errors='replace')
                lines.append(f"  {name} (ordinal: {exp.ordinal})")
                export_count += 1
            else:
                lines.append(f"  ordinal_{exp.ordinal}")
                export_count += 1

        summary = f"Exports: {export_count} functions"
        return "\n".join(lines), summary

    def _get_sections(self, pe) -> str:
        """获取节信息"""
        lines = []
        lines.append(f"{'Name':<10} {'VirtualSize':>12} {'VirtualAddr':>12} {'RawSize':>10} {'Entropy':>8}")
        lines.append("-" * 60)

        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='replace').rstrip('\x00')
            entropy = section.get_entropy()
            lines.append(
                f"{name:<10} {section.Misc_VirtualSize:>12} "
                f"0x{section.VirtualAddress:>10x} "
                f"{section.SizeOfRawData:>10} "
                f"{entropy:>8.2f}"
            )

        return "\n".join(lines)
