"""
分析 Pipeline - 阶段1 静态 Triage

核心原则：
- 确定性优先：工具负责确定性分析
- 大输出写 artifact 文件，小摘要进上下文
- 自动检测文件类型，选择合适的工具
"""

import logging
import platform
from pathlib import Path

from .schema import (
    AnalysisResult,
    SampleInfo,
    ToolResult,
    compute_hashes,
)
from .tools import (
    FileTool,
    StringsTool,
    ReadelfTool,
    ObjdumpTool,
    YaraTool,
    GhidraTool,
)
from .tools.pefile_tool import PEFileTool, HAS_PEFILE

logger = logging.getLogger(__name__)


def detect_file_type(file_path: str) -> str:
    """检测文件类型：ELF 或 PE"""
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            if magic[:4] == b'\x7fELF':
                return "ELF"
            elif magic[:2] == b'MZ':
                return "PE"
            else:
                return "UNKNOWN"
    except:
        return "UNKNOWN"


class AnalysisPipeline:
    """静态分析 Pipeline"""

    def __init__(
        self,
        output_dir: str = "artifacts",
        ghidra_home: str = None,
        yara_rules_dir: str = None,
        skip_ghidra: bool = False,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.is_windows = platform.system() == "Windows"

        # 初始化通用工具
        self.tools = {
            "strings": StringsTool(output_dir),
            "yara": YaraTool(output_dir, yara_rules_dir),
        }

        # Linux 工具（Windows 上可能不可用）
        if not self.is_windows:
            self.tools.update({
                "file": FileTool(output_dir),
                "readelf": ReadelfTool(output_dir),
                "objdump": ObjdumpTool(output_dir),
            })

        # PE 文件工具（跨平台）
        if HAS_PEFILE:
            self.tools["pefile"] = PEFileTool(output_dir)

        # Ghidra 可选
        if not skip_ghidra:
            self.tools["ghidra"] = GhidraTool(output_dir, ghidra_home)

    def analyze(self, sample_path: str) -> AnalysisResult:
        """执行完整分析流程"""
        sample_path = str(Path(sample_path).resolve())

        logger.info(f"Starting analysis: {sample_path}")

        # Stage 1: Intake - 计算 hash
        logger.info("Stage 1: Computing hashes...")
        hashes = compute_hashes(sample_path)
        sample_info = SampleInfo(
            path=sample_path,
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            size=hashes["size"],
        )

        result = AnalysisResult(sample=sample_info)

        # 检测文件类型
        file_type = detect_file_type(sample_path)
        logger.info(f"Detected file type: {file_type}")

        # Stage 2: Static triage - 根据文件类型选择工具
        logger.info("Stage 2: Static triage...")

        if file_type == "PE" and "pefile" in self.tools:
            # PE 文件分析
            logger.info("  Running pefile (PE analysis)...")
            try:
                pefile_result = self.tools["pefile"].run(sample_path, sample_info.sha256)
                result.tool_results.append(pefile_result)
                sample_info.file_type = "PE"
                logger.info(f"  pefile: {pefile_result.status.value}")
            except Exception as e:
                logger.error(f"  pefile failed: {e}")

        elif file_type == "ELF" and not self.is_windows:
            # ELF 文件分析（仅 Linux）
            for tool_name in ["file", "readelf", "objdump"]:
                if tool_name in self.tools:
                    tool = self.tools[tool_name]
                    logger.info(f"  Running {tool_name}...")
                    try:
                        tool_result = tool.run(sample_path, sample_info.sha256)
                        result.tool_results.append(tool_result)
                        logger.info(f"  {tool_name}: {tool_result.status.value}")
                    except Exception as e:
                        logger.error(f"  {tool_name} failed: {e}")

        else:
            # 未知文件类型或工具不可用
            logger.info(f"  Skipping type-specific tools (type={file_type}, platform={platform.system()})")

        # 字符串提取（跨平台，但 Windows 上 strings 命令可能不可用）
        if "strings" in self.tools:
            logger.info("  Running strings...")
            try:
                strings_result = self.tools["strings"].run(sample_path, sample_info.sha256)
                result.tool_results.append(strings_result)
                logger.info(f"  strings: {strings_result.status.value}")
            except Exception as e:
                logger.error(f"  strings failed: {e}")

        # Stage 3: YARA 规则匹配
        logger.info("Stage 3: YARA scanning...")
        try:
            yara_result = self.tools["yara"].run(sample_path, sample_info.sha256)
            result.tool_results.append(yara_result)
            logger.info(f"  yara: {yara_result.status.value}")
        except Exception as e:
            logger.error(f"  yara failed: {e}")

        # Stage 4: Ghidra 反编译（可选）
        if "ghidra" in self.tools:
            logger.info("Stage 4: Ghidra decompilation...")
            try:
                ghidra_result = self.tools["ghidra"].run(sample_path, sample_info.sha256)
                result.tool_results.append(ghidra_result)
                logger.info(f"  ghidra: {ghidra_result.status.value}")
            except Exception as e:
                logger.error(f"  ghidra failed: {e}")

        # 保存分析结果
        self._save_result(result)

        logger.info(f"Analysis complete: {len(result.tool_results)} tools executed")
        return result

    def _save_result(self, result: AnalysisResult):
        """保存分析结果到 JSON 文件"""
        result_file = self.output_dir / "analysis_result.json"
        result_file.write_text(result.to_json(), encoding="utf-8")
        logger.info(f"Result saved to {result_file}")


def run_analysis(
    sample_path: str,
    output_dir: str = "artifacts",
    ghidra_home: str = None,
    yara_rules_dir: str = None,
    skip_ghidra: bool = False,
) -> AnalysisResult:
    """便捷函数：执行单个样本的分析"""
    pipeline = AnalysisPipeline(
        output_dir=output_dir,
        ghidra_home=ghidra_home,
        yara_rules_dir=yara_rules_dir,
        skip_ghidra=skip_ghidra,
    )
    return pipeline.analyze(sample_path)
