"""
动态分析 Pipeline

安全规则：
- 必须人工确认后执行
- 默认无网络
- 资源限制
- 自动保存日志
"""

import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from .schema import AnalysisResult, ToolResult, ToolStatus, ArtifactType
from .tools.dynamic_base import DynamicResult
from .tools.strace_tool import StraceTool
from .tools.ltrace_tool import LtraceTool
from .tools.frida_tool import FridaTool
from .sandbox import Sandbox, SandboxConfig, SandboxResult
from .database import Database, FunctionSummary
from .llm import BaseLLMClient, ChatMessage

logger = logging.getLogger(__name__)


@dataclass
class DynamicAnalysisConfig:
    """动态分析配置"""
    # 工具开关
    enable_strace: bool = True
    enable_ltrace: bool = True
    enable_frida: bool = True

    # 沙箱配置
    timeout: int = 60
    enable_network: bool = False
    max_memory_mb: int = 512

    # Frida 配置
    frida_hooks: list[str] = field(default_factory=lambda: ["network", "crypto", "file", "process"])

    # 输出目录
    output_dir: str = "artifacts/dynamic"


@dataclass
class DynamicAnalysisResult:
    """动态分析结果"""
    sample_sha256: str
    sandbox_result: Optional[SandboxResult] = None
    tool_results: list[DynamicResult] = field(default_factory=list)
    summary: str = ""
    events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sample_sha256": self.sample_sha256,
            "sandbox_result": self.sandbox_result.__dict__ if self.sandbox_result else None,
            "tool_results": [r.to_dict() for r in self.tool_results],
            "summary": self.summary,
            "events": self.events[:1000],  # 限制大小
        }


class DynamicAnalysisPipeline:
    """动态分析 Pipeline"""

    def __init__(
        self,
        config: DynamicAnalysisConfig = None,
        db: Database = None,
        llm: BaseLLMClient = None,
    ):
        self.config = config or DynamicAnalysisConfig()
        self.output_dir = Path(self.config.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.db = db
        self.llm = llm

        # 初始化工具
        self.tools = {}
        if self.config.enable_strace:
            self.tools["strace"] = StraceTool(str(self.output_dir))
        if self.config.enable_ltrace:
            self.tools["ltrace"] = LtraceTool(str(self.output_dir))
        if self.config.enable_frida:
            self.tools["frida"] = FridaTool(
                str(self.output_dir),
                self.config.frida_hooks,
            )

    def analyze(
        self,
        sample_path: str,
        sample_sha256: str,
        confirmed: bool = False,
    ) -> DynamicAnalysisResult:
        """执行动态分析"""
        if not confirmed:
            logger.warning("Dynamic analysis requires confirmation. Set confirmed=True")
            return DynamicAnalysisResult(
                sample_sha256=sample_sha256,
                summary="Analysis not confirmed. Set confirmed=True to execute.",
            )

        logger.info(f"Starting dynamic analysis: {sample_path}")

        result = DynamicAnalysisResult(sample_sha256=sample_sha256)

        # 1. 沙箱执行
        logger.info("Step 1: Sandbox execution...")
        sandbox_config = SandboxConfig(
            max_execution_time=self.config.timeout,
            enable_network=self.config.enable_network,
            max_memory_mb=self.config.max_memory_mb,
        )
        sandbox = Sandbox(sandbox_config)
        sandbox_result = sandbox.execute(sample_path)
        result.sandbox_result = sandbox_result

        if not sandbox_result.success:
            logger.warning(f"Sandbox execution failed: {sandbox_result.error}")
            result.summary = f"Sandbox execution failed: {sandbox_result.error or sandbox_result.stderr[:200]}"
            return result

        # 2. 运行跟踪工具
        logger.info("Step 2: Running trace tools...")
        for tool_name, tool in self.tools.items():
            logger.info(f"  Running {tool_name}...")
            try:
                tool_result = tool.run(sample_path, timeout=self.config.timeout)
                result.tool_results.append(tool_result)
                logger.info(f"  {tool_name}: {tool_result.status}")
            except Exception as e:
                logger.error(f"  {tool_name} failed: {e}")
                result.tool_results.append(DynamicResult(
                    tool=tool_name,
                    status="failed",
                    errors=[str(e)],
                ))

        # 3. 生成摘要
        logger.info("Step 3: Generating summary...")
        result.summary = self._generate_summary(result)

        # 4. 保存结果
        self._save_result(result)

        # 5. 更新数据库（如果启用）
        if self.db:
            self._update_database(result)

        logger.info("Dynamic analysis complete")
        return result

    def _generate_summary(self, result: DynamicAnalysisResult) -> str:
        """生成动态分析摘要"""
        summary_parts = []

        # 沙箱执行摘要
        if result.sandbox_result:
            sb = result.sandbox_result
            summary_parts.append(f"执行时间: {sb.execution_time_ms}ms")
            summary_parts.append(f"退出码: {sb.exit_code}")
            if sb.peak_memory_mb > 0:
                summary_parts.append(f"峰值内存: {sb.peak_memory_mb:.1f}MB")

        # 工具结果摘要
        for tr in result.tool_results:
            if tr.summary:
                summary_parts.append(f"\n[{tr.tool}]")
                summary_parts.append(tr.summary)

        # 使用 LLM 分析（如果有）
        if self.llm and result.tool_results:
            llm_summary = self._llm_analyze(result)
            if llm_summary:
                summary_parts.append(f"\n[LLM 分析]")
                summary_parts.append(llm_summary)

        return "\n".join(summary_parts)

    def _llm_analyze(self, result: DynamicAnalysisResult) -> str:
        """使用 LLM 分析动态行为"""
        # 收集所有工具的摘要
        tool_summaries = []
        for tr in result.tool_results:
            if tr.summary:
                tool_summaries.append(f"[{tr.tool}]\n{tr.summary}")

        if not tool_summaries:
            return ""

        context = "\n\n".join(tool_summaries)

        prompt = f"""分析以下动态执行结果，总结样本的行为特征。

{context}

请用中文回答，包含：
1. 主要行为（网络、文件、进程等）
2. 可疑行为
3. 置信度（0-1）"""

        try:
            messages = [ChatMessage(role="user", content=prompt)]
            response = self.llm.chat(messages, temperature=0.3, max_tokens=500)
            return response.content
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return ""

    def _save_result(self, result: DynamicAnalysisResult):
        """保存分析结果"""
        import json

        result_file = self.output_dir / "dynamic_result.json"
        result_file.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        # 保存摘要
        summary_file = self.output_dir / "dynamic_summary.txt"
        summary_file.write_text(result.summary, encoding="utf-8")

        logger.info(f"Dynamic results saved to {self.output_dir}")

    def _update_database(self, result: DynamicAnalysisResult):
        """更新数据库"""
        # 从动态分析中提取函数信息
        # 这里可以根据需要扩展
        pass


def run_dynamic_analysis(
    sample_path: str,
    sample_sha256: str,
    output_dir: str = "artifacts/dynamic",
    confirmed: bool = False,
    enable_strace: bool = True,
    enable_ltrace: bool = True,
    enable_frida: bool = True,
    timeout: int = 60,
) -> DynamicAnalysisResult:
    """便捷函数：执行动态分析"""
    config = DynamicAnalysisConfig(
        enable_strace=enable_strace,
        enable_ltrace=enable_ltrace,
        enable_frida=enable_frida,
        timeout=timeout,
        output_dir=output_dir,
    )
    pipeline = DynamicAnalysisPipeline(config)
    return pipeline.analyze(sample_path, sample_sha256, confirmed)
