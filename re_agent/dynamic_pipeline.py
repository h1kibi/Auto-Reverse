"""
动态分析 Pipeline

安全规则：
- 必须人工确认后执行
- 通过 Docker 沙箱执行，不在宿主机直接运行样本
- 默认无网络
- 资源限制
"""

import json
import logging
from pathlib import Path
from dataclasses import dataclass, field

from .tools.dynamic_base import DynamicResult
from .tools.strace_tool import StraceTool
from .tools.ltrace_tool import LtraceTool
from .sandbox import DockerSandbox, DockerSandboxConfig
from .database import Database
from .llm import BaseLLMClient, ChatMessage

logger = logging.getLogger(__name__)


@dataclass
class DynamicAnalysisConfig:
    """动态分析配置"""
    enable_strace: bool = True
    enable_ltrace: bool = True
    enable_frida: bool = False  # MVP 阶段默认关闭
    timeout: int = 60
    enable_network: bool = False
    max_memory_mb: int = 512
    output_dir: str = "artifacts/dynamic"
    sandbox_image: str = "reverse-agent-sandbox:latest"


@dataclass
class DynamicAnalysisResult:
    """动态分析结果"""
    sample_sha256: str
    tool_results: list[DynamicResult] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "sample_sha256": self.sample_sha256,
            "tool_results": [r.to_dict() for r in self.tool_results],
            "summary": self.summary,
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
        logger.info(f"  Sandbox image: {self.config.sandbox_image}")
        logger.info(f"  Network: {'enabled' if self.config.enable_network else 'disabled'}")
        logger.info(f"  Timeout: {self.config.timeout}s")

        result = DynamicAnalysisResult(sample_sha256=sample_sha256)

        # 创建 Docker 沙箱
        sandbox = DockerSandbox(DockerSandboxConfig(
            image=self.config.sandbox_image,
            timeout=self.config.timeout,
            memory_mb=self.config.max_memory_mb,
            enable_network=self.config.enable_network,
        ))

        # 执行每个工具
        for tool_name, tool in self.tools.items():
            logger.info("Running %s in Docker sandbox...", tool_name)

            try:
                command = tool.build_command()
                sandbox_result = sandbox.run_tool(
                    sample_path=sample_path,
                    output_dir=self.output_dir,
                    command_template=command,
                )

                tool_result = tool.parse_result(sandbox_result)
                result.tool_results.append(tool_result)

                logger.info("  %s: %s", tool_name, tool_result.status)

            except Exception as e:
                logger.exception("%s failed", tool_name)
                result.tool_results.append(DynamicResult(
                    tool=tool_name,
                    status="failed",
                    errors=[str(e)],
                ))

        # 生成摘要
        result.summary = self._generate_summary(result)

        # 保存结果
        self._save_result(result)

        # 更新数据库
        if self.db:
            self._update_database(result)

        logger.info("Dynamic analysis complete")
        return result

    def _generate_summary(self, result: DynamicAnalysisResult) -> str:
        """生成动态分析摘要"""
        summary_parts = []

        for tr in result.tool_results:
            if tr.summary:
                summary_parts.append(f"[{tr.tool}]")
                summary_parts.append(tr.summary)
                summary_parts.append("")

        # 使用 LLM 分析（如果有）
        if self.llm and result.tool_results:
            llm_summary = self._llm_analyze(result)
            if llm_summary:
                summary_parts.append("[LLM 分析]")
                summary_parts.append(llm_summary)

        return "\n".join(summary_parts) if summary_parts else "No analysis results"

    def _llm_analyze(self, result: DynamicAnalysisResult) -> str:
        """使用 LLM 分析动态行为"""
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
        result_file = self.output_dir / "dynamic_result.json"
        result_file.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        summary_file = self.output_dir / "dynamic_summary.txt"
        summary_file.write_text(result.summary, encoding="utf-8")

        logger.info(f"Dynamic results saved to {self.output_dir}")

    def _update_database(self, result: DynamicAnalysisResult):
        """更新数据库"""
        pass


def run_dynamic_analysis(
    sample_path: str,
    sample_sha256: str,
    output_dir: str = "artifacts/dynamic",
    confirmed: bool = False,
    enable_strace: bool = True,
    enable_ltrace: bool = True,
    enable_frida: bool = False,
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
