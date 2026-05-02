"""
YARA 工具适配器 - 规则匹配
"""

from pathlib import Path
from .base import BaseTool
from ..schema import ToolResult, ToolStatus, ArtifactType


class YaraTool(BaseTool):
    """YARA 命令适配器"""

    name = "yara"
    version = "0.1.0"

    def __init__(self, output_dir: str = "artifacts", rules_dir: str = None):
        super().__init__(output_dir)
        self.rules_dir = rules_dir

    def run(self, sample_path: str, sample_sha256: str) -> ToolResult:
        def _execute():
            # 如果没有规则目录，尝试使用默认路径
            if not self.rules_dir:
                # 检查是否安装了 yara
                _, _, rc = self._run_command(["yara", "--version"])
                if rc != 0:
                    return ToolResult(
                        tool=self.name,
                        version=self.version,
                        sample_sha256=sample_sha256,
                        status=ToolStatus.SKIPPED,
                        summary="YARA not installed or not in PATH",
                    )

                # 使用默认规则目录或跳过
                default_rules = Path("/usr/share/yara-rules")
                if not default_rules.exists():
                    return ToolResult(
                        tool=self.name,
                        version=self.version,
                        sample_sha256=sample_sha256,
                        status=ToolStatus.SKIPPED,
                        summary="No YARA rules directory found",
                    )
                self.rules_dir = str(default_rules)

            # 扫描所有 .yar 文件
            rules_path = Path(self.rules_dir)
            yar_files = list(rules_path.glob("**/*.yar")) + list(rules_path.glob("**/*.yara"))

            if not yar_files:
                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.SKIPPED,
                    summary="No YARA rules found",
                )

            all_matches = []
            errors = []

            for rule_file in yar_files[:10]:  # 限制最多10个规则文件
                stdout, stderr, rc = self._run_command(
                    ["yara", str(rule_file), sample_path],
                    timeout=30,
                )
                if rc == 0 and stdout.strip():
                    matches = stdout.strip().split("\n")
                    all_matches.extend(matches)
                elif rc != 0 and stderr:
                    errors.append(f"yara {rule_file.name}: {stderr[:100]}")

            if all_matches:
                content = "\n".join(all_matches)
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.YARA_MATCHES,
                    content=content,
                    name="yara_matches",
                    metadata={"match_count": len(all_matches)},
                )

                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.SUCCESS,
                    artifacts=[artifact],
                    summary=f"YARA found {len(all_matches)} matches:\n" + "\n".join(all_matches[:10]),
                )
            else:
                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.SUCCESS,
                    summary="No YARA matches found",
                    errors=errors,
                )

        result, elapsed_ms = self._time_execution(_execute)
        result.runtime_ms = elapsed_ms
        return result
