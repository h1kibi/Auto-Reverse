"""
报告生成器 - 生成 Markdown 格式的分析报告

证据驱动：报告必须引用 artifact，带置信度
"""

from datetime import datetime
from pathlib import Path

from .schema import AnalysisResult, ToolStatus, ArtifactType


class ReportGenerator:
    """分析报告生成器"""

    def __init__(self, output_dir: str = "artifacts"):
        self.output_dir = Path(output_dir)

    def generate(self, result: AnalysisResult) -> str:
        """生成 Markdown 报告"""
        sections = [
            self._header(result),
            self._basic_info(result),
            self._file_type(result),
            self._pe_analysis(result),
            self._strings_analysis(result),
            self._imports_analysis(result),
            self._sections_analysis(result),
            self._yara_matches(result),
            self._ghidra_analysis(result),
            self._tool_execution_log(result),
            self._footer(result),
        ]

        report = "\n\n".join(filter(None, sections))

        # 保存报告
        report_path = self.output_dir / "report.md"
        report_path.write_text(report, encoding="utf-8")

        return report

    def _header(self, result: AnalysisResult) -> str:
        return f"""# 逆向分析报告

**生成时间**: {result.timestamp}
**样本 SHA256**: `{result.sample.sha256}`"""

    def _basic_info(self, result: AnalysisResult) -> str:
        return f"""## 基本信息

| 属性 | 值 |
|------|-----|
| 文件路径 | `{result.sample.path}` |
| 文件大小 | {result.sample.size:,} bytes |
| MD5 | `{result.sample.md5}` |
| SHA1 | `{result.sample.sha1}` |
| SHA256 | `{result.sample.sha256}` |"""

    def _file_type(self, result: AnalysisResult) -> str:
        tool_result = self._find_tool_result(result, "file")
        if not tool_result:
            return None

        return f"""## 文件类型

- **结论**: {tool_result.summary}
- **置信度**: 高
- **证据**: `file` 命令输出"""

    def _pe_analysis(self, result: AnalysisResult) -> str:
        """PE 文件分析结果"""
        tool_result = self._find_tool_result(result, "pefile")
        if not tool_result:
            return None

        if tool_result.status != ToolStatus.SUCCESS:
            return None

        # 从 artifacts 中提取信息
        pe_info = None
        imports_summary = ""
        exports_summary = ""

        for artifact in tool_result.artifacts:
            if artifact.type == ArtifactType.FILE_INFO:
                pe_info = artifact
            elif artifact.type == ArtifactType.IMPORTS:
                imports_summary = f"- **导入**: 见 `{artifact.path}`"
            elif artifact.type == ArtifactType.FUNCTIONS:
                exports_summary = f"- **导出**: 见 `{artifact.path}`"

        if not pe_info:
            return f"""## PE 文件分析

- **结论**: {tool_result.summary}
- **置信度**: 高
- **证据**: `pefile` 库分析"""

        # 提取关键信息
        info_text = pe_info.metadata
        arch = info_text.get("architecture", "Unknown")
        file_type = info_text.get("file_type", "Unknown")
        subsystem = info_text.get("subsystem", "Unknown")

        return f"""## PE 文件分析

| 属性 | 值 |
|------|-----|
| 架构 | {arch} |
| 类型 | {file_type} |
| 子系统 | {subsystem} |

- **置信度**: 高
- **证据**: `pefile` 库分析

### 导入函数
{imports_summary}

### 导出函数
{exports_summary}

详见 artifacts 目录中的 `pe_imports.txt`、`pe_exports.txt`、`pe_sections.txt`"""

    def _strings_analysis(self, result: AnalysisResult) -> str:
        tool_result = self._find_tool_result(result, "strings")
        if not tool_result:
            return None

        # 从 artifact metadata 获取字符串数量
        count = 0
        for artifact in tool_result.artifacts:
            if artifact.type == ArtifactType.STRINGS:
                count = artifact.metadata.get("count", 0)
                break

        # 提取有趣的字符串（从 summary 中）
        interesting_lines = []
        if "Interesting strings found:" in tool_result.summary:
            lines = tool_result.summary.split("\n")
            in_interesting = False
            for line in lines:
                if "Interesting strings found:" in line:
                    in_interesting = True
                    continue
                if in_interesting and line.strip():
                    interesting_lines.append(line.strip())

        interesting_section = ""
        if interesting_lines:
            interesting_section = f"""
### 关键字符串

```
{chr(10).join(interesting_lines)}
```"""

        return f"""## 字符串分析

- **总字符串数**: {count}
- **置信度**: 高
- **证据**: `strings` 命令输出
{interesting_section}"""

    def _imports_analysis(self, result: AnalysisResult) -> str:
        tool_result = self._find_tool_result(result, "readelf")
        if not tool_result:
            return None

        # 查找导入相关的 artifact
        imports_artifact = None
        for artifact in tool_result.artifacts:
            if artifact.type == ArtifactType.IMPORTS:
                imports_artifact = artifact
                break

        if not imports_artifact:
            return None

        return f"""## 导入分析

- **动态依赖**: 见 `{imports_artifact.path}`
- **置信度**: 高
- **证据**: `readelf -d` 输出"""

    def _sections_analysis(self, result: AnalysisResult) -> str:
        # 尝试从 readelf 或 pefile 获取段信息
        for tool_name in ["readelf", "pefile"]:
            tool_result = self._find_tool_result(result, tool_name)
            if not tool_result:
                continue

            sections_artifact = None
            for artifact in tool_result.artifacts:
                if artifact.type == ArtifactType.SECTIONS:
                    sections_artifact = artifact
                    break

            if sections_artifact:
                return f"""## 段信息

- **详情**: 见 `{sections_artifact.path}`
- **置信度**: 高
- **证据**: `{tool_name}` 分析输出"""

        return None

    def _yara_matches(self, result: AnalysisResult) -> str:
        tool_result = self._find_tool_result(result, "yara")
        if not tool_result:
            return None

        if tool_result.status == ToolStatus.SKIPPED:
            return f"""## YARA 匹配

- **状态**: 跳过（{tool_result.summary}）"""

        if "No YARA matches" in tool_result.summary:
            return """## YARA 匹配

- **结果**: 无匹配规则"""

        return f"""## YARA 匹配

- **结果**: 发现匹配
- **详情**:
```
{tool_result.summary}
```
- **置信度**: 高
- **证据**: YARA 规则匹配"""

    def _ghidra_analysis(self, result: AnalysisResult) -> str:
        tool_result = self._find_tool_result(result, "ghidra")
        if not tool_result:
            return None

        if tool_result.status == ToolStatus.SKIPPED:
            return f"""## Ghidra 反编译

- **状态**: 跳过（{tool_result.summary}）"""

        if tool_result.status == ToolStatus.FAILED:
            return f"""## Ghidra 反编译

- **状态**: 失败
- **错误**: {tool_result.errors[0] if tool_result.errors else 'Unknown error'}"""

        # 统计 artifact
        func_count = 0
        decompiled_count = 0
        for artifact in tool_result.artifacts:
            if artifact.type == ArtifactType.FUNCTIONS:
                func_count = artifact.metadata.get("count", 0)
            elif artifact.type == ArtifactType.DECOMPILED_FUNCTION:
                decompiled_count += 1

        return f"""## Ghidra 反编译

- **函数数量**: {func_count}
- **已反编译**: {decompiled_count} 个函数
- **调用图**: 已生成
- **置信度**: 中（自动反编译可能有误差）
- **证据**: Ghidra headless 分析输出

### 关键函数

查看 `artifacts/functions.json` 获取完整函数列表。
查看 `artifacts/callgraph.json` 获取调用图。"""

    def _tool_execution_log(self, result: AnalysisResult) -> str:
        rows = []
        for tr in result.tool_results:
            status_icon = {
                ToolStatus.SUCCESS: "[OK]",
                ToolStatus.FAILED: "[FAIL]",
                ToolStatus.PARTIAL: "[PARTIAL]",
                ToolStatus.SKIPPED: "[SKIP]",
            }.get(tr.status, "[?]")

            rows.append(
                f"| {tr.tool} | {status_icon} {tr.status.value} | {tr.runtime_ms}ms | {len(tr.artifacts)} |"
            )

        return f"""## 工具执行日志

| 工具 | 状态 | 耗时 | Artifacts |
|------|------|------|-----------|
{chr(10).join(rows)}"""

    def _footer(self, result: AnalysisResult) -> str:
        return f"""---

## 待确认事项

- [ ] 动态分析（需人工批准）
- [ ] 网络行为验证
- [ ] 加密算法确认
- [ ] 漏洞验证

---

*报告由 Reverse-Agent 自动生成*
*证据文件位于 `{self.output_dir}/` 目录*"""

    def _find_tool_result(self, result: AnalysisResult, tool_name: str):
        """查找指定工具的结果"""
        for tr in result.tool_results:
            if tr.tool == tool_name:
                return tr
        return None
