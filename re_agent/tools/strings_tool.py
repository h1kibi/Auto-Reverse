"""
strings 工具适配器 - 提取可读字符串
"""

from .base import BaseTool
from ..schema import ToolResult, ToolStatus, ArtifactType


class StringsTool(BaseTool):
    """strings 命令适配器"""

    name = "strings"
    version = "0.1.0"

    def __init__(self, output_dir: str = "artifacts", min_length: int = 4):
        super().__init__(output_dir)
        self.min_length = min_length

    def run(self, sample_path: str, sample_sha256: str) -> ToolResult:
        def _execute():
            stdout, stderr, rc = self._run_command(
                ["strings", f"-n{self.min_length}", sample_path]
            )
            if rc != 0:
                # Fallback: Python-based string extraction (Windows compatible)
                stdout = _python_strings(sample_path, self.min_length)

            strings_list = stdout.strip().split("\n")
            strings_count = len(strings_list)

            # 保存完整 strings 输出
            artifact = self._create_artifact(
                artifact_type=ArtifactType.STRINGS,
                content=stdout,
                name="strings",
                metadata={"count": strings_count, "min_length": self.min_length},
            )

            # 提取关键字符串摘要（URL、IP、路径等）
            interesting = self._find_interesting_strings(strings_list)
            summary_lines = [f"Total strings: {strings_count}"]
            if interesting:
                summary_lines.append("Interesting strings found:")
                summary_lines.extend(interesting[:20])  # 最多显示20个

            return ToolResult(
                tool=self.name,
                version=self.version,
                sample_sha256=sample_sha256,
                status=ToolStatus.SUCCESS,
                artifacts=[artifact],
                summary="\n".join(summary_lines),
            )

        result, elapsed_ms = self._time_execution(_execute)
        result.runtime_ms = elapsed_ms
        return result

    def _find_interesting_strings(self, strings_list: list[str]) -> list[str]:
        """提取可能有趣的字符串"""
        import re

        interesting = []
        patterns = [
            (r"https?://\S+", "URL"),
            (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP"),
            (r"[A-Za-z]:\\[\w\\]+\.\w+", "WindowsPath"),
            (r"/[\w/]+\.\w+", "UnixPath"),
            (r"\w+@\w+\.\w+", "Email"),
            (r"password|passwd|secret|key|token", "Credential"),
            (r"error|warning|failed|success", "Status"),
        ]

        for s in strings_list:
            for pattern, label in patterns:
                if re.search(pattern, s, re.IGNORECASE):
                    interesting.append(f"  [{label}] {s[:100]}")
                    break

        return interesting


def _python_strings(filepath: str, min_length: int = 4) -> str:
    """Windows-compatible Python string extraction fallback."""
    import re
    strings = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        # Find sequences of printable ASCII
        current = []
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
                continue
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
        if len(current) >= min_length:
            strings.append("".join(current))
    except Exception:
        pass
    return "\n".join(strings)
