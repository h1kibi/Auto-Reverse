"""
ltrace 工具适配器 - 库函数跟踪

使用方式：通过 DockerSandbox 在容器中执行
"""

from pathlib import Path
from .dynamic_base import DynamicResult


class LtraceTool:
    """ltrace 工具"""

    name = "ltrace"

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)

    def build_command(self) -> list[str]:
        """构建在容器中执行的命令"""
        return [
            "timeout", "60",
            "ltrace",
            "-f",
            "-s", "256",
            "-o", "{out}/ltrace.log",
            "{sample}",
        ]

    def parse_result(self, sandbox_result) -> DynamicResult:
        """解析沙箱执行结果"""
        log_path = self.output_dir / "ltrace.log"

        if log_path.exists():
            ltrace_log = log_path.read_text(encoding="utf-8", errors="replace")
            summary = self._analyze_libcalls(ltrace_log)
        else:
            ltrace_log = ""
            summary = "ltrace log not generated"

        return DynamicResult(
            tool=self.name,
            status="success" if sandbox_result.success else "failed",
            stdout=sandbox_result.stdout[:5000],
            stderr=sandbox_result.stderr[:2000],
            summary=summary,
            errors=[sandbox_result.stderr] if sandbox_result.stderr else [],
            runtime_ms=sandbox_result.execution_time_ms,
        )

    def _analyze_libcalls(self, ltrace_log: str) -> str:
        """分析库函数调用"""
        if not ltrace_log:
            return "No ltrace output"

        func_counts = {}
        crypto_calls = []
        memory_calls = []

        for line in ltrace_log.split("\n"):
            if "(" in line and ")" in line:
                func_name = line.split("(")[0].strip()
                if func_name:
                    func_counts[func_name] = func_counts.get(func_name, 0) + 1

                    if any(cc in func_name for cc in ["encrypt", "decrypt", "AES", "RSA", "hash"]):
                        crypto_calls.append(line[:200])
                    elif any(mc in func_name for mc in ["malloc", "free", "realloc"]):
                        memory_calls.append(line[:200])

        summary_parts = [f"Total library calls: {sum(func_counts.values())}"]

        if crypto_calls:
            summary_parts.append(f"Crypto-related calls: {len(crypto_calls)}")
            for call in crypto_calls[:3]:
                summary_parts.append(f"  {call[:100]}")

        if memory_calls:
            summary_parts.append(f"Memory allocation calls: {len(memory_calls)}")

        top_funcs = sorted(func_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_funcs:
            summary_parts.append("Top library functions:")
            for name, count in top_funcs:
                summary_parts.append(f"  {name}: {count}")

        return "\n".join(summary_parts)
