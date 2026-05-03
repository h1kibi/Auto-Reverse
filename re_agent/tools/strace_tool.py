"""
strace 工具适配器 - 系统调用跟踪

使用方式：通过 DockerSandbox 在容器中执行
"""

from pathlib import Path
from .dynamic_base import DynamicResult


class StraceTool:
    """strace 工具"""

    name = "strace"

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)

    def build_command(self) -> list[str]:
        """构建在容器中执行的命令"""
        return [
            "timeout", "60",
            "strace",
            "-f",
            "-tt",
            "-s", "256",
            "-o", "{out}/strace.log",
            "{sample}",
        ]

    def parse_result(self, sandbox_result) -> DynamicResult:
        """解析沙箱执行结果"""
        log_path = self.output_dir / "strace.log"

        if log_path.exists():
            strace_log = log_path.read_text(encoding="utf-8", errors="replace")
            summary = self._analyze_syscalls(strace_log)
        else:
            strace_log = ""
            summary = "strace log not generated"

        return DynamicResult(
            tool=self.name,
            status="success" if sandbox_result.success else "failed",
            stdout=sandbox_result.stdout[:5000],
            stderr=sandbox_result.stderr[:2000],
            summary=summary,
            errors=[sandbox_result.stderr] if sandbox_result.stderr else [],
            runtime_ms=sandbox_result.execution_time_ms,
        )

    def _analyze_syscalls(self, strace_log: str) -> str:
        """分析系统调用"""
        if not strace_log:
            return "No strace output"

        syscall_counts = {}
        network_calls = []
        process_calls = []

        for line in strace_log.split("\n"):
            if "(" in line and "=" in line:
                syscall = line.split("(")[0].strip()
                if syscall:
                    syscall_counts[syscall] = syscall_counts.get(syscall, 0) + 1

                if any(nc in syscall for nc in ["socket", "connect", "send", "recv", "bind"]):
                    network_calls.append(line[:200])
                elif any(pc in syscall for pc in ["fork", "exec", "clone", "wait", "kill"]):
                    process_calls.append(line[:200])

        summary_parts = [f"Total syscalls: {sum(syscall_counts.values())}"]

        if network_calls:
            summary_parts.append(f"Network calls: {len(network_calls)}")
            for call in network_calls[:3]:
                summary_parts.append(f"  {call[:100]}")

        if process_calls:
            summary_parts.append(f"Process calls: {len(process_calls)}")

        top_syscalls = sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_syscalls:
            summary_parts.append("Top syscalls:")
            for name, count in top_syscalls:
                summary_parts.append(f"  {name}: {count}")

        return "\n".join(summary_parts)
