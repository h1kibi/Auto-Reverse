"""
strace 工具适配器 - 系统调用跟踪
"""

from .dynamic_base import BaseDynamicTool, DynamicResult


class StraceTool(BaseDynamicTool):
    """strace 命令适配器"""

    name = "strace"
    requires_confirmation = True

    def run(
        self,
        sample_path: str,
        timeout: int = 60,
        args: list[str] = None,
        env: dict = None,
    ) -> DynamicResult:
        def _execute():
            # 构建 strace 命令
            cmd = [
                "strace",
                "-f",  # 跟踪子进程
                "-e", "trace=network,process,file",  # 跟踪网络、进程、文件
                "-o", str(self.output_dir / "strace.log"),
                sample_path,
            ]
            if args:
                cmd.extend(args)

            stdout, stderr, rc = self._run_command(cmd, timeout=timeout, env=env)

            # 读取 strace 日志
            log_path = self.output_dir / "strace.log"
            strace_log = ""
            if log_path.exists():
                strace_log = log_path.read_text(encoding="utf-8", errors="replace")

            # 分析系统调用
            summary = self._analyze_syscalls(strace_log)

            # 保存 artifact
            artifacts = []
            if strace_log:
                artifact_path = self._save_artifact("strace_full.log", strace_log)
                artifacts.append({
                    "type": "strace_log",
                    "path": artifact_path,
                    "name": "strace_full",
                })

            status = "success" if rc == 0 else "failed"
            if rc == -1:
                status = "timeout"

            return DynamicResult(
                tool=self.name,
                status=status,
                stdout=stdout[:5000],
                stderr=stderr[:2000],
                artifacts=artifacts,
                summary=summary,
                exit_code=rc,
            )

        result, elapsed_ms = self._time_execution(_execute)
        result.runtime_ms = elapsed_ms
        return result

    def _analyze_syscalls(self, strace_log: str) -> str:
        """分析系统调用"""
        if not strace_log:
            return "No strace output"

        # 统计系统调用
        syscall_counts = {}
        network_calls = []
        file_calls = []
        process_calls = []

        for line in strace_log.split("\n"):
            # 解析系统调用
            if "(" in line and "=" in line:
                syscall = line.split("(")[0].strip()
                if syscall:
                    syscall_counts[syscall] = syscall_counts.get(syscall, 0) + 1

                # 分类
                if any(nc in syscall for nc in ["socket", "connect", "send", "recv", "bind", "listen"]):
                    network_calls.append(line[:200])
                elif any(fc in syscall for fc in ["open", "read", "write", "close", "stat"]):
                    file_calls.append(line[:200])
                elif any(pc in syscall for pc in ["fork", "exec", "clone", "wait", "kill"]):
                    process_calls.append(line[:200])

        # 生成摘要
        summary_parts = [f"Total syscalls: {sum(syscall_counts.values())}"]

        if network_calls:
            summary_parts.append(f"Network calls: {len(network_calls)}")
            # 显示前几个网络调用
            for call in network_calls[:3]:
                summary_parts.append(f"  {call[:100]}")

        if process_calls:
            summary_parts.append(f"Process calls: {len(process_calls)}")

        # 显示最常见的系统调用
        top_syscalls = sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_syscalls:
            summary_parts.append("Top syscalls:")
            for name, count in top_syscalls:
                summary_parts.append(f"  {name}: {count}")

        return "\n".join(summary_parts)
