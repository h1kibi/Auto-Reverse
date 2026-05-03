"""
ltrace 工具适配器 - 库函数跟踪
"""

from .dynamic_base import BaseDynamicTool, DynamicResult


class LtraceTool(BaseDynamicTool):
    """ltrace 命令适配器"""

    name = "ltrace"
    requires_confirmation = True

    def run(
        self,
        sample_path: str,
        timeout: int = 60,
        args: list[str] = None,
        env: dict = None,
    ) -> DynamicResult:
        def _execute():
            # 构建 ltrace 命令
            cmd = [
                "ltrace",
                "-f",  # 跟踪子进程
                "-e", "malloc+free+puts+printf+sprintf+memcpy+strcmp+strlen",  # 常见函数
                "-o", str(self.output_dir / "ltrace.log"),
                sample_path,
            ]
            if args:
                cmd.extend(args)

            stdout, stderr, rc = self._run_command(cmd, timeout=timeout, env=env)

            # 读取 ltrace 日志
            log_path = self.output_dir / "ltrace.log"
            ltrace_log = ""
            if log_path.exists():
                ltrace_log = log_path.read_text(encoding="utf-8", errors="replace")

            # 分析库函数调用
            summary = self._analyze_libcalls(ltrace_log)

            # 保存 artifact
            artifacts = []
            if ltrace_log:
                artifact_path = self._save_artifact("ltrace_full.log", ltrace_log)
                artifacts.append({
                    "type": "ltrace_log",
                    "path": artifact_path,
                    "name": "ltrace_full",
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

    def _analyze_libcalls(self, ltrace_log: str) -> str:
        """分析库函数调用"""
        if not ltrace_log:
            return "No ltrace output"

        # 统计库函数调用
        func_counts = {}
        crypto_calls = []
        memory_calls = []
        string_calls = []

        for line in ltrace_log.split("\n"):
            # 解析函数调用
            if "(" in line and ")" in line:
                func_name = line.split("(")[0].strip()
                if func_name:
                    func_counts[func_name] = func_counts.get(func_name, 0) + 1

                # 分类
                if any(cc in func_name for cc in ["encrypt", "decrypt", "AES", "RSA", "hash", "MD5", "SHA"]):
                    crypto_calls.append(line[:200])
                elif any(mc in func_name for mc in ["malloc", "free", "realloc", "calloc"]):
                    memory_calls.append(line[:200])
                elif any(sc in func_name for sc in ["strcpy", "strcat", "strcmp", "strlen", "memcpy"]):
                    string_calls.append(line[:200])

        # 生成摘要
        summary_parts = [f"Total library calls: {sum(func_counts.values())}"]

        if crypto_calls:
            summary_parts.append(f"Crypto-related calls: {len(crypto_calls)}")
            for call in crypto_calls[:3]:
                summary_parts.append(f"  {call[:100]}")

        if memory_calls:
            summary_parts.append(f"Memory allocation calls: {len(memory_calls)}")

        if string_calls:
            summary_parts.append(f"String operation calls: {len(string_calls)}")

        # 显示最常见的库函数
        top_funcs = sorted(func_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_funcs:
            summary_parts.append("Top library functions:")
            for name, count in top_funcs:
                summary_parts.append(f"  {name}: {count}")

        return "\n".join(summary_parts)
