"""
Frida 工具适配器 - 动态 Instrumentation
"""

import json
from pathlib import Path
from .dynamic_base import BaseDynamicTool, DynamicResult


# Frida hook 脚本模板
FRIDA_HOOK_SCRIPTS = {
    "network": """
// Hook 网络相关 API
var connect = Module.findExportByName(null, 'connect');
if (connect) {
    Interceptor.attach(connect, {
        onEnter: function(args) {
            var sockaddr = args[1];
            var port = sockaddr.add(2).readU16();
            var ip = sockaddr.add(4).readByteArray(4);
            var ipStr = Array.from(new Uint8Array(ip)).join('.');
            console.log('[connect] ' + ipStr + ':' + port);
            send({type: 'network', call: 'connect', ip: ipStr, port: port});
        }
    });
}

var send_func = Module.findExportByName(null, 'send');
if (send_func) {
    Interceptor.attach(send_func, {
        onEnter: function(args) {
            var size = args[2].toInt32();
            console.log('[send] size=' + size);
            send({type: 'network', call: 'send', size: size});
        }
    });
}

var recv_func = Module.findExportByName(null, 'recv');
if (recv_func) {
    Interceptor.attach(recv_func, {
        onLeave: function(retval) {
            var size = retval.toInt32();
            console.log('[recv] size=' + size);
            send({type: 'network', call: 'recv', size: size});
        }
    });
}
""",

    "crypto": """
// Hook 加密相关 API
var crypto_funcs = ['encrypt', 'decrypt', 'AES_encrypt', 'AES_decrypt', 'EVP_EncryptUpdate', 'EVP_DecryptUpdate'];
crypto_funcs.forEach(function(funcName) {
    var func = Module.findExportByName(null, funcName);
    if (func) {
        Interceptor.attach(func, {
            onEnter: function(args) {
                console.log('[' + funcName + '] called');
                send({type: 'crypto', call: funcName});
            }
        });
    }
});
""",

    "file": """
// Hook 文件操作 API
var fopen = Module.findExportByName(null, 'fopen');
if (fopen) {
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            var path = args[0].readUtf8String();
            var mode = args[1].readUtf8String();
            console.log('[fopen] path=' + path + ' mode=' + mode);
            send({type: 'file', call: 'fopen', path: path, mode: mode});
        }
    });
}

var fread = Module.findExportByName(null, 'fread');
if (fread) {
    Interceptor.attach(fread, {
        onEnter: function(args) {
            var size = args[1].toInt32() * args[2].toInt32();
            console.log('[fread] size=' + size);
            send({type: 'file', call: 'fread', size: size});
        }
    });
}
""",

    "process": """
// Hook 进程相关 API
var system = Module.findExportByName(null, 'system');
if (system) {
    Interceptor.attach(system, {
        onEnter: function(args) {
            var cmd = args[0].readUtf8String();
            console.log('[system] cmd=' + cmd);
            send({type: 'process', call: 'system', cmd: cmd});
        }
    });
}

var exec = Module.findExportByName(null, 'execve');
if (exec) {
    Interceptor.attach(exec, {
        onEnter: function(args) {
            var path = args[0].readUtf8String();
            console.log('[execve] path=' + path);
            send({type: 'process', call: 'execve', path: path});
        }
    });
}
""",
}


class FridaTool(BaseDynamicTool):
    """Frida 适配器"""

    name = "frida"
    requires_confirmation = True

    def __init__(
        self,
        output_dir: str = "artifacts/dynamic",
        hook_categories: list[str] = None,
    ):
        super().__init__(output_dir)
        self.hook_categories = hook_categories or ["network", "crypto", "file", "process"]

    def run(
        self,
        sample_path: str,
        timeout: int = 60,
        args: list[str] = None,
        env: dict = None,
    ) -> DynamicResult:
        def _execute():
            # 生成 Frida 脚本
            script_content = self._generate_script()
            script_path = self.output_dir / "frida_hooks.js"
            script_path.write_text(script_content, encoding="utf-8")

            # 构建 frida 命令
            # 使用 frida-trace 或 frida 命令
            cmd = [
                "frida",
                "-f", sample_path,  # spawn
                "-l", str(script_path),  # 加载脚本
                "--no-pause",
                "-q",  # quiet
            ]
            if args:
                cmd.extend(["--args", *args])

            # 设置超时
            import subprocess
            import os
            import signal

            process_env = os.environ.copy()
            if env:
                process_env.update(env)

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=process_env,
                )

                # 等待指定时间后终止
                try:
                    stdout, stderr = proc.communicate(timeout=timeout)
                    rc = proc.returncode
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=5)
                    stdout, stderr = proc.communicate()
                    rc = -1

            except FileNotFoundError:
                return DynamicResult(
                    tool=self.name,
                    status="failed",
                    summary="frida not found. Install: pip install frida-tools",
                    errors=["frida command not found"],
                )
            except Exception as e:
                return DynamicResult(
                    tool=self.name,
                    status="failed",
                    summary=f"Frida execution failed: {str(e)}",
                    errors=[str(e)],
                )

            # 解析输出
            events = self._parse_output(stdout)
            summary = self._generate_summary(events)

            # 保存 artifacts
            artifacts = []

            # 保存完整日志
            log_path = self._save_artifact("frida_output.log", stdout)
            artifacts.append({
                "type": "frida_log",
                "path": log_path,
                "name": "frida_output",
            })

            # 保存事件 JSON
            events_path = self._save_artifact(
                "frida_events.json",
                json.dumps(events, indent=2, ensure_ascii=False),
            )
            artifacts.append({
                "type": "frida_events",
                "path": events_path,
                "name": "frida_events",
            })

            # 保存 hook 脚本
            artifacts.append({
                "type": "frida_script",
                "path": str(script_path),
                "name": "frida_hooks",
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

    def _generate_script(self) -> str:
        """生成 Frida hook 脚本"""
        scripts = []
        for category in self.hook_categories:
            if category in FRIDA_HOOK_SCRIPTS:
                scripts.append(f"// === {category.upper()} HOOKS ===")
                scripts.append(FRIDA_HOOK_SCRIPTS[category])

        return "\n".join(scripts)

    def _parse_output(self, output: str) -> list[dict]:
        """解析 Frida 输出"""
        events = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            # 尝试解析 JSON 消息
            if line.startswith("{"):
                try:
                    event = json.loads(line)
                    events.append(event)
                except:
                    pass

            # 解析 console.log 输出
            elif "[" in line and "]" in line:
                try:
                    # 格式: [type] key=value ...
                    bracket_end = line.index("]")
                    event_type = line[1:bracket_end]
                    details = line[bracket_end + 1:].strip()

                    event = {"type": event_type, "raw": details}
                    # 解析 key=value
                    for part in details.split():
                        if "=" in part:
                            key, value = part.split("=", 1)
                            event[key] = value

                    events.append(event)
                except:
                    events.append({"type": "unknown", "raw": line})

        return events

    def _generate_summary(self, events: list[dict]) -> str:
        """生成摘要"""
        if not events:
            return "No events captured"

        # 按类型统计
        type_counts = {}
        for event in events:
            event_type = event.get("type", "unknown")
            type_counts[event_type] = type_counts.get(event_type, 0) + 1

        summary_parts = [f"Total events: {len(events)}"]

        # 网络事件
        network_events = [e for e in events if e.get("type") == "network"]
        if network_events:
            summary_parts.append(f"Network events: {len(network_events)}")
            # 显示连接目标
            connections = [e for e in network_events if e.get("call") == "connect"]
            for conn in connections[:3]:
                ip = conn.get("ip", "?")
                port = conn.get("port", "?")
                summary_parts.append(f"  Connect to: {ip}:{port}")

        # 加密事件
        crypto_events = [e for e in events if e.get("type") == "crypto"]
        if crypto_events:
            summary_parts.append(f"Crypto events: {len(crypto_events)}")
            calls = set(e.get("call", "?") for e in crypto_events)
            summary_parts.append(f"  Functions: {', '.join(calls)}")

        # 文件事件
        file_events = [e for e in events if e.get("type") == "file"]
        if file_events:
            summary_parts.append(f"File events: {len(file_events)}")
            # 显示访问的文件
            files = set(e.get("path", "?") for e in file_events if e.get("path"))
            for f in list(files)[:3]:
                summary_parts.append(f"  File: {f}")

        # 进程事件
        process_events = [e for e in events if e.get("type") == "process"]
        if process_events:
            summary_parts.append(f"Process events: {len(process_events)}")
            for e in process_events[:3]:
                cmd = e.get("cmd") or e.get("path", "?")
                summary_parts.append(f"  {e.get('call', '?')}: {cmd}")

        return "\n".join(summary_parts)
