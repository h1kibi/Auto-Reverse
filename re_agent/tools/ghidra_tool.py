"""
Ghidra headless 工具适配器 - 反编译和函数分析
"""

import json
import os
from pathlib import Path
from .base import BaseTool
from ..schema import ToolResult, ToolStatus, ArtifactType


class GhidraTool(BaseTool):
    """Ghidra headless (analyzeHeadless) 适配器"""

    name = "ghidra"
    version = "0.1.0"

    def __init__(
        self,
        output_dir: str = "artifacts",
        ghidra_home: str = None,
        max_functions: int = 500,
    ):
        super().__init__(output_dir)
        self.ghidra_home = ghidra_home or self._find_ghidra()
        self.max_functions = max_functions
        self.ghidra_out = Path(output_dir) / "ghidra"

    def _find_ghidra(self) -> str:
        """尝试自动查找 Ghidra 安装路径"""
        candidates = [
            "/opt/ghidra",
            "/usr/local/ghidra",
            os.path.expanduser("~/ghidra"),
            "C:\\ghidra",
        ]

        for path in candidates:
            if Path(path).exists():
                return path

        if "GHIDRA_HOME" in os.environ:
            return os.environ["GHIDRA_HOME"]

        return None

    def run(self, sample_path: str, sample_sha256: str) -> ToolResult:
        def _execute():
            if not self.ghidra_home:
                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.SKIPPED,
                    summary="Ghidra not found. Set GHIDRA_HOME or install to /opt/ghidra",
                )

            ghidra_bin = Path(self.ghidra_home) / "support" / "analyzeHeadless"
            if not ghidra_bin.exists():
                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.FAILED,
                    summary=f"Ghidra analyzeHeadless not found at {ghidra_bin}",
                )

            # 创建输出目录
            self.ghidra_out.mkdir(parents=True, exist_ok=True)
            project_dir = self.ghidra_out / "project"
            project_dir.mkdir(exist_ok=True)
            decompiled_dir = self.ghidra_out / "decompiled"
            decompiled_dir.mkdir(exist_ok=True)

            # 创建 Ghidra 脚本
            script_content = self._generate_analysis_script()
            script_path = self.ghidra_out / "analyze.py"
            script_path.write_text(script_content, encoding="utf-8")

            # 执行 Ghidra headless 分析
            cmd = [
                str(ghidra_bin),
                str(project_dir),
                f"project_{sample_sha256[:12]}",
                "-import", sample_path,
                "-postScript", script_path.name,
                "-scriptPath", str(self.ghidra_out),
                "-deleteProject",
            ]

            stdout, stderr, rc = self._run_command(cmd, timeout=300)

            if rc != 0:
                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.FAILED,
                    summary="Ghidra analysis failed",
                    errors=[stderr[:500] if stderr else "Unknown error"],
                )

            # 收集 artifacts
            artifacts = self._collect_artifacts(sample_sha256)

            summary = f"Ghidra analysis completed: {len(artifacts)} artifacts generated"
            return ToolResult(
                tool=self.name,
                version=self.version,
                sample_sha256=sample_sha256,
                status=ToolStatus.SUCCESS,
                artifacts=artifacts,
                summary=summary,
            )

        result, elapsed_ms = self._time_execution(_execute)
        result.runtime_ms = elapsed_ms
        return result

    def _generate_analysis_script(self) -> str:
        """生成 Ghidra Python 分析脚本"""
        return f'''
import json
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUTPUT_DIR = r"{self.ghidra_out.as_posix()}"
MAX_FUNCTIONS = {self.max_functions}

def safe_name(name):
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)

def run():
    monitor = ConsoleTaskMonitor()
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    func_manager = currentProgram.getFunctionManager()
    functions = list(func_manager.getFunctions(True))

    if len(functions) > MAX_FUNCTIONS:
        functions = functions[:MAX_FUNCTIONS]

    decompiled_dir = os.path.join(OUTPUT_DIR, "decompiled")
    if not os.path.exists(decompiled_dir):
        os.makedirs(decompiled_dir)

    function_rows = []
    call_edges = []

    for func in functions:
        name = func.getName()
        entry = str(func.getEntryPoint())

        row = {{
            "name": name,
            "address": entry,
            "is_library": func.isExternal(),
            "body_size": func.getBody().getNumAddresses(),
        }}
        function_rows.append(row)

        called = func.getCalledFunctions(monitor)
        for callee in called:
            call_edges.append({{
                "caller": name,
                "caller_address": entry,
                "callee": callee.getName(),
                "callee_address": str(callee.getEntryPoint()),
            }})

        try:
            res = decomp.decompileFunction(func, 60, monitor)
            if res and res.getDecompiledFunction():
                c_code = res.getDecompiledFunction().getC()
                out_name = safe_name(name) + "_" + entry.replace(":", "_") + ".c"
                with open(os.path.join(decompiled_dir, out_name), "w") as f:
                    f.write(c_code)
                row["decompiled_path"] = os.path.join("decompiled", out_name)
        except Exception as e:
            row["decompile_error"] = str(e)

    with open(os.path.join(OUTPUT_DIR, "functions.json"), "w") as f:
        json.dump(function_rows, f, indent=2)

    with open(os.path.join(OUTPUT_DIR, "callgraph.json"), "w") as f:
        json.dump(call_edges, f, indent=2)

    print("Analysis complete: {{}} functions, {{}} call edges, {{}} decompiled".format(
        len(function_rows), len(call_edges),
        len([r for r in function_rows if "decompiled_path" in r])
    ))

run()
'''

    def _collect_artifacts(self, sample_sha256: str) -> list:
        """收集 Ghidra 输出的 artifact"""
        artifacts = []

        # 函数列表
        func_file = self.ghidra_out / "functions.json"
        if func_file.exists():
            content = func_file.read_text(encoding="utf-8")
            func_list = json.loads(content)
            artifact = self._create_artifact(
                artifact_type=ArtifactType.FUNCTIONS,
                content=content,
                name="function_list",
                metadata={"count": len(func_list)},
            )
            artifacts.append(artifact)

        # 调用图
        graph_file = self.ghidra_out / "callgraph.json"
        if graph_file.exists():
            content = graph_file.read_text(encoding="utf-8")
            artifact = self._create_artifact(
                artifact_type=ArtifactType.CALL_GRAPH,
                content=content,
                name="call_graph",
            )
            artifacts.append(artifact)

        # 反编译代码
        decompiled_dir = self.ghidra_out / "decompiled"
        if decompiled_dir.exists():
            for c_file in decompiled_dir.glob("*.c"):
                content = c_file.read_text(encoding="utf-8")
                # 从文件名提取函数名和地址
                parts = c_file.stem.rsplit("_", 1)
                func_name = parts[0] if len(parts) > 1 else c_file.stem
                address = parts[1] if len(parts) > 1 else ""

                artifact = self._create_artifact(
                    artifact_type=ArtifactType.DECOMPILED_FUNCTION,
                    content=content,
                    name=func_name,
                    address=address,
                )
                artifacts.append(artifact)

        return artifacts
