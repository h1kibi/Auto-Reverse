"""
Ghidra headless 工具适配器 - 反编译和函数分析
"""

import json
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

    def _find_ghidra(self) -> str:
        """尝试自动查找 Ghidra 安装路径"""
        import os

        # 常见路径
        candidates = [
            "/opt/ghidra",
            "/usr/local/ghidra",
            os.path.expanduser("~/ghidra"),
            "C:\\ghidra",
        ]

        for path in candidates:
            if Path(path).exists():
                return path

        # 检查环境变量
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

            # 创建临时项目目录
            project_dir = self.output_dir / "ghidra_project"
            project_dir.mkdir(exist_ok=True)

            # 创建 Ghidra 脚本
            script_content = self._generate_analysis_script()
            script_path = self.output_dir / "analyze.py"
            script_path.write_text(script_content, encoding="utf-8")

            # 执行 Ghidra headless 分析
            cmd = [
                str(ghidra_bin),
                str(project_dir),
                "temp_project",
                "-import", sample_path,
                "-postScript", str(script_path),
                "-scriptPath", str(self.output_dir),
                "-deleteProject",
            ]

            stdout, stderr, rc = self._run_command(cmd, timeout=300)

            if rc != 0:
                return ToolResult(
                    tool=self.name,
                    version=self.version,
                    sample_sha256=sample_sha256,
                    status=ToolStatus.FAILED,
                    summary=f"Ghidra analysis failed",
                    errors=[stderr[:500] if stderr else "Unknown error"],
                )

            # 读取脚本输出
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
        """生成 Ghidra Java/Python 分析脚本"""
        return f'''
# Ghidra headless analysis script
# Outputs function list, call graph, and decompiled code

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

output_dir = "{self.output_dir.as_posix()}"
max_functions = {self.max_functions}

def run():
    monitor = ConsoleTaskMonitor()
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    func_manager = currentProgram.getFunctionManager()
    functions = list(func_manager.getFunctions(True))

    # 限制函数数量
    if len(functions) > max_functions:
        functions = functions[:max_functions]

    # 1. 导出函数列表
    func_list = []
    for func in functions:
        entry = func.getEntryPoint()
        func_list.append({{
            "name": func.getName(),
            "address": str(entry),
            "is_thunk": func.isThunk(),
            "is_library": func.isLibrary(),
            "param_count": func.getParameterCount(),
        }})

    func_json = json.dumps(func_list, indent=2)
    with open(output_dir + "/functions.json", "w") as f:
        f.write(func_json)

    # 2. 导出调用图
    call_graph = {{}}
    for func in functions[:200]:  # 限制调用图大小
        callers = [str(c.getEntryPoint()) for c in func.getCallingFunctions(monitor)]
        callees = [str(c.getEntryPoint()) for c in func.getCalledFunctions(monitor)]
        call_graph[str(func.getEntryPoint())] = {{
            "name": func.getName(),
            "callers": callers,
            "callees": callees,
        }}

    graph_json = json.dumps(call_graph, indent=2)
    with open(output_dir + "/callgraph.json", "w") as f:
        f.write(graph_json)

    # 3. 反编译关键函数（前50个）
    decompiled = {{}}
    for func in functions[:50]:
        result = decomp.decompileFunction(func, 60, monitor)
        if result and result.depiledFunction():
            decompiled[func.getName()] = {{
                "address": str(func.getEntryPoint()),
                "code": result.getDecompiledFunction().getC(),
            }}

    dec_json = json.dumps(decompiled, indent=2, ensure_ascii=False)
    with open(output_dir + "/decompiled.json", "w") as f:
        f.write(dec_json)

    print("Analysis complete: {{}} functions, {{}} call graph entries, {{}} decompiled".format(
        len(func_list), len(call_graph), len(decompiled)
    ))

run()
'''

    def _collect_artifacts(self, sample_sha256: str) -> list:
        """收集 Ghidra 输出的 artifact"""
        artifacts = []

        # 函数列表
        func_file = self.output_dir / "functions.json"
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
        graph_file = self.output_dir / "callgraph.json"
        if graph_file.exists():
            content = graph_file.read_text(encoding="utf-8")
            artifact = self._create_artifact(
                artifact_type=ArtifactType.CALL_GRAPH,
                content=content,
                name="call_graph",
            )
            artifacts.append(artifact)

        # 反编译代码
        dec_file = self.output_dir / "decompiled.json"
        if dec_file.exists():
            content = dec_file.read_text(encoding="utf-8")
            decompiled = json.loads(content)

            # 为每个函数创建单独的 artifact
            for func_name, info in decompiled.items():
                artifact = self._create_artifact(
                    artifact_type=ArtifactType.DECOMPILED_FUNCTION,
                    content=info["code"],
                    name=func_name,
                    address=info["address"],
                )
                artifacts.append(artifact)

        return artifacts
