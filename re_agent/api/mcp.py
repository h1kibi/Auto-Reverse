"""
MCP (Model Context Protocol) Adapter

Exposes Reverse-Agent tools as MCP-compatible endpoints.
Supports: analyze, solve, get_report, memory_search, list_artifacts

Design: Internal ToolSpec -> MCP Server Adapter -> Clients
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MCPTool:
    """MCP-compatible tool definition"""
    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)


class MCPAdapter:
    """Adapter that exposes Reverse-Agent as MCP tools"""

    def __init__(self):
        self.tools = self._build_tools()

    def _build_tools(self) -> dict[str, MCPTool]:
        return {
            "analyze_sample": MCPTool(
                name="analyze_sample",
                description="Run static analysis on a binary sample. Returns file info, strings, imports, and function details.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "sample_path": {"type": "string", "description": "Path to the sample binary"},
                        "skip_ghidra": {"type": "boolean", "default": True},
                    },
                    "required": ["sample_path"],
                },
            ),
            "solve_challenge": MCPTool(
                name="solve_challenge",
                description="Solve a CTF reverse challenge using the full solver pipeline.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "sample_path": {"type": "string", "description": "Path to the challenge binary"},
                        "flag_regex": {"type": "string", "default": r"flag\{[^}]+\}"},
                        "timeout": {"type": "integer", "default": 120},
                        "verify": {"type": "boolean", "default": True},
                    },
                    "required": ["sample_path"],
                },
            ),
            "get_report": MCPTool(
                name="get_report",
                description="Get the analysis/solve report for a sample by its SHA256 hash.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "sha256": {"type": "string", "description": "SHA256 hash of the sample"},
                    },
                    "required": ["sha256"],
                },
            ),
            "memory_search": MCPTool(
                name="memory_search",
                description="Search the memory store for relevant playbooks and past solve experiences.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query (tags, signals, keywords)"},
                        "limit": {"type": "integer", "default": 10},
                    },
                    "required": ["query"],
                },
            ),
            "list_artifacts": MCPTool(
                name="list_artifacts",
                description="List artifacts for a given sample run.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "sha256": {"type": "string", "description": "SHA256 hash of the sample"},
                    },
                    "required": ["sha256"],
                },
            ),
        }

    def list_tools(self) -> list[dict]:
        """Return MCP-compatible tools list"""
        return [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            }
            for t in self.tools.values()
        ]

    def call_tool(self, name: str, arguments: dict) -> dict:
        """Execute a tool call"""
        if name not in self.tools:
            raise ValueError(f"unknown tool: {name}")

        if name == "analyze_sample":
            return self._handle_analyze(arguments)
        elif name == "solve_challenge":
            return self._handle_solve(arguments)
        elif name == "get_report":
            return self._handle_get_report(arguments)
        elif name == "memory_search":
            return self._handle_memory_search(arguments)
        elif name == "list_artifacts":
            return self._handle_list_artifacts(arguments)
        else:
            raise ValueError(f"unhandled tool: {name}")

    def _handle_analyze(self, args: dict) -> dict:
        from ..pipeline import run_analysis
        from ..artifacts import compute_sha256, sample_artifact_dir

        sample_path = Path(args["sample_path"])
        skip_ghidra = args.get("skip_ghidra", True)

        if not sample_path.exists():
            return {"error": f"sample not found: {sample_path}"}

        sha256 = compute_sha256(sample_path)
        output_dir = sample_artifact_dir(Path("artifacts/results"), sha256)

        result = run_analysis(
            sample_path=str(sample_path),
            output_dir=str(output_dir),
            skip_ghidra=skip_ghidra,
        )

        return {
            "sha256": result.sample.sha256,
            "file_type": result.sample.file_type,
            "size": result.sample.size,
            "tool_count": len(result.tool_results),
            "tools": [tr.tool for tr in result.tool_results],
        }

    def _handle_solve(self, args: dict) -> dict:
        from ..ctf.pipeline import solve_challenge
        from ..artifacts import compute_sha256, sample_artifact_dir

        sample_path = Path(args["sample_path"])
        if not sample_path.exists():
            return {"error": f"sample not found: {sample_path}"}

        sha256 = compute_sha256(sample_path)
        output_dir = sample_artifact_dir(Path("artifacts/results"), sha256)

        result = solve_challenge(
            sample_path=str(sample_path),
            output_dir=str(output_dir),
            flag_regex=args.get("flag_regex", r"(?:flag|ctf)\{[^}]+\}"),
            skip_ghidra=True,
            timeout=args.get("timeout", 120),
            validate=args.get("verify", args.get("do_verify", True)),
            enable_memory=args.get("enable_memory", False),
        )

        return {
            "status": result.status,
            "solved": result.verified,
            "method": result.method,
            "best_flag": result.best_flag,
            "candidate_count": len(result.candidates),
            "summary": result.summary,
        }

    def _handle_get_report(self, args: dict) -> dict:
        from ..artifacts import sample_artifact_dir

        sha256 = args["sha256"]
        report_path = sample_artifact_dir(Path("artifacts/results"), sha256) / "report.md"

        if not report_path.exists():
            runs_dir = Path("artifacts/results")
            for run in runs_dir.glob(f"*{sha256[:8]}*"):
                rp = run / "report.md"
                if rp.exists():
                    report_path = rp
                    break

        if not report_path.exists():
            return {"error": f"report not found for {sha256[:16]}..."}

        return {"report": report_path.read_text(encoding="utf-8", errors="replace")[:10000]}

    def _handle_memory_search(self, args: dict) -> dict:
        try:
            from ..memory.store import MemoryStore
            from ..memory.retriever import MemoryRetriever

            store = MemoryStore("memory.db")
            retriever = MemoryRetriever(store)

            results = retriever.search(args["query"], limit=args.get("limit", 10))
            store.close()

            return {"query": args["query"], "results": results, "count": len(results)}
        except Exception as e:
            return {"error": str(e)}

    def _handle_list_artifacts(self, args: dict) -> dict:
        from ..artifacts import sample_artifact_dir

        sha256 = args["sha256"]
        artifact_dir = sample_artifact_dir(Path("artifacts/results"), sha256)

        if not artifact_dir.exists():
            return {"error": f"no artifacts for {sha256[:16]}..."}

        files = []
        for p in artifact_dir.rglob("*"):
            if p.is_file():
                files.append({
                    "path": str(p.relative_to(artifact_dir)),
                    "size": p.stat().st_size,
                })

        return {
            "sha256": sha256,
            "artifact_dir": str(artifact_dir),
            "files": files[:100],
        }
