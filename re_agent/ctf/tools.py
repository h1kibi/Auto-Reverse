"""
CTF local tool runtime.

PR-4 目标：
- 不接 OpenAI
- 不做复杂 Agent
- 只提供 AI 以后可调用的本地工具接口
"""

from __future__ import annotations

import json
import re
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..pipeline import run_analysis
from .profiler import build_profile
from .validator import FlagValidator

JsonDict = dict[str, Any]


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: JsonDict
    handler: Callable[[JsonDict], JsonDict]


class ArtifactStore:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, relative: str) -> Path:
        p = self.root / relative
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def write_json(self, relative: str, payload: JsonDict) -> str:
        p = self.path(relative)
        p.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(p.relative_to(self.root))

    def append_jsonl(self, relative: str, payload: JsonDict) -> str:
        p = self.path(relative)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return str(p.relative_to(self.root))

    def write_text(self, relative: str, text: str) -> str:
        p = self.path(relative)
        p.write_text(text, encoding="utf-8")
        return str(p.relative_to(self.root))


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"duplicate tool: {spec.name}")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")
        return self._tools[name]

    def names(self) -> list[str]:
        return sorted(self._tools)


class ToolExecutor:
    def __init__(self, registry: ToolRegistry, store: ArtifactStore):
        self.registry = registry
        self.store = store

    def execute(self, tool_name: str, arguments: JsonDict) -> JsonDict:
        started = time.time()

        try:
            spec = self.registry.get(tool_name)
            result = spec.handler(arguments)
            elapsed_ms = int((time.time() - started) * 1000)

            self.store.append_jsonl(
                "agent_trace.jsonl",
                {
                    "event": "tool_result",
                    "tool": tool_name,
                    "arguments": arguments,
                    "elapsed_ms": elapsed_ms,
                    "ok": True,
                    "summary": result.get("summary", ""),
                    "artifacts": result.get("artifacts", []),
                },
            )

            return {
                "ok": True,
                "tool": tool_name,
                **result,
            }

        except Exception as e:
            elapsed_ms = int((time.time() - started) * 1000)
            tb = traceback.format_exc()

            self.store.append_jsonl(
                "agent_trace.jsonl",
                {
                    "event": "tool_error",
                    "tool": tool_name,
                    "arguments": arguments,
                    "elapsed_ms": elapsed_ms,
                    "ok": False,
                    "error": str(e),
                    "traceback": tb[-4000:],
                },
            )

            return {
                "ok": False,
                "tool": tool_name,
                "summary": f"{tool_name} failed: {e}",
                "error": str(e),
            }


def build_default_ctf_registry(store: ArtifactStore) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(_profile_sample_tool(store))
    registry.register(_validate_candidate_tool(store))
    registry.register(_decompile_function_tool(store))
    return registry


# ========== 辅助函数 ==========

FLAG_RE = re.compile(
    r"(?:flag|ctf|picoCTF|hgame|nssctf|h1kibi)\{[^}\r\n]{1,160}\}",
    re.IGNORECASE,
)

BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{12,}={0,2}$")
HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){6,}$")


def _interesting_strings(strings: list[str]) -> list[str]:
    keywords = [
        "correct", "wrong", "success", "fail", "invalid",
        "input", "flag", "ctf", "password", "key", "check", "verify",
    ]
    out = []
    seen = set()
    for s in strings:
        low = s.lower()
        if any(k in low for k in keywords) and s not in seen:
            out.append(s[:240])
            seen.add(s)
    return out


def _suggest_next_tools(
    flag_like: list[str],
    encoded_like: list[dict[str, str]],
    success_strings: list[str],
    failure_strings: list[str],
    skip_ghidra: bool,
) -> list[str]:
    out = []
    if flag_like:
        out.append("validate_candidate")
    if encoded_like:
        out.append("decode_strings")
    if success_strings or failure_strings:
        out.append("decompile_function")
    if skip_ghidra:
        out.append("profile_sample(skip_ghidra=false)")
    return out


def _find_decompile_artifacts(root: Path) -> list[Path]:
    patterns = [
        "**/*decomp*.c",
        "**/*decomp*.txt",
        "**/*decompile*.json",
        "**/*functions*.json",
        "**/ghidra/**/*.json",
        "**/ghidra/**/*.c",
        "**/ghidra/**/*.txt",
    ]
    out = []
    for pat in patterns:
        out.extend(root.glob(pat))
    return sorted({p for p in out if p.is_file()})


def _pick_decompile_artifact(paths: list[Path], function: str) -> Path | None:
    needle = function.lower()
    for p in paths:
        if needle in p.name.lower():
            return p
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")[:1_000_000]
        except Exception:
            continue
        if needle in text.lower():
            return p
    return paths[0] if paths else None


def _read_excerpt(path: Path, function: str, max_lines: int) -> JsonDict:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    needle = function.lower()
    start = 0
    for i, line in enumerate(lines):
        if needle in line.lower():
            start = max(0, i - 10)
            break
    end = min(len(lines), start + max_lines)
    return {
        "start_line": start + 1,
        "end_line": end,
        "total_lines": len(lines),
        "text": "\n".join(lines[start:end]),
    }


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "function"


# ========== 工具定义 ==========

def _profile_sample_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        sample_path = Path(args["sample_path"]).resolve()
        skip_ghidra = bool(args.get("skip_ghidra", True))

        analysis = run_analysis(
            sample_path=str(sample_path),
            output_dir=str(store.path("analysis")),
            skip_ghidra=skip_ghidra,
        )

        profile = build_profile(analysis)
        strings = list(profile.strings or [])

        flag_like = []
        encoded_like = []

        for s in strings:
            x = s.strip()
            if FLAG_RE.search(x):
                flag_like.append(x[:240])
            elif BASE64_RE.match(x):
                encoded_like.append({"kind": "base64_like", "value": x[:240]})
            elif HEX_RE.match(x):
                encoded_like.append({"kind": "hex_like", "value": x[:240]})

        payload = {
            "sample_path": str(sample_path),
            "sha256": profile.sha256,
            "file_type": profile.file_type,
            "architecture": profile.architecture,
            "tags": profile.tags[:30],
            "imports": profile.imports[:80],
            "strings_summary": {
                "total": len(strings),
                "flag_like": flag_like[:20],
                "encoded_like": encoded_like[:30],
                "success_strings": profile.success_strings[:20],
                "failure_strings": profile.failure_strings[:20],
                "interesting": _interesting_strings(strings)[:80],
            },
            "suggested_next_tools": _suggest_next_tools(
                flag_like=flag_like,
                encoded_like=encoded_like,
                success_strings=profile.success_strings,
                failure_strings=profile.failure_strings,
                skip_ghidra=skip_ghidra,
            ),
        }

        artifact = store.write_json("profile.json", payload)

        compact = {
            "sha256": payload["sha256"],
            "file_type": payload["file_type"],
            "architecture": payload["architecture"],
            "tags": payload["tags"],
            "strings_summary": payload["strings_summary"],
            "suggested_next_tools": payload["suggested_next_tools"],
        }

        return {
            "summary": (
                f"profile_sample completed: {len(strings)} strings, "
                f"{len(flag_like)} flag-like, {len(encoded_like)} encoded-like"
            ),
            "data": compact,
            "artifacts": [artifact],
        }

    return ToolSpec(
        name="profile_sample",
        description="Analyze binary and return compact CTF profile.",
        input_schema={
            "type": "object",
            "properties": {
                "sample_path": {"type": "string"},
                "skip_ghidra": {"type": "boolean", "default": True},
            },
            "required": ["sample_path"],
            "additionalProperties": False,
        },
        handler=handler,
    )


def _validate_candidate_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        sample_path = Path(args["sample_path"]).resolve()
        candidate = str(args["candidate"])
        timeout = int(args.get("timeout", 10))

        validator = FlagValidator(timeout=timeout)
        result = validator.validate(
            sample_path=sample_path,
            candidate=candidate,
            output_dir=store.root,
        )

        agent_artifact = store.write_json(
            "agent_validate_result.json",
            {
                "accepted": result.accepted,
                "candidate": result.candidate,
                "mode": result.mode,
                "exit_code": result.exit_code,
                "matched_success": result.matched_success,
                "matched_failure": result.matched_failure,
                "stdout_tail": result.stdout[-1000:],
                "stderr_tail": result.stderr[-1000:],
                "evidence": result.evidence,
            },
        )

        return {
            "summary": (
                f"candidate {'accepted' if result.accepted else 'rejected'} "
                f"using mode={result.mode}"
            ),
            "data": {
                "accepted": result.accepted,
                "candidate": result.candidate,
                "mode": result.mode,
                "exit_code": result.exit_code,
                "matched_success": result.matched_success,
                "matched_failure": result.matched_failure,
                "stdout_tail": result.stdout[-1000:],
                "stderr_tail": result.stderr[-1000:],
                "evidence": result.evidence,
                "final_verdict": "solved" if result.accepted else "not_solved",
            },
            "artifacts": [
                agent_artifact,
                "validation_result.json",
                "validation_results.jsonl",
            ],
        }

    return ToolSpec(
        name="validate_candidate",
        description="Validate a candidate flag/input by running the binary in Docker sandbox.",
        input_schema={
            "type": "object",
            "properties": {
                "sample_path": {"type": "string"},
                "candidate": {"type": "string"},
                "timeout": {"type": "integer", "default": 10},
            },
            "required": ["sample_path", "candidate"],
            "additionalProperties": False,
        },
        handler=handler,
    )


def _decompile_function_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        function = str(args.get("function", "main"))
        max_lines = int(args.get("max_lines", 80))

        candidates = _find_decompile_artifacts(store.root)
        if not candidates:
            return {
                "summary": "No decompile artifacts found.",
                "data": {
                    "found": False,
                    "reason": "missing_decompile_artifacts",
                    "suggested_next_tool": {
                        "tool": "profile_sample",
                        "arguments": {"skip_ghidra": False},
                    },
                },
                "artifacts": [],
            }

        best = _pick_decompile_artifact(candidates, function)
        if best is None:
            return {
                "summary": f"No decompile artifact matched function={function!r}.",
                "data": {
                    "found": False,
                    "available_artifacts": [
                        str(p.relative_to(store.root)) for p in candidates[:20]
                    ],
                },
                "artifacts": [],
            }

        excerpt = _read_excerpt(best, function=function, max_lines=max_lines)
        rel = str(best.relative_to(store.root))
        excerpt_artifact = store.write_text(
            f"decompile_excerpts/{_safe_name(function)}.txt",
            excerpt["text"],
        )

        return {
            "summary": f"Returned decompile excerpt for {function!r} from {rel}",
            "data": {
                "found": True,
                "function": function,
                "source_artifact": rel,
                "start_line": excerpt["start_line"],
                "end_line": excerpt["end_line"],
                "total_lines": excerpt["total_lines"],
                "excerpt": excerpt["text"],
            },
            "artifacts": [excerpt_artifact],
        }

    return ToolSpec(
        name="decompile_function",
        description="Read a bounded decompile excerpt from existing artifacts.",
        input_schema={
            "type": "object",
            "properties": {
                "function": {"type": "string", "default": "main"},
                "max_lines": {"type": "integer", "default": 80},
            },
            "required": ["function"],
            "additionalProperties": False,
        },
        handler=handler,
    )
