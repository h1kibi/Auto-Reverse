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

    def safe_path(self, relative: str) -> Path:
        """Return a path inside artifact root, rejecting traversal/absolute paths."""
        if not isinstance(relative, str) or not relative.strip():
            raise ValueError("artifact path must be a non-empty string")

        rel = Path(relative)

        if rel.is_absolute():
            raise ValueError("artifact path must be relative")

        if any(part in {"..", ""} for part in rel.parts):
            raise ValueError("artifact path must not contain '..' or empty path parts")

        resolved_root = self.root.resolve()
        resolved_path = (resolved_root / rel).resolve()

        try:
            resolved_path.relative_to(resolved_root)
        except ValueError as e:
            raise ValueError("artifact path escapes artifact root") from e

        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        return resolved_path

    def write_json(self, relative: str, payload: JsonDict) -> str:
        p = self.path(relative)
        p.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return str(p.relative_to(self.root))

    def write_json_safe(self, relative: str, payload: JsonDict) -> str:
        p = self.safe_path(relative)
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

    def write_text_safe(self, relative: str, text: str) -> str:
        p = self.safe_path(relative)
        p.write_text(text, encoding="utf-8")
        return str(p.relative_to(self.root))

    def read_text_range_safe(
        self,
        relative: str,
        start_line: int = 1,
        max_lines: int = 120,
        max_chars: int = 12000,
    ) -> JsonDict:
        p = self.safe_path(relative)

        if not p.exists():
            raise FileNotFoundError(f"artifact not found: {relative}")

        if not p.is_file():
            raise ValueError(f"artifact is not a file: {relative}")

        text = p.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()

        start = max(1, int(start_line))
        max_lines = max(1, min(int(max_lines), 500))

        end = min(len(lines), start + max_lines - 1)
        chunk = "\n".join(lines[start - 1:end])

        if len(chunk) > max_chars:
            chunk = chunk[:max_chars]
            truncated_by_chars = True
        else:
            truncated_by_chars = False

        return {
            "path": str(Path(relative)),
            "start_line": start,
            "end_line": end,
            "total_lines": len(lines),
            "truncated_by_chars": truncated_by_chars,
            "text": chunk,
        }


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
    registry.register(_decode_strings_tool(store))
    registry.register(_rank_functions_tool(store))
    registry.register(_run_angr_stdout_tool(store))
    registry.register(_run_z3_tool(store))
    registry.register(_write_artifact_tool(store))
    registry.register(_read_artifact_range_tool(store))
    registry.register(_list_artifacts_tool(store))
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


def _decode_strings_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        from .models import ChallengeProfile
        from .solvers.base import SolverContext
        from .solvers.encoding import EncodingSolver

        profile_path = store.path("profile.json")
        if not profile_path.exists():
            return {
                "summary": "profile.json not found. Run profile_sample first.",
                "data": {
                    "found": False,
                    "reason": "missing_profile",
                    "suggested_next_tool": {"tool": "profile_sample"},
                },
                "artifacts": [],
            }

        profile_payload = json.loads(
            profile_path.read_text(encoding="utf-8", errors="replace")
        )

        sample_path = Path(
            args.get("sample_path")
            or profile_payload.get("sample_path")
            or ""
        ).resolve()

        flag_regex = args.get(
            "flag_regex",
            r"(?:flag|ctf|picoCTF|hgame|nssctf|h1kibi)\{[^}\r\n]{1,160}\}",
        )

        strings_summary = profile_payload.get("strings_summary", {})
        strings: list[str] = []

        for item in strings_summary.get("flag_like", []):
            if isinstance(item, str):
                strings.append(item)

        for item in strings_summary.get("interesting", []):
            if isinstance(item, str):
                strings.append(item)

        for item in strings_summary.get("encoded_like", []):
            if isinstance(item, dict):
                value = item.get("value")
                if value:
                    strings.append(str(value))
            elif isinstance(item, str):
                strings.append(item)

        strings.extend(_load_strings_from_analysis(store.root))
        strings = _dedup_strings(strings)

        if not strings:
            return {
                "summary": "No strings available for decoding.",
                "data": {
                    "found": False,
                    "reason": "empty_strings",
                    "suggested_next_tool": {"tool": "profile_sample"},
                },
                "artifacts": [],
            }

        profile = ChallengeProfile(
            sample_path=sample_path,
            sha256=profile_payload.get("sha256", ""),
            file_type=profile_payload.get("file_type", ""),
            architecture=profile_payload.get("architecture", ""),
            strings=strings,
            imports=profile_payload.get("imports", []),
            success_strings=strings_summary.get("success_strings", []),
            failure_strings=strings_summary.get("failure_strings", []),
            tags=profile_payload.get("tags", []),
        )

        ctx = SolverContext(
            profile=profile,
            output_dir=store.root,
            flag_regex=flag_regex,
            timeout=int(args.get("timeout", 30)),
        )

        solver = EncodingSolver()
        candidates = solver.solve(ctx)

        candidate_payload = [
            {
                "value": c.value,
                "source": c.source,
                "confidence": c.confidence,
                "evidence": c.evidence[:3],
            }
            for c in candidates[:20]
        ]

        artifact = store.write_json(
            "decode_strings_result.json",
            {
                "candidate_count": len(candidate_payload),
                "candidates": candidate_payload,
                "strings_checked": len(strings),
            },
        )

        return {
            "summary": (
                f"decode_strings found {len(candidate_payload)} candidate(s) "
                f"from {len(strings)} strings"
            ),
            "data": {
                "found": bool(candidate_payload),
                "candidate_count": len(candidate_payload),
                "candidates": candidate_payload,
                "next_step": (
                    "validate_candidate"
                    if candidate_payload
                    else "decompile_function or rank_functions"
                ),
            },
            "artifacts": [artifact],
        }

    return ToolSpec(
        name="decode_strings",
        description=(
            "Decode strings using raw/base64/hex/rot13/reverse/single-byte xor "
            "and return flag-like candidates."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "sample_path": {"type": "string"},
                "flag_regex": {
                    "type": "string",
                    "default": r"(?:flag|ctf)\{[^}\r\n]{1,160}\}",
                },
                "timeout": {"type": "integer", "default": 30},
            },
            "required": [],
            "additionalProperties": False,
        },
        handler=handler,
    )


def _rank_functions_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        max_functions = int(args.get("max_functions", 10))

        artifacts = _find_decompile_artifacts(store.root)
        if not artifacts:
            return {
                "summary": "No function/decompile artifacts found.",
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

        ranked: list[dict[str, Any]] = []

        for path in artifacts[:50]:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")[:1_000_000]
            except Exception:
                continue

            ranked.extend(_rank_functions_from_text(path, text))

        ranked = sorted(ranked, key=lambda x: x["score"], reverse=True)
        ranked = ranked[:max_functions]

        artifact = store.write_json(
            "rank_functions_result.json",
            {
                "functions": ranked,
                "artifact_count": len(artifacts),
            },
        )

        return {
            "summary": f"rank_functions returned {len(ranked)} suspicious function(s)",
            "data": {
                "found": bool(ranked),
                "functions": ranked,
                "next_step": (
                    "decompile_function"
                    if ranked
                    else "profile_sample(skip_ghidra=false)"
                ),
            },
            "artifacts": [artifact],
        }

    return ToolSpec(
        name="rank_functions",
        description=(
            "Rank suspicious functions from existing decompile/function artifacts. "
            "Use before decompile_function when no obvious flag candidate exists."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "max_functions": {
                    "type": "integer",
                    "default": 10,
                    "minimum": 1,
                    "maximum": 30,
                },
            },
            "required": [],
            "additionalProperties": False,
        },
        handler=handler,
    )


# ========== 新增辅助函数 ==========

def _load_strings_from_analysis(root: Path) -> list[str]:
    """尽力从 analysis artifacts 中读取完整 strings"""
    out: list[str] = []

    patterns = [
        "analysis/**/*strings*.json",
        "analysis/**/*strings*.txt",
        "analysis/**/strings",
        "**/*strings*.json",
        "**/*strings*.txt",
    ]

    for pat in patterns:
        for path in root.glob(pat):
            if not path.is_file():
                continue

            try:
                if path.suffix.lower() == ".json":
                    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                    out.extend(_extract_strings_from_json(data))
                else:
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                    out.extend(x.strip() for x in lines if x.strip())
            except Exception:
                continue

    return out[:5000]


def _extract_strings_from_json(data: Any) -> list[str]:
    out: list[str] = []

    if isinstance(data, str):
        return [data]

    if isinstance(data, list):
        for item in data:
            out.extend(_extract_strings_from_json(item))
        return out

    if isinstance(data, dict):
        for key in ("string", "value", "text", "name"):
            value = data.get(key)
            if isinstance(value, str):
                out.append(value)

        for value in data.values():
            if isinstance(value, (dict, list)):
                out.extend(_extract_strings_from_json(value))

    return out


def _dedup_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    for item in items:
        x = item.strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)

    return out


def _rank_functions_from_text(path: Path, text: str) -> list[dict[str, Any]]:
    """从文本 artifact 中粗略提取/打分函数"""
    blocks = _split_function_blocks(text)
    if not blocks:
        blocks = [("unknown", text[:12000], 1)]

    out: list[dict[str, Any]] = []

    for name, block, start_line in blocks:
        score, reasons = _score_function_block(name, block)
        if score <= 0:
            continue

        out.append(
            {
                "name": name,
                "score": round(score, 3),
                "reasons": reasons,
                "source_artifact": str(path.name),
                "start_line": start_line,
                "excerpt": _compact_code_excerpt(block, max_lines=30),
            }
        )

    return out


def _split_function_blocks(text: str) -> list[tuple[str, str, int]]:
    lines = text.splitlines()
    starts: list[tuple[str, int]] = []

    func_re = re.compile(
        r"^\s*(?:[A-Za-z_][\w\s\*\(\)]*\s+)?"
        r"([A-Za-z_][\w$@.]*)\s*\([^;]*\)\s*\{?\s*$"
    )

    for i, line in enumerate(lines):
        m = func_re.match(line)
        if not m:
            continue

        name = m.group(1)
        if name in {"if", "while", "for", "switch"}:
            continue

        starts.append((name, i))

    blocks: list[tuple[str, str, int]] = []

    for idx, (name, start) in enumerate(starts):
        end = starts[idx + 1][1] if idx + 1 < len(starts) else min(len(lines), start + 160)
        block = "\n".join(lines[start:end])
        blocks.append((name, block, start + 1))

    return blocks[:100]


def _score_function_block(name: str, block: str) -> tuple[float, list[str]]:
    low_name = name.lower()
    low = block.lower()

    score = 0.0
    reasons: list[str] = []

    name_keywords = ["check", "verify", "validate", "auth", "flag", "password"]
    if any(k in low_name for k in name_keywords):
        score += 0.25
        reasons.append("suspicious function name")

    success_keywords = ["correct", "success", "congrat", "accepted", "you win"]
    failure_keywords = ["wrong", "fail", "invalid", "try again", "nope"]

    if any(k in low for k in success_keywords):
        score += 0.25
        reasons.append("references success-like output")

    if any(k in low for k in failure_keywords):
        score += 0.15
        reasons.append("references failure-like output")

    input_keywords = ["scanf", "fgets", "read(", "gets(", "argv", "stdin"]
    if any(k in low for k in input_keywords):
        score += 0.15
        reasons.append("handles user input")

    compare_keywords = ["strcmp", "strncmp", "memcmp", "strlen"]
    if any(k in low for k in compare_keywords):
        score += 0.20
        reasons.append("uses string length/compare API")

    bit_ops = [" ^ ", " xor ", "<<", ">>", " & ", " | "]
    if any(k in low for k in bit_ops):
        score += 0.15
        reasons.append("contains bitwise operations")

    constants = re.findall(r"0x[0-9a-fA-F]{2,}", block)
    if len(constants) >= 5:
        score += 0.10
        reasons.append("contains many constants")

    return min(score, 1.0), reasons


def _compact_code_excerpt(block: str, max_lines: int = 30) -> str:
    lines = block.splitlines()
    interesting = []

    keywords = [
        "correct", "wrong", "success", "fail", "invalid",
        "strcmp", "strncmp", "memcmp", "strlen",
        "scanf", "fgets", "read", "argv",
        "^", "<<", ">>",
    ]

    for i, line in enumerate(lines):
        low = line.lower()
        if any(k in low for k in keywords):
            start = max(0, i - 2)
            end = min(len(lines), i + 3)
            interesting.extend(lines[start:end])

    if not interesting:
        interesting = lines[:max_lines]

    return "\n".join(_dedup_strings(interesting)[:max_lines])


# ========== run_angr_stdout 工具 ==========

def _run_angr_stdout_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        sample_path = Path(args["sample_path"]).resolve()
        input_modes = args.get("input_modes", ["argv", "stdin"])
        lengths = args.get("lengths", [8, 12, 16, 24, 32, 40, 48, 64])
        timeout = int(args.get("timeout", 60))
        max_candidates = int(args.get("max_candidates", 5))

        success_needles = args.get(
            "success_needles",
            ["correct", "success", "accepted", "congrat", "you win", "well done"],
        )
        failure_needles = args.get(
            "failure_needles",
            ["wrong", "incorrect", "fail", "invalid", "try again", "nope"],
        )

        flag_regex = args.get(
            "flag_regex",
            r"(?:flag|ctf|picoCTF|hgame|nssctf|h1kibi)\{[^}\r\n]{1,160}\}",
        )

        try:
            import angr
            import claripy
        except ImportError:
            return {
                "summary": "angr or claripy is not installed. Install with: pip install -e '.[ctf]'",
                "data": {
                    "found": False,
                    "reason": "missing_angr",
                    "install_hint": "pip install -e '.[ctf]'",
                },
                "artifacts": [],
            }

        project = angr.Project(str(sample_path), auto_load_libs=False)

        success_bytes = _to_needles(success_needles)
        failure_bytes = _to_needles(failure_needles)
        regex = re.compile(flag_regex, re.IGNORECASE)

        candidates: list[dict[str, Any]] = []
        attempts: list[dict[str, Any]] = []

        for mode in input_modes:
            if mode not in {"argv", "stdin"}:
                attempts.append({
                    "mode": mode,
                    "status": "skipped",
                    "reason": "unsupported input mode",
                })
                continue

            for length in lengths:
                if len(candidates) >= max_candidates:
                    break

                result = _angr_try_stdout_path(
                    project=project,
                    sample_path=sample_path,
                    mode=mode,
                    length=int(length),
                    timeout=timeout,
                    success_needles=success_bytes,
                    failure_needles=failure_bytes,
                    regex=regex,
                )

                attempts.append(result["attempt"])

                for c in result["candidates"]:
                    if not any(x["value"] == c["value"] for x in candidates):
                        candidates.append(c)

            if len(candidates) >= max_candidates:
                break

        payload = {
            "found": bool(candidates),
            "candidate_count": len(candidates),
            "candidates": candidates[:max_candidates],
            "attempts": attempts,
            "config": {
                "input_modes": input_modes,
                "lengths": lengths,
                "timeout": timeout,
                "success_needles": success_needles,
                "failure_needles": failure_needles,
            },
        }

        artifact = store.write_json("run_angr_stdout_result.json", payload)

        return {
            "summary": (
                f"run_angr_stdout found {len(candidates)} candidate(s) "
                f"after {len(attempts)} attempt(s)"
            ),
            "data": {
                "found": bool(candidates),
                "candidate_count": len(candidates),
                "candidates": candidates[:max_candidates],
                "next_step": "validate_candidate" if candidates else "decompile_function or rank_functions",
            },
            "artifacts": [artifact],
        }

    return ToolSpec(
        name="run_angr_stdout",
        description=(
            "Use angr symbolic execution and stdout/stderr success predicates "
            "to find argv/stdin inputs reaching success output."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "sample_path": {"type": "string"},
                "input_modes": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["argv", "stdin"]},
                    "default": ["argv", "stdin"],
                },
                "lengths": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "default": [8, 12, 16, 24, 32, 40, 48, 64],
                },
                "timeout": {"type": "integer", "default": 60},
                "max_candidates": {"type": "integer", "default": 5},
                "success_needles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["correct", "success", "accepted", "congrat"],
                },
                "failure_needles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["wrong", "incorrect", "fail", "invalid"],
                },
                "flag_regex": {
                    "type": "string",
                    "default": r"(?:flag|ctf)\{[^}\r\n]{1,160}\}",
                },
            },
            "required": ["sample_path"],
            "additionalProperties": False,
        },
        handler=handler,
    )


def _angr_try_stdout_path(
    project,
    sample_path: Path,
    mode: str,
    length: int,
    timeout: int,
    success_needles: list[bytes],
    failure_needles: list[bytes],
    regex: re.Pattern,
) -> dict[str, Any]:
    import angr
    import claripy

    sym = claripy.BVS(f"input_{mode}_{length}", length * 8)

    add_options = {
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    }

    try:
        if mode == "argv":
            state = project.factory.full_init_state(
                args=[str(sample_path), sym],
                add_options=add_options,
            )
        elif mode == "stdin":
            stdin = claripy.Concat(sym, claripy.BVV(b"\n"))
            state = project.factory.full_init_state(
                args=[str(sample_path)],
                stdin=stdin,
                add_options=add_options,
            )
        else:
            return {
                "attempt": {"mode": mode, "length": length, "status": "skipped", "reason": "unsupported mode"},
                "candidates": [],
            }

        for b in sym.chop(8):
            state.solver.add(b >= 0x20)
            state.solver.add(b <= 0x7E)

        simgr = project.factory.simulation_manager(state)

        def is_success(s) -> bool:
            out = _angr_state_output(s)
            return any(n in out for n in success_needles)

        def is_failure(s) -> bool:
            out = _angr_state_output(s)
            return any(n in out for n in failure_needles)

        simgr.explore(find=is_success, avoid=is_failure, num_find=3, timeout=timeout)

        candidates: list[dict[str, Any]] = []

        for found in simgr.found[:3]:
            try:
                raw = found.solver.eval(sym, cast_to=bytes)
            except Exception:
                continue

            text = raw.split(b"\x00")[0].decode("utf-8", errors="replace").strip()
            if not text:
                continue

            match = regex.search(text)
            value = match.group(0) if match else text

            stdout_tail = found.posix.dumps(1).decode("utf-8", errors="replace")[-500:]
            stderr_tail = found.posix.dumps(2).decode("utf-8", errors="replace")[-500:]

            candidates.append({
                "value": value,
                "mode": mode,
                "length": length,
                "confidence": 0.88 if match else 0.70,
                "evidence": [
                    "angr reached stdout/stderr success predicate",
                    f"mode={mode}",
                    f"length={length}",
                ],
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
            })

        return {
            "attempt": {
                "mode": mode,
                "length": length,
                "status": "found" if candidates else "not_found",
                "found_count": len(candidates),
                "active": len(simgr.active),
                "deadended": len(simgr.deadended),
                "avoided": len(simgr.avoided),
            },
            "candidates": candidates,
        }

    except Exception as e:
        return {
            "attempt": {"mode": mode, "length": length, "status": "error", "error": repr(e)},
            "candidates": [],
        }


def _angr_state_output(state) -> bytes:
    try:
        stdout = state.posix.dumps(1)
    except Exception:
        stdout = b""

    try:
        stderr = state.posix.dumps(2)
    except Exception:
        stderr = b""

    return (stdout + b"\n" + stderr).lower()


def _to_needles(values: list[str]) -> list[bytes]:
    out: list[bytes] = []
    for value in values:
        b = str(value).lower().encode("utf-8", errors="ignore")
        if b:
            out.append(b)
    return out


# ========== run_z3 工具 ==========

def _run_z3_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        try:
            from .solvers.z3_constraints import solve_constraint_spec
        except Exception as e:
            return {
                "summary": f"failed to import Z3 solver: {e}",
                "data": {"found": False, "reason": "import_error", "error": str(e)},
                "artifacts": [],
            }

        try:
            import z3  # noqa: F401
        except ImportError:
            return {
                "summary": "z3-solver is not installed. Install with: pip install -e '.[ctf]'",
                "data": {"found": False, "reason": "missing_z3", "install_hint": "pip install -e '.[ctf]'"},
                "artifacts": [],
            }

        spec_result = _load_z3_constraints_spec(store, args)
        if not spec_result["ok"]:
            return {
                "summary": spec_result["summary"],
                "data": {"found": False, "reason": spec_result["reason"], "error": spec_result.get("error")},
                "artifacts": spec_result.get("artifacts", []),
            }

        spec = spec_result["spec"]

        validation_error = _validate_z3_spec_shape(spec)
        if validation_error:
            artifact = store.write_json("run_z3_result.json", {
                "found": False, "reason": "invalid_constraints",
                "error": validation_error, "constraints": spec,
            })
            return {
                "summary": f"invalid Z3 constraints: {validation_error}",
                "data": {"found": False, "reason": "invalid_constraints", "error": validation_error},
                "artifacts": [artifact],
            }

        constraints_artifact = store.write_json("constraints.json", spec)

        try:
            flag = solve_constraint_spec(spec)
        except Exception as e:
            result_artifact = store.write_json("run_z3_result.json", {
                "found": False, "reason": "solver_error", "error": repr(e),
                "constraints_artifact": constraints_artifact,
            })
            return {
                "summary": f"run_z3 failed: {e}",
                "data": {"found": False, "reason": "solver_error", "error": repr(e)},
                "artifacts": [constraints_artifact, result_artifact],
            }

        candidates: list[dict[str, Any]] = []
        if flag:
            candidates.append({
                "value": flag,
                "source": "run_z3",
                "confidence": 0.86,
                "evidence": [
                    "Z3 returned sat for provided constraints",
                    f"length={spec.get('length')}",
                    f"prefix={spec.get('prefix', '')!r}",
                    f"suffix={spec.get('suffix', '')!r}",
                ],
            })

        result_artifact = store.write_json("run_z3_result.json", {
            "found": bool(candidates),
            "candidate_count": len(candidates),
            "candidates": candidates,
            "constraints_artifact": constraints_artifact,
            "constraint_count": len(spec.get("constraints", [])),
        })

        return {
            "summary": f"run_z3 found {len(candidates)} candidate(s)",
            "data": {
                "found": bool(candidates),
                "candidate_count": len(candidates),
                "candidates": candidates,
                "next_step": "validate_candidate" if candidates else "decompile_function or revise constraints",
            },
            "artifacts": [constraints_artifact, result_artifact],
        }

    return ToolSpec(
        name="run_z3",
        description=(
            "Solve byte-level CTF flag constraints with Z3. "
            "Input must be a constraints JSON object or a path to a constraints artifact. "
            "Candidates must still be verified with validate_candidate."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "sample_path": {"type": "string"},
                "constraints": {"type": "object", "description": "Inline constraints spec."},
                "constraints_path": {"type": "string", "description": "Path to constraints JSON file."},
            },
            "required": [],
            "additionalProperties": False,
        },
        handler=handler,
    )


def _load_z3_constraints_spec(store: ArtifactStore, args: JsonDict) -> JsonDict:
    if "constraints" in args and args["constraints"]:
        spec = args["constraints"]
        if not isinstance(spec, dict):
            return {"ok": False, "summary": "constraints must be a JSON object", "reason": "bad_constraints_type"}
        return {"ok": True, "spec": spec, "summary": "loaded inline constraints", "artifacts": []}

    constraints_path = args.get("constraints_path")
    if constraints_path:
        p = Path(str(constraints_path))
        if not p.is_absolute():
            p = store.path(str(constraints_path))
        if not p.exists():
            return {"ok": False, "summary": f"constraints_path not found: {constraints_path}", "reason": "missing_constraints_path"}
        try:
            spec = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            return {"ok": False, "summary": f"failed to read constraints JSON: {e}", "reason": "bad_constraints_json", "error": str(e)}
        if not isinstance(spec, dict):
            return {"ok": False, "summary": "constraints JSON must be an object", "reason": "bad_constraints_type"}
        return {"ok": True, "spec": spec, "summary": f"loaded constraints from {constraints_path}", "artifacts": [str(constraints_path)]}

    default_path = store.path("constraints.json")
    if default_path.exists():
        try:
            spec = json.loads(default_path.read_text(encoding="utf-8", errors="replace"))
        except Exception as e:
            return {"ok": False, "summary": f"failed to read default constraints.json: {e}", "reason": "bad_constraints_json", "error": str(e)}
        return {"ok": True, "spec": spec, "summary": "loaded default constraints.json", "artifacts": ["constraints.json"]}

    return {"ok": False, "summary": "No constraints provided. Pass constraints or constraints_path.", "reason": "missing_constraints"}


def _validate_z3_spec_shape(spec: JsonDict) -> str | None:
    length = spec.get("length")
    if not isinstance(length, int):
        return "length must be an integer"
    if length <= 0 or length > 256:
        return "length must be between 1 and 256"

    prefix = spec.get("prefix", "")
    if prefix is not None and not isinstance(prefix, str):
        return "prefix must be a string"

    suffix = spec.get("suffix", "")
    if suffix is not None and not isinstance(suffix, str):
        return "suffix must be a string"

    constraints = spec.get("constraints", [])
    if not isinstance(constraints, list):
        return "constraints must be a list"

    for i, constraint in enumerate(constraints):
        if not isinstance(constraint, dict):
            return f"constraints[{i}] must be an object"
        if "left" not in constraint:
            return f"constraints[{i}] missing left"
        if "right" not in constraint:
            return f"constraints[{i}] missing right"
        op = constraint.get("op", "==")
        if op not in {"==", "!=", "<", "<=", ">", ">="}:
            return f"constraints[{i}] has unsupported op: {op}"

    if prefix and len(prefix) > length:
        return "prefix longer than length"
    if suffix and len(suffix) > length:
        return "suffix longer than length"
    if prefix and suffix and len(prefix) + len(suffix) > length:
        return "prefix + suffix longer than length"

    return None


# ========== write_artifact / read_artifact_range 工具 ==========

def _write_artifact_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        path = str(args["path"])
        content_type = str(args.get("content_type", "text"))
        overwrite = bool(args.get("overwrite", False))

        try:
            target = store.safe_path(path)
        except ValueError as e:
            return {
                "summary": f"invalid artifact path: {e}",
                "data": {"written": False, "reason": "invalid_path", "error": str(e)},
                "artifacts": [],
            }

        if target.exists() and not overwrite:
            return {
                "summary": f"artifact already exists: {path}",
                "data": {
                    "written": False,
                    "reason": "already_exists",
                    "path": path,
                    "hint": "set overwrite=true to replace it",
                },
                "artifacts": [path],
            }

        if content_type == "json":
            payload = args.get("json")
            if not isinstance(payload, dict):
                return {
                    "summary": "json content must be an object",
                    "data": {"written": False, "reason": "invalid_json_content"},
                    "artifacts": [],
                }
            rel = store.write_json_safe(path, payload)

        elif content_type == "text":
            text = args.get("text")
            if not isinstance(text, str):
                return {
                    "summary": "text content must be a string",
                    "data": {"written": False, "reason": "invalid_text_content"},
                    "artifacts": [],
                }
            rel = store.write_text_safe(path, text)

        else:
            return {
                "summary": f"unsupported content_type: {content_type}",
                "data": {
                    "written": False,
                    "reason": "unsupported_content_type",
                    "supported": ["json", "text"],
                },
                "artifacts": [],
            }

        return {
            "summary": f"wrote artifact: {rel}",
            "data": {
                "written": True,
                "path": rel,
                "content_type": content_type,
                "bytes": target.stat().st_size,
                "next_step": (
                    "run_z3 with constraints_path"
                    if rel.endswith(".json") and "constraint" in rel.lower()
                    else "read_artifact_range"
                ),
            },
            "artifacts": [rel],
        }

    return ToolSpec(
        name="write_artifact",
        description=(
            "Write a JSON or text artifact inside the current artifact store. "
            "Use this to save generated constraints, notes, or intermediate analysis. "
            "Paths must be relative and cannot escape the artifact directory."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative artifact path, e.g. constraints.generated.json",
                },
                "content_type": {
                    "type": "string",
                    "enum": ["json", "text"],
                    "default": "text",
                },
                "json": {
                    "type": "object",
                    "description": "JSON object to write when content_type=json",
                },
                "text": {
                    "type": "string",
                    "description": "Text content to write when content_type=text",
                },
                "overwrite": {
                    "type": "boolean",
                    "default": False,
                },
            },
            "required": ["path", "content_type"],
            "additionalProperties": False,
        },
        handler=handler,
    )


def _read_artifact_range_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        path = str(args["path"])
        start_line = int(args.get("start_line", 1))
        max_lines = int(args.get("max_lines", 120))
        max_chars = int(args.get("max_chars", 12000))

        try:
            payload = store.read_text_range_safe(
                path,
                start_line=start_line,
                max_lines=max_lines,
                max_chars=max_chars,
            )
        except Exception as e:
            return {
                "summary": f"failed to read artifact range: {e}",
                "data": {
                    "found": False,
                    "reason": "read_error",
                    "error": str(e),
                    "path": path,
                },
                "artifacts": [],
            }

        return {
            "summary": (
                f"read {payload['path']} lines "
                f"{payload['start_line']}-{payload['end_line']} "
                f"of {payload['total_lines']}"
            ),
            "data": {"found": True, **payload},
            "artifacts": [payload["path"]],
        }

    return ToolSpec(
        name="read_artifact_range",
        description=(
            "Read a bounded line range from a text artifact. "
            "Use this instead of loading full large files into the model context."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative artifact path to read.",
                },
                "start_line": {
                    "type": "integer",
                    "default": 1,
                    "minimum": 1,
                },
                "max_lines": {
                    "type": "integer",
                    "default": 120,
                    "minimum": 1,
                    "maximum": 500,
                },
                "max_chars": {
                    "type": "integer",
                    "default": 12000,
                    "minimum": 100,
                    "maximum": 50000,
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        handler=handler,
    )


# ========== list_artifacts 工具 ==========

def _list_artifacts_tool(store: ArtifactStore) -> ToolSpec:
    def handler(args: JsonDict) -> JsonDict:
        prefix = str(args.get("prefix", "") or "")
        max_files = int(args.get("max_files", 100))
        include_preview = bool(args.get("include_preview", False))
        preview_lines = int(args.get("preview_lines", 3))

        max_files = max(1, min(max_files, 500))
        preview_lines = max(1, min(preview_lines, 20))

        try:
            base = store.safe_path(prefix) if prefix else store.root
        except Exception as e:
            return {
                "summary": f"invalid artifact prefix: {e}",
                "data": {"found": False, "reason": "invalid_prefix", "error": str(e)},
                "artifacts": [],
            }

        if not base.exists():
            return {
                "summary": f"artifact prefix not found: {prefix}",
                "data": {"found": False, "reason": "prefix_not_found", "prefix": prefix},
                "artifacts": [],
            }

        files: list[dict[str, Any]] = []

        if base.is_file():
            candidates = [base]
        else:
            candidates = sorted(
                p for p in base.rglob("*")
                if p.is_file() and not _is_hidden_artifact_path(p, store.root)
            )

        for path in candidates[:max_files]:
            try:
                rel = str(path.relative_to(store.root))
            except ValueError:
                continue

            item: dict[str, Any] = {
                "path": rel,
                "size_bytes": path.stat().st_size,
                "kind": _artifact_kind(path),
                "suggested_tool": _suggest_artifact_tool(path),
            }

            if include_preview and _is_text_like_artifact(path):
                item["preview"] = _preview_artifact(path, preview_lines=preview_lines)

            files.append(item)

        summary = f"listed {len(files)} artifact(s)" if files else "no artifacts found"

        return {
            "summary": summary,
            "data": {
                "found": bool(files),
                "prefix": prefix,
                "count": len(files),
                "truncated": len(candidates) > max_files,
                "files": files,
                "next_step": "read_artifact_range for relevant text artifacts",
            },
            "artifacts": [x["path"] for x in files[:20]],
        }

    return ToolSpec(
        name="list_artifacts",
        description=(
            "List files inside the current artifact store. "
            "Use this to discover profile, solver results, decompile excerpts, "
            "constraints files, logs, and reports before reading a bounded range."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "prefix": {
                    "type": "string",
                    "default": "",
                    "description": "Optional relative directory or file prefix inside artifact store.",
                },
                "max_files": {
                    "type": "integer",
                    "default": 100,
                    "minimum": 1,
                    "maximum": 500,
                },
                "include_preview": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include short previews for text-like files.",
                },
                "preview_lines": {
                    "type": "integer",
                    "default": 3,
                    "minimum": 1,
                    "maximum": 20,
                },
            },
            "required": [],
            "additionalProperties": False,
        },
        handler=handler,
    )


def _is_hidden_artifact_path(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    return any(part.startswith(".") for part in rel.parts)


def _artifact_kind(path: Path) -> str:
    name = path.name.lower()
    suffix = path.suffix.lower()

    if name in {"profile.json", "solve_result.json", "validation_result.json"}:
        return "result_json"

    if name.endswith(".jsonl"):
        return "trace_jsonl"

    if "constraint" in name and suffix == ".json":
        return "constraints_json"

    if "decompile" in str(path).lower() or suffix in {".c", ".cpp", ".h"}:
        return "code_or_decompile"

    if suffix == ".json":
        return "json"

    if suffix in {".txt", ".md", ".log"}:
        return "text"

    if suffix in {".png", ".jpg", ".jpeg", ".webp"}:
        return "image"

    return "file"


def _suggest_artifact_tool(path: Path) -> str:
    kind = _artifact_kind(path)

    if kind == "constraints_json":
        return "run_z3 or read_artifact_range"

    if kind in {"json", "result_json", "trace_jsonl", "text", "code_or_decompile"}:
        return "read_artifact_range"

    return "none"


def _is_text_like_artifact(path: Path) -> bool:
    suffix = path.suffix.lower()
    name = path.name.lower()

    if name.endswith(".jsonl"):
        return True

    return suffix in {".txt", ".md", ".log", ".json", ".c", ".cpp", ".h", ".py", ".sh"}


def _preview_artifact(path: Path, preview_lines: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""

    text = "\n".join(lines[:preview_lines])
    return text[:2000]
