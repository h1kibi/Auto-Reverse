"""Stage 2 additions: XrefNode, ComparisonNode, FunctionContextBundle, snapshot."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class XrefNode:
    """Cross-reference between two addresses"""
    from_addr: int
    to_addr: int
    kind: str  # "data", "code", "call", "string_ref"
    evidence_artifact: str | None = None


@dataclass
class ComparisonNode:
    """A comparison operation detected in code"""
    id: str
    function: str
    kind: str  # "strcmp", "memcmp", "manual_loop", "cmp"
    left: str | None = None
    right: str | None = None
    length: int | None = None
    evidence: str = ""


@dataclass
class FunctionContextBundle:
    """Compressed context for LLM consumption (ReVa style)"""
    function: str
    address: int = 0
    decompile_excerpt: str = ""
    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    referenced_strings: list[str] = field(default_factory=list)
    imports_used: list[str] = field(default_factory=list)
    constants: list[str] = field(default_factory=list)
    suspicious_patterns: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)


CANONICAL_TAGS: dict[str, list[str]] = {
    "z3": ["z3", "z3-solver", "constraint", "constraints", "约束求解"],
    "angr": ["angr", "symbolic execution", "符号执行"],
    "dynamic_trace": ["ltrace", "frida", "gdb", "动态调试"],
    "encoding": ["base64", "hex", "rot", "xor", "编码"],
    "static_flag": ["strings", "flag", "plaintext"],
    "patcher": ["anti_debug", "anti-debug", "unpack", "脱壳"],
}

SENSITIVE_KEYS: set[str] = {
    "candidate", "flag", "value", "stdin", "password", "secret", "token",
}


def canonicalize_tag(tag: str) -> str:
    """Normalize tag to canonical form"""
    low = tag.lower()
    for canonical, variants in CANONICAL_TAGS.items():
        if low in variants or any(v in low for v in variants):
            return canonical
    return low


def redact_tool_args(obj: Any) -> Any:
    """Recursively redact sensitive values"""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k.lower() in SENSITIVE_KEYS:
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_tool_args(v)
        return out
    if isinstance(obj, list):
        return [redact_tool_args(x) for x in obj]
    return obj
