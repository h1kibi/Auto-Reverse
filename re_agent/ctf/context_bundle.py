"""
FunctionContextBundle - low-token function evidence for LLM consumption.

Inspired by ReVa: small tools, critical fragments, xrefs, namespace.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from pathlib import Path


class EvidenceBrief(BaseModel):
    """Global binary summary (cheap for LLM round 1)."""

    file_type: str = ""
    arch: str = ""
    bits: int | None = None
    input_channels: list[str] = Field(default_factory=list)
    success_strings: list[str] = Field(default_factory=list)
    failure_strings: list[str] = Field(default_factory=list)
    comparison_hints: list[str] = Field(default_factory=list)
    encoding_hints: list[str] = Field(default_factory=list)
    crypto_hints: list[str] = Field(default_factory=list)
    solver_hints: list[str] = Field(default_factory=list)
    protections: list[str] = Field(default_factory=list)
    top_functions: list[str] = Field(default_factory=list)


class FunctionContextBundle(BaseModel):
    """Low-token evidence bundle for a single function."""

    function: str
    address: str = ""
    role_guess: str | None = None

    decompile_excerpt: str = ""
    disasm_excerpt: str = ""

    referenced_strings: list[str] = Field(default_factory=list)
    imports_used: list[str] = Field(default_factory=list)
    constants: list[str] = Field(default_factory=list)
    callers: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)
    xrefs: list[dict] = Field(default_factory=list)

    suspicious_patterns: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


def build_evidence_brief(profile) -> EvidenceBrief:
    """Build EvidenceBrief from ChallengeProfile."""
    return EvidenceBrief(
        file_type=getattr(profile, "file_type", ""),
        arch=getattr(profile, "architecture", ""),
        input_channels=getattr(profile, "input_channels", [])[:5],
        success_strings=getattr(profile, "success_strings", [])[:5],
        failure_strings=getattr(profile, "failure_strings", [])[:5],
        comparison_hints=getattr(profile, "comparison_hints", [])[:10],
        encoding_hints=getattr(profile, "encoding_hints", [])[:5],
        crypto_hints=getattr(profile, "crypto_hints", [])[:5],
        solver_hints=getattr(profile, "solver_hints", [])[:5],
        protections=getattr(profile, "protections", [])[:5],
    )


def build_context_bundle(
    function: str, profile, evidence, artifact_root: Path, max_excerpt_chars: int = 6000
) -> FunctionContextBundle:
    """Build a FunctionContextBundle from existing profiling/evidence data."""
    decomp = _find_decompile_excerpt(artifact_root, function, max_excerpt_chars)
    ref_strs, imports, constants, recommended = [], [], [], []

    if profile is not None:
        for s in getattr(profile, "success_strings", []) + getattr(profile, "failure_strings", []):
            if s and s in decomp:
                ref_strs.append(s)
        for s in getattr(profile, "strings", [])[:50]:
            if s and s in decomp:
                ref_strs.append(s)
                if len(ref_strs) >= 10:
                    break
        for imp in getattr(profile, "imports", []):
            if imp and imp.lower() in decomp.lower():
                imports.append(imp)
                if len(imports) >= 10:
                    break

    import re

    constants = list(set(re.findall(r"0x[0-9a-fA-F]{2,8}", decomp)))[:20]

    if profile is not None:
        if any(x in [i.lower() for i in imports] for x in ["strcmp", "strncmp", "memcmp"]):
            recommended.append("dynamic_trace")
        if any(op in decomp for op in ["^", "+", "-", "!=", "==", "strlen"]):
            recommended.append("z3_extractor")
        if getattr(profile, "success_strings", []) or getattr(profile, "failure_strings", []):
            recommended.append("angr_path")

    return FunctionContextBundle(
        function=function,
        decompile_excerpt=decomp[:max_excerpt_chars],
        referenced_strings=list(set(ref_strs))[:20],
        imports_used=list(set(imports))[:20],
        constants=constants,
        recommended_next_steps=list(set(recommended)),
    )


def _find_decompile_excerpt(root: Path, function: str, max_chars: int) -> str:
    """Search artifacts for a decompile excerpt matching the function name."""
    patterns = [
        "**/decompile_excerpts/*.txt",
        "**/ghidra/**/*.c",
        "**/*decomp*.txt",
        "**/*decomp*.c",
    ]
    for pat in patterns:
        for path in root.glob(pat):
            if not path.is_file():
                continue
            if function.lower() in path.name.lower():
                return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
        for path in root.glob(pat):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                if function.lower() in text.lower()[:50000]:
                    return text[:max_chars]
            except Exception:
                continue
    return ""
