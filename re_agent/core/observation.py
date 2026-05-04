"""
RuntimeObservation - unified tool/solver output.

GPT requirement: summary + structured + artifacts + evidence_ids + candidates + risk.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Literal, Any


class RuntimeObservation(BaseModel):
    tool: str
    status: Literal["ok", "skipped", "error", "timeout"]
    summary: str

    structured: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    candidates: list[dict[str, Any]] = Field(default_factory=list)

    risk: Literal["read_only", "executes_sample", "mutates_binary"] = "read_only"
    elapsed_ms: int | None = None
    error: str | None = None


def normalize_tool_result(tool_name: str, raw: dict) -> RuntimeObservation:
    """Convert existing tool output dict to RuntimeObservation (no rewriting needed)."""
    return RuntimeObservation(
        tool=tool_name,
        status=raw.get("status", "ok"),
        summary=raw.get("summary", ""),
        structured=raw.get("structured", raw.get("data", {})),
        artifacts=raw.get("artifacts", []),
        evidence_ids=raw.get("evidence_ids", []),
        candidates=raw.get("candidates", []),
        risk=raw.get("risk", "read_only"),
        error=raw.get("error"),
    )
