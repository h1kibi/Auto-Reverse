"""
RuntimeObservation - unified tool/solver output.

GPT requirement: summary + structured + artifacts + evidence_ids + candidates + risk.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Literal, Any

from ..brain.context_builder import approx_tokens


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
    token_hint: int = 0

    def to_brain_view(self) -> dict:
        """Compressed view for BrainContext (plan v0.6.8)."""
        return {
            "tool": self.tool,
            "status": self.status,
            "summary": self.summary,
            "evidence_ids": self.evidence_ids[:10],
            "candidate_count": len(self.candidates),
            "risk": self.risk,
            "token_hint": self.token_hint,
        }


def normalize_tool_result(tool_name: str, raw: dict) -> RuntimeObservation:
    """Convert existing tool output dict to RuntimeObservation (no rewriting needed)."""
    status = raw.get("status")
    if not status:
        if raw.get("error") or raw.get("ok") is False:
            status = "error"
        elif raw.get("ok", True):
            status = "ok"
        else:
            status = "error"

    return RuntimeObservation(
        tool=tool_name,
        status=status,
        summary=raw.get("summary", ""),
        structured=raw.get("structured", raw.get("data", {})),
        artifacts=raw.get("artifacts", []),
        evidence_ids=raw.get("evidence_ids", []),
        candidates=raw.get("candidates", []),
        risk=raw.get("risk", "read_only"),
        elapsed_ms=raw.get("elapsed_ms"),
        error=raw.get("error"),
        token_hint=raw.get("token_hint", approx_tokens(raw.get("summary", ""))),
    )
