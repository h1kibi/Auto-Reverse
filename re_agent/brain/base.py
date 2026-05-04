"""
Brain protocol + schema repair + base classes.
"""

from __future__ import annotations

from typing import Protocol
from .context import BrainContext
from .actions import BrainResult


class Brain(Protocol):
    name: str

    def plan(self, ctx: BrainContext) -> BrainResult: ...


def parse_brain_result(raw: str) -> BrainResult:
    """Schema repair: try parse, fallback on failure."""
    try:
        return BrainResult.model_validate_json(raw)
    except Exception:
        return BrainResult(
            actions=[],
            stop_reason="invalid_brain_json",
            assumptions=[raw[:1000]],
        )
