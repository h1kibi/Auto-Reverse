"""
Brain protocol + schema repair + base classes.
"""

from __future__ import annotations

from typing import Protocol
from .context import BrainContext
from .actions import BrainResult, BrainAction


class Brain(Protocol):
    name: str

    def plan(self, ctx: BrainContext) -> BrainResult: ...


def parse_brain_result(raw: str) -> BrainResult:
    """Schema repair: try multiple parse strategies."""
    import json

    # Strategy 1: Direct parse
    try:
        data = json.loads(raw)
        result = _normalize_brain_result(data)
        if result.actions:
            return result
    except (json.JSONDecodeError, Exception):
        pass

    # Strategy 1b: List of actions directly
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            result = _normalize_brain_result({"actions": data})
            if result.actions:
                return result
    except Exception:
        pass

    # Strategy 2: Try to recover actions from assumptions (MiMo pattern)
    try:
        data = json.loads(raw)
        assumptions = data.get("assumptions", []) if isinstance(data, dict) else []
        for assumption in assumptions:
            text = str(assumption).strip()
            for attempt in [text]:
                try:
                    inner = json.loads(attempt)
                    if isinstance(inner, dict) and inner.get("actions"):
                        result = _normalize_brain_result(inner)
                        if result.actions:
                            return result
                    if isinstance(inner, list):
                        result = _normalize_brain_result({"actions": inner})
                        if result.actions:
                            return result
                except Exception:
                    pass
    except Exception:
        pass

    # Strategy 2: Extract JSON from text (fenced or bare)
    import re
    m = re.search(r'\{[\s\S]*"actions"[\s\S]*\}', raw)
    if m:
        try:
            data = json.loads(m.group())
            return _normalize_brain_result(data)
        except Exception:
            pass

    # Strategy 3: actions wrapped in assumptions string
    try:
        # Some models put the full action JSON in assumptions
        data = json.loads(raw)
        assumptions = data.get("assumptions", [])
        if isinstance(assumptions, list) and len(assumptions) > 0:
            text = str(assumptions[0])
            # Try to extract actions from the assumption text
            inner = json.loads(text) if text.strip().startswith("{") else None
            if inner and "actions" in inner:
                return _normalize_brain_result(inner)
            elif inner:
                return BrainResult(
                    actions=[_normalize_action(a) for a in inner]
                    if isinstance(inner, list) else [],
                    stop_reason="recovered_from_assumptions",
                )
    except Exception:
        pass

    return BrainResult(
        actions=[],
        stop_reason="invalid_brain_json",
        assumptions=[raw[:1000]],
    )


def _normalize_brain_result(data: dict) -> BrainResult:
    """Normalize raw dict to BrainResult, fixing common LLM mistakes."""
    raw_actions = data.get("actions", [])
    if isinstance(raw_actions, str):
        import json
        try:
            raw_actions = json.loads(raw_actions)
        except Exception:
            raw_actions = []

    actions = [_normalize_action(a) for a in raw_actions if isinstance(a, dict)]

    # Accept list of actions directly (some models return just the array)
    if not actions and isinstance(data, list):
        actions = [_normalize_action(a) for a in data if isinstance(a, dict)]

    return BrainResult(
        actions=actions,
        assumptions=data.get("assumptions", []) if isinstance(data, dict) else [],
        stop_reason=data.get("stop_reason") if isinstance(data, dict) else None,
    )


def _normalize_action(a: dict) -> BrainAction:
    """Normalize a single action dict, fixing common LLM mistakes."""
    # Fix invalid risk values
    risk = a.get("risk", "read_only")
    valid_risks = {"read_only", "executes_sample", "mutates_binary"}
    if risk not in valid_risks:
        risk = "read_only" if risk in ("none", "safe") else "executes_sample"

    # Fix invalid created_from values
    created = a.get("created_from", "brain")
    if created not in ("brain", "memory", "policy"):
        created = "brain"

    return BrainAction(
        action_id=a.get("action_id") or a.get("id") or f"step_{a.get('name','unknown')}",
        kind=a.get("kind", "run_solver"),
        name=a.get("name"),
        params=a.get("params", {}),
        rationale=a.get("rationale", ""),
        expected_observation=a.get("expected_observation"),
        risk=risk,
        requires_validation=a.get("requires_validation", True),
        memory_refs=a.get("memory_refs", []) if isinstance(a.get("memory_refs"), list) else [],
        created_from=created,
    )
