"""
Memory Decision Hints - memory-to-tool bias.

Let user playbooks directly boost/avoid tools in recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MemoryDecisionHint:
    source_id: str
    source_type: str = "memory"
    confidence: float = 0.5
    prefer_tools: list[str] = field(default_factory=list)
    avoid_tools: list[str] = field(default_factory=list)
    trigger_signals: list[str] = field(default_factory=list)
    first_action: str | None = None
    rationale: str = ""


def memory_hits_to_decision_hints(hits: list[dict]) -> list[dict]:
    hints = []
    for hit in hits:
        recipe = (hit.get("tool_recipe") or hit.get("successful_recipe")
                   or hit.get("reusable_tool_calls") or [])
        prefer = []
        for step in recipe:
            if isinstance(step, dict) and step.get("tool"):
                prefer.append(step["tool"])
            elif isinstance(step, str):
                prefer.append(step.split("(")[0].strip())
        hints.append({
            "source_id": hit.get("id", ""),
            "source_type": hit.get("type", "memory"),
            "confidence": float(hit.get("relevance_score", hit.get("score", 0.5))),
            "prefer_tools": prefer[:8],
            "avoid_tools": hit.get("avoid_tools", [])[:8],
            "trigger_signals": hit.get("matched_signals", [])[:12],
            "first_action": prefer[0] if prefer else None,
            "rationale": str(hit.get("why_relevant", ""))[:400],
        })
    return hints


def apply_memory_bias(recommendations, memory_hints):
    by_tool = {r["tool"]: dict(r) for r in recommendations if r.get("tool")}
    for hint in memory_hints:
        conf = max(0.0, min(float(hint.get("confidence", 0.5)), 1.0))
        for tool in hint.get("prefer_tools", []):
            rec = by_tool.setdefault(tool, {"tool": tool, "score": 0.0, "why": []})
            rec["score"] = float(rec.get("score", 0.0)) + 0.25 * conf
            rec.setdefault("why", []).append("memory_prefer")
        for tool in hint.get("avoid_tools", []):
            if tool in by_tool:
                by_tool[tool]["score"] = float(by_tool[tool].get("score", 0.0)) - 0.35 * conf
                by_tool[tool].setdefault("why", []).append("memory_avoid")
    return sorted(by_tool.values(), key=lambda x: x.get("score", 0.0), reverse=True)
