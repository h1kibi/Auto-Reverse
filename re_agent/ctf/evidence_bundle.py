"""
Evidence Bundle - compressed context for LLM consumption.

Evidence Loop goal: LLM sees compact evidence, not raw artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvidenceItem:
    id: str
    kind: str
    summary: str
    confidence: float = 0.5
    source_tool: str | None = None
    artifact: str | None = None
    line_range: tuple[int, int] | None = None
    token_cost_estimate: int = 0


@dataclass
class EvidenceBundle:
    sha256: str = ""
    profile: dict[str, Any] = field(default_factory=dict)
    signals: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    recommended_tools: list[dict[str, Any]] = field(default_factory=list)
    memory_hits: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    token_budget: int = 3000

    def compact(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "signals": self.signals[:30],
            "hypotheses": self.hypotheses[:8],
            "recommended_tools": self.recommended_tools[:8],
            "memory_hits": self.memory_hits[:5],
            "evidence": [
                {
                    "id": e.id, "kind": e.kind, "summary": e.summary,
                    "confidence": e.confidence, "source_tool": e.source_tool,
                }
                for e in self.evidence[:30]
            ],
        }


class EvidenceContextBuilder:
    def __init__(self, memory_retriever=None, token_budget: int = 3000):
        self.memory_retriever = memory_retriever
        self.token_budget = token_budget

    def build_from_profile(self, profile: dict) -> EvidenceBundle:
        signals = self._signals(profile)
        hypotheses = self._hypotheses(profile, signals)
        memory_hits = []
        if self.memory_retriever:
            try:
                memory_hits = self.memory_retriever.retrieve_for_profile(profile, top_k=5)
            except Exception:
                pass
        recommended_tools = self._recommend_tools(profile, signals, memory_hits)
        return EvidenceBundle(
            sha256=profile.get("sha256", ""),
            profile={
                "file_type": profile.get("file_type"),
                "architecture": profile.get("architecture"),
                "input_channels": profile.get("input_channels", []),
                "protections": profile.get("protections", []),
            },
            signals=signals, hypotheses=hypotheses,
            recommended_tools=recommended_tools, memory_hits=memory_hits,
            evidence=self._evidence_items(profile), token_budget=self.token_budget,
        )

    def _signals(self, profile):
        out = []
        for key in ["tags", "comparison_hints", "crypto_hints", "encoding_hints",
                      "protections", "solver_hints"]:
            out.extend(str(x).lower() for x in profile.get(key, []) if x)
        if profile.get("success_strings"): out.append("has_success_string")
        if profile.get("failure_strings"): out.append("has_failure_string")
        return sorted(set(out))

    def _hypotheses(self, profile, signals):
        h = []
        if "has_success_string" in signals or "has_failure_string" in signals:
            h.append("runtime_check_or_comparison")
        if profile.get("encoding_hints"): h.append("encoded_flag_or_key_material")
        if profile.get("crypto_hints"): h.append("crypto_transform_recovery")
        if "upx" in " ".join(signals): h.append("packed_binary_needs_unpack")
        if any("e_language" in s for s in signals): h.append("e_language_pattern")
        return h

    def _recommend_tools(self, profile, signals, memory_hits):
        tools = []
        if profile.get("encoding_hints"):
            tools.append({"tool": "decode_strings", "why": "encoded strings", "priority": 90})
        if "has_success_string" in signals or "has_failure_string" in signals:
            tools.append({"tool": "rank_functions", "why": "success/failure strings", "priority": 80})
        if any("e_language" in s for s in signals):
            tools.append({"tool": "detect_e_language", "why": "E-language signal", "priority": 75})
        if profile.get("protections") and any("packed" in str(p) for p in profile.get("protections", [])):
            tools.append({"tool": "detect_packer", "why": "packed binary", "priority": 100})
        return sorted(tools, key=lambda x: x["priority"], reverse=True)

    def _evidence_items(self, profile):
        items = []
        for i, s in enumerate(profile.get("success_strings", [])[:10]):
            items.append(EvidenceItem(id=f"str:success:{i}", kind="success_string",
                         summary=s[:160], confidence=0.8))
        for i, s in enumerate(profile.get("failure_strings", [])[:10]):
            items.append(EvidenceItem(id=f"str:failure:{i}", kind="failure_string",
                         summary=s[:160], confidence=0.8))
        return items
