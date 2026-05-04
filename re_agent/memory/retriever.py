"""
Memory Retriever - Hybrid retrieval for CTF reverse strategies.

Strategy:
1. Tag exact match (fast, most reliable)
2. BM25 content search (for textual queries)
3. Signal overlap scoring (profile to playbook matching)
4. Rerank by evidence overlap
"""

import re
from typing import Any

from .schema import Playbook, SelfLesson
from .store import MemoryStore


class MemoryRetriever:
    """Hybrid retriever for playbooks and self-lessons"""

    def __init__(self, store: MemoryStore):
        self.store = store

    def retrieve_for_profile(self, profile_dict: dict, top_k: int = 5) -> list[dict]:
        """Retrieve relevant playbooks and lessons for a challenge profile"""
        results: list[dict] = []

        tags = profile_dict.get("tags", [])
        comparison_hints = profile_dict.get("comparison_hints", [])
        crypto_hints = profile_dict.get("crypto_hints", [])
        encoding_hints = profile_dict.get("encoding_hints", [])
        success_strings = profile_dict.get("success_strings", [])
        failure_strings = profile_dict.get("failure_strings", [])
        file_type = profile_dict.get("file_type", "")

        # Build query signal list
        query_signals = set()
        query_signals.update(comparison_hints)
        query_signals.update(crypto_hints)
        query_signals.update(encoding_hints)
        query_signals.update(tags)

        if success_strings:
            query_signals.add("has_success_string")
        if failure_strings:
            query_signals.add("has_failure_string")
        if comparison_hints:
            query_signals.add("has_comparison")

        # 1. Tag exact match
        tag_matches = self.store.search_playbooks_by_tag(list(query_signals), limit=top_k * 3)

        scored = []
        for pb in tag_matches:
            score = self._score_playbook_for_signals(pb, query_signals)
            if score > 0:
                scored.append((score, pb))

        # 2. Also search by content
        content_query = " ".join(list(query_signals)[:5])
        if content_query:
            content_matches = self.store.search_playbooks_by_content(content_query, limit=5)
            seen_ids = {pb.id for _, pb in scored}
            for pb in content_matches:
                if pb.id not in seen_ids:
                    score = self._score_playbook_for_signals(pb, query_signals) * 0.7
                    if score > 0:
                        scored.append((score, pb))

        # 3. Include recent self-lessons with similar signals
        recent = self.store.get_recent_lessons(limit=10)
        for lesson in recent:
            overlap = len(set(lesson.key_signals) & query_signals)
            if overlap >= 2:
                score = min(0.6, overlap * 0.2)
                scored.append((score, lesson))

        scored.sort(key=lambda x: x[0], reverse=True)

        for score, item in scored[:top_k]:
            entry = self._to_response(score, item)
            if entry:
                results.append(entry)

        return results

    def _score_playbook_for_signals(self, pb: Playbook, query_signals: set) -> float:
        pb_signals = set(s.lower() for s in pb.signals)
        pb_tags = set(s.lower() for s in pb.pattern_tags)

        signal_overlap = len(pb_signals & query_signals)
        tag_overlap = len(pb_tags & query_signals)

        score = 0.0
        score += signal_overlap * 0.25
        score += tag_overlap * 0.15
        score += pb.confidence * 0.1

        return min(score, 1.0)

    def _to_response(self, score: float, item: Any) -> dict | None:
        if isinstance(item, Playbook):
            return {
                "id": item.id,
                "type": "playbook",
                "title": item.title,
                "relevance_score": round(score, 3),
                "why_relevant": f"signals match: {', '.join(item.pattern_tags[:5])}",
                "steps": item.tactic_steps[:5],
                "pitfalls": item.pitfalls[:3],
                "tool_recipe": item.tool_recipe[:3],
            }
        elif isinstance(item, SelfLesson):
            return {
                "id": item.id,
                "type": "self_lesson",
                "relevance_score": round(score, 3),
                "why_relevant": f"similar challenge pattern: {item.generalized_pattern[:100]}",
                "steps": item.successful_recipe[:5],
                "pitfalls": item.should_avoid_next_time[:3],
                "tool_recipe": item.reusable_tool_calls[:3],
            }
        return None

    def search(self, query: str, limit: int = 10) -> list[dict]:
        """Simple text search across playbooks"""
        results = []
        pbs = self.store.search_playbooks_by_content(query, limit)
        for pb in pbs:
            results.append({
                "id": pb.id,
                "title": pb.title,
                "type": "playbook",
                "tags": pb.pattern_tags[:5],
                "tactic_steps": pb.tactic_steps[:3],
            })
        return results
