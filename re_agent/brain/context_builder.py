"""
BrainContextBuilder - token-budgeted context assembly for LLM consumption.

GPT requirement: profile(300t) -> memory(800t) -> bundles(1500t) -> observations(700t) -> tools(300t).
"""

from __future__ import annotations

from .context import BrainContext
from .actions import BrainAction


def approx_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def pack_until_budget(sections: list[tuple[str, str, int]], budget: int) -> str:
    result = []
    used = 0
    for name, content, max_t in sections:
        if used >= budget:
            break
        truncated = content
        if approx_tokens(content) > max_t:
            lines = content.split("\n")
            while lines and approx_tokens("\n".join(lines)) > max_t:
                lines = lines[:-1]
            truncated = "\n".join(lines)
        result.append(f"## {name}\n{truncated}")
        used += approx_tokens(truncated)
    return "\n\n".join(result)


class BrainContextBuilder:
    def __init__(self, token_budget: int = 4096):
        self.token_budget = token_budget

    def build(self, state: dict, evidence_brief: dict,
              memory_hits: list[dict], context_bundles: list[dict],
              previous_observations: list[dict]) -> BrainContext:
        return BrainContext(
            run_id=state.get("run_id", ""),
            profile=evidence_brief,
            evidence_summary=evidence_brief,
            memory_hits=memory_hits[:5],
            context_bundles=context_bundles[:3],
            previous_actions=state.get("previous_actions", [])[-5:],
            previous_observations=previous_observations[-5:],
            failed_solvers=state.get("failed_solvers", [])[-5:],
            allowed_tools=["profile_sample", "validate_candidate",
                           "decompile_function", "decode_strings",
                           "rank_functions", "read_artifact_range", "list_artifacts"],
            allowed_solvers=["static_flag", "encoding", "dynamic_trace",
                             "z3_extractor", "z3_constraints", "angr_path",
                             "brute_force", "patcher"],
            budget_seconds_remaining=state.get("budget_seconds", 300),
            token_budget=self.token_budget,
        )
