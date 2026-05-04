"""
Strategy Planner for CTF reverse challenges.

Two planners:
1. DeterministicPlanner - rule-based plan from profile signals
2. LLMPlanner - supplements with LLM-generated plan (optional)
"""

from dataclasses import dataclass, field
from typing import Any

from .models import ChallengeProfile


@dataclass
class PlanStep:
    """A single step in the strategy plan"""
    id: str
    kind: str  # solver, tool, validator, memory
    name: str
    priority: int = 50
    budget_seconds: int = 30
    params: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    required_evidence: list[str] = field(default_factory=list)


@dataclass
class StrategyPlan:
    """Complete strategy plan"""
    goal: str = "Find and verify the CTF flag."
    steps: list[PlanStep] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    stop_conditions: list[str] = field(default_factory=lambda: ["verified_candidate_found"])


class DeterministicPlanner:
    """Rule-based planner that generates a plan from profile signals"""

    def build(self, profile: ChallengeProfile) -> StrategyPlan:
        steps: list[PlanStep] = []

        steps.append(PlanStep(
            id="static-flag",
            kind="solver",
            name="static_flag",
            priority=100,
            budget_seconds=5,
            rationale="Always check direct flag-like strings first.",
        ))

        if profile.encoding_hints or profile.has_encoded_strings:
            steps.append(PlanStep(
                id="decode",
                kind="solver",
                name="decoding",
                priority=90,
                budget_seconds=15,
                rationale="Encoded-looking strings were found.",
            ))

        if profile.has_success_string or profile.has_failure_string:
            steps.append(PlanStep(
                id="dynamic-trace",
                kind="solver",
                name="dynamic_trace",
                priority=80,
                budget_seconds=10,
                rationale="Success/failure strings suggest runtime comparison.",
            ))

        if profile.comparison_hints:
            steps.append(PlanStep(
                id="z3",
                kind="solver",
                name="z3_constraints",
                priority=70,
                budget_seconds=30,
                rationale="Comparison APIs found - may need constraint solving.",
            ))

        if profile.has_success_string:
            steps.append(PlanStep(
                id="angr",
                kind="solver",
                name="angr_path",
                priority=60,
                budget_seconds=60,
                rationale="Success strings with angr symbolic execution.",
            ))

        if profile.crypto_hints:
            steps.append(PlanStep(
                id="z3-extract",
                kind="solver",
                name="z3_extractor",
                priority=65,
                budget_seconds=30,
                rationale="Crypto hints detected - constraint extraction needed.",
            ))

        steps.sort(key=lambda s: s.priority, reverse=True)

        assumptions: list[str] = []
        if "argv" in profile.input_channels:
            assumptions.append("input via argv")
        if "stdin" in profile.input_channels:
            assumptions.append("input via stdin")

        return StrategyPlan(
            goal="Find and verify the CTF flag.",
            steps=steps,
            assumptions=assumptions,
            stop_conditions=["verified_candidate_found"],
        )


class LLMPlanner:
    """LLM-based planner for supplementary planning"""

    def __init__(self):
        self._client = None

    def build(
        self,
        profile: ChallengeProfile,
        memory_hits: list[dict] | None = None,
    ) -> StrategyPlan | None:
        try:
            from ..llm import LLMFactory
            import os

            api_key = os.getenv("MIMO_API_KEY") or os.getenv("OPENAI_API_KEY")
            if not api_key:
                return None

            if os.getenv("MIMO_API_KEY"):
                client = LLMFactory.create("mimo", api_key=api_key)
            else:
                client = LLMFactory.create("openai", api_key=api_key)

            import json
            from ..llm import ChatMessage

            prompt = _build_llm_plan_prompt(profile, memory_hits)
            resp = client.chat(
                [ChatMessage(role="user", content=prompt)],
                temperature=0.1,
                max_tokens=800,
            )

            data = json.loads(resp.content)
            if not isinstance(data, list):
                return None

            steps = []
            for item in data:
                solver = item.get("solver")
                if not solver:
                    continue
                steps.append(PlanStep(
                    id=f"llm-{solver}",
                    kind="solver",
                    name=solver,
                    priority=int(item.get("priority", 50)),
                    budget_seconds=int(item.get("budget_seconds", 30)),
                    params=item.get("params", {}),
                    rationale=item.get("rationale", ""),
                ))

            return StrategyPlan(
                goal="Find and verify the CTF flag.",
                steps=sorted(steps, key=lambda s: s.priority, reverse=True),
                assumptions=data[0].get("assumptions", []) if data else [],
            )

        except Exception:
            return None


class PlanMerger:
    """Merges deterministic and LLM plans"""

    def merge(
        self,
        base: StrategyPlan,
        llm_plan: StrategyPlan | None = None,
        max_total_seconds: int = 300,
    ) -> StrategyPlan:
        if llm_plan is None:
            return base

        seen_solvers = {s.name for s in base.steps}
        merged_steps = list(base.steps)

        for step in llm_plan.steps:
            if step.name not in seen_solvers:
                merged_steps.append(step)
                seen_solvers.add(step.name)

        total_budget = sum(s.budget_seconds for s in merged_steps)
        if total_budget > max_total_seconds:
            scale = max_total_seconds / total_budget
            for step in merged_steps:
                step.budget_seconds = max(5, int(step.budget_seconds * scale))

        merged_steps.sort(key=lambda s: s.priority, reverse=True)

        return StrategyPlan(
            goal=base.goal,
            steps=merged_steps,
            assumptions=list(set(base.assumptions + (llm_plan.assumptions or []))),
            stop_conditions=base.stop_conditions,
        )


def _build_llm_plan_prompt(profile: ChallengeProfile, memory_hits: list[dict] | None = None) -> str:
    memory_section = ""
    if memory_hits:
        hits_text = json.dumps(memory_hits[:3], ensure_ascii=False, indent=2)
        memory_section = f"\nMemory hints:\n{hits_text}\n"

    return f"""You are a CTF reverse strategy planner. Output JSON only.

Profile:
file_type={profile.file_type}
arch={profile.architecture}
tags={profile.tags}
input_channels={profile.input_channels}
comparison_hints={profile.comparison_hints}
crypto_hints={profile.crypto_hints}
encoding_hints={profile.encoding_hints}
protections={profile.protections}
solver_hints={profile.solver_hints}
success_strings={profile.success_strings[:5]}
failure_strings={profile.failure_strings[:5]}
{memory_section}
Available solvers: static_flag, decoding, dynamic_trace, z3_constraints, z3_extractor, angr_path

Output JSON array:
[{{
  "solver": "decoding",
  "priority": 90,
  "budget_seconds": 15,
  "rationale": "...",
  "params": {{}}
}}]

Only output valid solver names. Keep it short."""
