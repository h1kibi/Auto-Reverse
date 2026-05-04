"""
PolicyGate - execution permission check before running BrainActions.

GPT requirement: LLM cannot freely request dangerous tools.
"""

from __future__ import annotations

from pydantic import BaseModel


class RuntimePolicy(BaseModel):
    allow_dynamic: bool = False
    allow_mutation: bool = False
    allow_raw_commands: bool = False
    max_steps: int = 5
    max_actions_per_step: int = 2


class PolicyGate:
    def __init__(self, policy: RuntimePolicy | None = None):
        self.policy = policy or RuntimePolicy()

    def allow(self, action) -> bool:
        risk = getattr(action, "risk", "read_only")
        if risk == "executes_sample" and not self.policy.allow_dynamic:
            return False
        if risk == "mutates_binary" and not self.policy.allow_mutation:
            return False
        if getattr(action, "kind", "") == "run_tool" and getattr(action, "name", "").startswith("raw_"):
            if not self.policy.allow_raw_commands:
                return False
        return True
