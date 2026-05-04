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
    allow_unpack: bool = True
    block_static_when_packed: bool = True
    test_mode_allow_unverified: bool = False
    max_steps: int = 5
    max_actions_per_step: int = 2
    max_retries_per_action: int = 1


class PolicyGate:
    def __init__(self, policy: RuntimePolicy | None = None):
        self.policy = policy or RuntimePolicy()

    def allow(self, action, state: dict | None = None) -> bool:
        risk = getattr(action, "risk", "read_only")
        if risk == "executes_sample" and not self.policy.allow_dynamic:
            return False
        if risk == "mutates_binary" and not self.policy.allow_mutation:
            return False
        name = getattr(action, "name", "")
        if name == "unpack_upx" and not self.policy.allow_unpack:
            return False
        # Packed binary: block static solvers
        if state and state.get("packer_profile", {}).get("is_packed"):
            if self.policy.block_static_when_packed and name in {"static_flag", "encoding"}:
                return False
        return True
