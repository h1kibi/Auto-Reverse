"""
BrainAction models - LLM outputs only structured actions, never free text decisions.

GPT requirement:
- LLM 不能宣布 solved
- LLM 不能运行 shell
- LLM 不能绕过 sandbox
- 只有 validator accepted 才 solved
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Literal

ActionKind = Literal[
    "run_tool",
    "run_solver",
    "extract_constraints",
    "propose_candidate",
    "request_context",
    "stop",
]

RiskLevel = Literal[
    "read_only",
    "executes_sample",
    "mutates_binary",
]


class BrainAction(BaseModel):
    id: str | None = None
    kind: ActionKind
    name: str | None = None
    params: dict = Field(default_factory=dict)
    rationale: str
    expected_observation: str | None = None
    risk: RiskLevel = "read_only"
    requires_validation: bool = True


class BrainResult(BaseModel):
    actions: list[BrainAction] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    stop_reason: str | None = None
