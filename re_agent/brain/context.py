"""
BrainContext - token-budgeted context sent to LLM.

GPT requirement: LLM 只看压缩证据，不看完备 artifact。
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class MemoryTacticCard(BaseModel):
    """Compressed memory card - NOT full playbook text."""
    id: str
    title: str = ""
    source_type: str = "user"
    priority: int = 50
    why_relevant: str = ""
    signals: list[str] = Field(default_factory=list)
    recommended_strategy: list[str] = Field(default_factory=list)
    tool_sequence: list[dict] = Field(default_factory=list)
    pitfalls: list[str] = Field(default_factory=list)


class BrainContext(BaseModel):
    run_id: str = ""
    goal: str = "solve CTF reverse challenge"

    profile: dict = Field(default_factory=dict)
    evidence_summary: dict = Field(default_factory=dict)

    memory_hits: list[dict] = Field(default_factory=list)
    context_bundles: list[dict] = Field(default_factory=list)

    previous_actions: list[dict] = Field(default_factory=list)
    previous_observations: list[dict] = Field(default_factory=list)

    failed_solvers: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_solvers: list[str] = Field(default_factory=list)

    budget_seconds_remaining: int = 300
    token_budget: int = 4096
    estimated_tokens: int = 0
    truncation_notes: list[str] = Field(default_factory=list)
