"""
Memory Schemas - Playbook and SelfLesson structured models.

Playbook: distilled tactical knowledge from community articles
SelfLesson: auto-generated reflection after solving a challenge
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


@dataclass
class Playbook:
    """Distilled tactical knowledge from community articles"""
    id: str = ""
    source_url: str = ""
    source_name: str = ""
    title: str = ""
    author: str | None = None
    published_at: str | None = None

    pattern_tags: list[str] = field(default_factory=list)
    target_type: list[str] = field(default_factory=list)
    difficulty: str | None = None

    signals: list[str] = field(default_factory=list)
    tactic_steps: list[str] = field(default_factory=list)
    tool_recipe: list[dict] = field(default_factory=list)
    code_templates: list[str] = field(default_factory=list)
    pitfalls: list[str] = field(default_factory=list)
    validation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    confidence: float = 0.8
    license_note: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class SelfLesson:
    """Auto-generated experience from a completed solve"""
    id: str = ""
    challenge_sha256: str = ""
    challenge_profile: dict = field(default_factory=dict)
    solved: bool = False
    verified: bool = False

    winning_solver: str | None = None
    input_channel: str | None = None
    key_signals: list[str] = field(default_factory=list)
    failed_attempts: list[str] = field(default_factory=list)
    successful_recipe: list[str] = field(default_factory=list)
    generalized_pattern: str = ""
    reusable_tool_calls: list[dict] = field(default_factory=list)
    should_try_earlier_next_time: list[str] = field(default_factory=list)
    should_avoid_next_time: list[str] = field(default_factory=list)

    artifacts: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence: float = 0.5


@dataclass
class MemoryEntry:
    """Generic memory entry for storage"""
    id: str = ""
    memory_type: Literal["playbook", "self_lesson"] = "playbook"
    tags: list[str] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    content: str = ""
    metadata: dict = field(default_factory=dict)
    embedding: list[float] | None = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    confidence: float = 0.5
