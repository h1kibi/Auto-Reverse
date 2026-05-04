"""
ToolSpec and ToolBus protocol.

Unified interface for all analysis tools with risk levels, typed I/O, and timeouts.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolRisk(str, Enum):
    """Tool execution risk level"""
    READ_ONLY = "read_only"
    EXECUTES_SAMPLE = "executes_sample"
    MUTATES_BINARY = "mutates_binary"
    NETWORK = "network"
    SECRET_ACCESS = "secret_access"


@dataclass
class ToolSpec:
    """Tool specification"""
    name: str
    description: str
    risk: ToolRisk = ToolRisk.READ_ONLY
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    default_timeout: int = 30
    requires_confirmation: bool = False

    @property
    def is_read_only(self) -> bool:
        return self.risk == ToolRisk.READ_ONLY

    @property
    def is_dangerous(self) -> bool:
        return self.risk in (ToolRisk.EXECUTES_SAMPLE, ToolRisk.MUTATES_BINARY, ToolRisk.NETWORK)


@dataclass
class ToolCall:
    """A tool invocation"""
    tool: str
    args: dict[str, Any]
    run_id: str = ""
    timeout: int | None = None


@dataclass
class ToolObservation:
    """Result of a tool execution"""
    tool: str
    status: str  # ok, skipped, timeout, error
    summary: str = ""
    artifacts: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    raw_excerpt: str | None = None
    error: str | None = None
    elapsed_ms: int | None = None
