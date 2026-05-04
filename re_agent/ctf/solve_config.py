"""
SolveConfig - unified CTF solve configuration.

Defines all tuning knobs for a solve run in one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SolveConfig:
    """Unified solver configuration (one-stop tuning)."""

    # ── flag discovery ──
    flag_regex: str = r"(?:flag|ctf|picoCTF|hgame|nssctf|h1kibi)\{[^}\r\n]{1,160}\}"
    verify: bool = True

    # ── analysis depth ──
    quick: bool = False
    deep: bool = False
    skip_ghidra: bool = True

    # ── solver toggles ──
    enable_llm_planner: bool = False
    enable_memory: bool = True
    enable_dynamic: bool = False
    enable_angr: bool = True
    enable_ghidra: bool = True
    enable_r2: bool = True

    # ── time & resource budgets ──
    max_total_seconds: int = 300
    max_solver_seconds: int = 60
    max_dynamic_seconds: int = 10
    max_candidates: int = 50

    # ── validation ──
    allowed_input_channels: list[str] = field(default_factory=lambda: ["argv", "stdin"])
    validation_timeout: int = 10

    # ── output ──
    redact_candidates_in_logs: bool = False
    write_reflection: bool = True
    write_learning_report: bool = True

    def for_sandbox(self) -> dict:
        return {
            "timeout": self.validation_timeout,
            "enable_network": False,
        }
