"""
Solver base classes and context.

SolverContext now carries EvidenceGraph so solvers can consume
structured evidence instead of raw files.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..models import ChallengeProfile, FlagCandidate


@dataclass
class SolverContext:
    """Rich solver context with evidence graph"""

    profile: ChallengeProfile
    output_dir: Path
    flag_regex: str = r"(flag|ctf|picoCTF|hgame|nssctf|h1kibi)\{[^}\r\n]{1,160}\}"
    timeout: int = 120
    evidence: object | None = None  # EvidenceGraph (lazy imported)
    memory_hits: list[dict] = field(default_factory=list)

    @property
    def has_evidence(self) -> bool:
        return self.evidence is not None

    def get_success_targets(self) -> list[int]:
        """Get success branch targets from evidence graph"""
        if not self.evidence:
            return []
        try:
            return list(self.evidence.get_xref_targets_for_strings(
                self.profile.success_strings
            ))
        except Exception:
            return []

    def get_failure_targets(self) -> list[int]:
        if not self.evidence:
            return []
        try:
            return list(self.evidence.get_xref_targets_for_strings(
                self.profile.failure_strings
            ))
        except Exception:
            return []

    def get_comparison_functions(self) -> list[str]:
        """Get function names with comparison tags"""
        if not self.evidence:
            return []
        try:
            return [fn.name for fn in self.evidence.get_functions_by_tag("comparison")]
        except Exception:
            return []

    def get_flag_like_strings(self) -> list[str]:
        if not self.evidence:
            return [
                s for s in self.profile.strings
                if "flag" in s.lower() or "ctf" in s.lower()
            ]
        try:
            return [s.value for s in self.evidence.get_strings_by_tag("flag_like")]
        except Exception:
            return []


class BaseSolver(ABC):
    """Solver base class"""

    name: str = "base"

    @abstractmethod
    def score(self, ctx: SolverContext) -> float:
        """Return 0..1 applicability score"""
        raise NotImplementedError

    @abstractmethod
    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        """Execute solve, return candidate flags"""
        raise NotImplementedError

    def explain_skip(self, ctx: SolverContext) -> str:
        """Explain why this solver was skipped"""
        return "score too low"
