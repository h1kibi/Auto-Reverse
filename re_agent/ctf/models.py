"""
CTF 数据模型
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass
class FlagCandidate:
    """候选 flag"""
    value: str
    source: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    verified: bool = False


@dataclass
class ChallengeProfile:
    """挑战画像"""
    sample_path: Path
    sha256: str
    file_type: str = ""
    architecture: str = ""
    strings: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    success_strings: list[str] = field(default_factory=list)
    failure_strings: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class SolveResult:
    """求解结果"""
    status: Literal["solved", "unsolved", "error"]
    sha256: str
    candidates: list[FlagCandidate] = field(default_factory=list)
    method: str = ""
    summary: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def best_flag(self) -> str | None:
        """返回最佳 flag（优先验证过的）"""
        verified = [c for c in self.candidates if c.verified]
        pool = verified or self.candidates
        if not pool:
            return None
        return max(pool, key=lambda c: c.confidence).value
