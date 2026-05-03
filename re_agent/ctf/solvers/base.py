"""
求解器基类
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from ..models import ChallengeProfile, FlagCandidate


@dataclass
class SolverContext:
    """求解器上下文"""
    profile: ChallengeProfile
    output_dir: Path
    flag_regex: str = r"(flag|ctf|picoCTF|hgame|nssctf|h1kibi)\{[^}\r\n]{1,160}\}"
    timeout: int = 120


class BaseSolver(ABC):
    """求解器基类"""

    name: str = "base"

    @abstractmethod
    def score(self, ctx: SolverContext) -> float:
        """返回 0..1 的适用度评分"""
        raise NotImplementedError

    @abstractmethod
    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        """执行求解，返回候选 flag 列表"""
        raise NotImplementedError
