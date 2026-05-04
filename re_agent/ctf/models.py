"""
CTF 数据模型
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass
class EvidenceRef:
    """证据引用"""
    id: str = ""
    kind: str = ""
    artifact_id: str | None = None
    location: str | None = None
    excerpt: str | None = None


@dataclass
class Candidate:
    """候选答案"""
    value: str
    source: str
    confidence: float = 0.5
    evidence: list[EvidenceRef] = field(default_factory=list)
    input_channel: Literal["argv", "stdin", "file", "env", "unknown"] = "unknown"
    notes: str | None = None

    @property
    def verified(self) -> bool:
        return self.confidence >= 0.97


@dataclass
class SolverRun:
    """求解器执行记录"""
    solver: str
    status: Literal["ok", "skipped", "timeout", "error"]
    score: float = 0.0
    candidates: list[dict] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    error: str | None = None
    elapsed_ms: int | None = None


@dataclass
class SolveResult:
    """求解结果"""
    status: Literal["solved", "unsolved", "error"]
    sha256: str
    verified: bool = False
    winning_candidate: dict | None = None
    method: str = ""
    candidates: list[dict] = field(default_factory=list)
    solver_runs: list[SolverRun] = field(default_factory=list)
    trace_path: str | None = None
    reproduce_path: str | None = None
    summary: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def best_flag(self) -> str | None:
        """返回最佳 flag（优先验证过的）"""
        if self.winning_candidate:
            if isinstance(self.winning_candidate, dict):
                return self.winning_candidate.get("value")
            return getattr(self.winning_candidate, "value", None)
        if not self.candidates:
            return None

        def _is_verified(c):
            if isinstance(c, dict):
                return c.get("verified", False)
            return getattr(c, "verified", False)

        def _get_confidence(c):
            if isinstance(c, dict):
                return c.get("confidence", 0)
            return getattr(c, "confidence", 0)

        def _get_value(c):
            if isinstance(c, dict):
                return c.get("value")
            return getattr(c, "value", None)

        verified = [c for c in self.candidates if _is_verified(c)]
        pool = verified or self.candidates
        best = max(pool, key=_get_confidence)
        return _get_value(best)


@dataclass
class ChallengeProfile:
    """挑战画像"""
    sample_path: Path
    sha256: str
    file_type: str = ""
    architecture: str = ""
    bits: int | None = None
    endian: str | None = None
    os: str | None = None

    strings: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    success_strings: list[str] = field(default_factory=list)
    failure_strings: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    input_channels: list[str] = field(default_factory=list)
    runtimes: list[str] = field(default_factory=list)
    protections: list[str] = field(default_factory=list)
    crypto_hints: list[str] = field(default_factory=list)
    comparison_hints: list[str] = field(default_factory=list)
    encoding_hints: list[str] = field(default_factory=list)
    solver_hints: list[str] = field(default_factory=list)
    suspicious_constants: list[str] = field(default_factory=list)

    @property
    def has_encoded_strings(self) -> bool:
        return bool(self.encoding_hints) or any(
            "base64" in s.lower() or "hex" in s.lower()
            for s in self.tags
        )

    @property
    def has_success_string(self) -> bool:
        return bool(self.success_strings)

    @property
    def has_failure_string(self) -> bool:
        return bool(self.failure_strings)

    @property
    def has_constraint_like_code(self) -> bool:
        return bool(self.comparison_hints) or bool(self.crypto_hints)


@dataclass
class FlagCandidate:
    """候选 flag（兼容旧接口）"""
    value: str
    source: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    verified: bool = False
