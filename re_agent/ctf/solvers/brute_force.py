"""
Brute Force Solver

For small search spaces (e.g., 4-char key, known charset, limited combinations).
Only triggers when the search space is explicitly small (< 1M combinations).
"""

from __future__ import annotations

import itertools
import re
import string

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


class BruteForceSolver(BaseSolver):
    """Small-space brute force solver"""

    name = "brute_force"

    # Maximum combinations before skipping
    MAX_COMBINATIONS = 500_000

    def score(self, ctx: SolverContext) -> float:
        """Only scores high when profile suggests tiny search space."""
        profile = ctx.profile
        if not profile:
            return 0.0

        # If suspicious constants suggest small key
        for sc in profile.suspicious_constants:
            try:
                val = int(sc, 16) if sc.startswith("0x") else int(sc)
                if val <= 0xFF:
                    return 0.4  # single byte key
            except ValueError:
                pass

        return 0.0

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        regex = re.compile(ctx.flag_regex, re.IGNORECASE)
        candidates: list[FlagCandidate] = []

        # Strategy 1: Single-byte XOR
        for s in ctx.profile.strings[:200]:
            s = s.strip()
            if not s or len(s) < 4:
                continue
            try:
                raw = s.encode("latin1")
            except Exception:
                continue
            for key in range(256):
                decoded = bytes(b ^ key for b in raw)
                try:
                    text = decoded.decode("utf-8", errors="replace")
                except Exception:
                    continue
                for m in regex.finditer(text):
                    candidates.append(FlagCandidate(
                        value=m.group(0), source=self.name,
                        confidence=0.6,
                        evidence=[f"xor single byte key={key:#x}"],
                    ))

        # Strategy 2: Small charset brute (4-char printable)
        charset = string.printable[:95]  # standard printable ASCII
        for length in [3, 4]:
            total = len(charset) ** length
            if total > self.MAX_COMBINATIONS:
                continue
            for combo in itertools.product(charset, repeat=length):
                value = "".join(combo)
                if regex.match(value):
                    candidates.append(FlagCandidate(
                        value=value, source=self.name + ":charset",
                        confidence=0.3,
                        evidence=[f"charset brute force (len={length})"],
                    ))
                    if len(candidates) >= 5:
                        break
            if len(candidates) >= 5:
                break

        return _dedup(candidates)


def _dedup(candidates: list[FlagCandidate]) -> list[FlagCandidate]:
    seen: set[str] = set()
    out: list[FlagCandidate] = []
    for c in sorted(candidates, key=lambda x: x.confidence, reverse=True):
        if c.value in seen:
            continue
        seen.add(c.value)
        out.append(c)
    return out
