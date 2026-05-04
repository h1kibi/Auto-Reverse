"""
Patcher Solver (v2)

Produces artifacts (patched binary), NOT fake flag candidates.
Pipeline should re-enqueue downstream solvers on patched sample.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


class PatcherSolver(BaseSolver):
    """Binary patcher - returns empty candidates, produces artifacts"""

    name = "patcher"

    X86_PTRACE_SIG = bytes([0xb8, 0x65, 0x00, 0x00, 0x00, 0x0f, 0x05])
    X86_RET_ZERO = bytes([0x31, 0xc0, 0x90, 0x90, 0x90, 0x90, 0x90])

    def score(self, ctx: SolverContext) -> float:
        if not ctx.profile:
            return 0.0
        return 0.6 if "anti_debug" in ctx.profile.protections else 0.0

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        profile = ctx.profile
        if "anti_debug" not in profile.protections:
            return []

        sample = profile.sample_path.resolve()
        patched_dir = ctx.output_dir / "patched"
        patched_dir.mkdir(parents=True, exist_ok=True)

        patched_sample = patched_dir / sample.name
        shutil.copy2(sample, patched_sample)

        try:
            raw = bytearray(patched_sample.read_bytes())
        except Exception:
            return []

        changes = 0
        idx = 0
        sig = self.X86_PTRACE_SIG
        while idx < len(raw) - len(sig):
            if raw[idx:idx + len(sig)] == sig:
                raw[idx:idx + len(sig)] = self.X86_RET_ZERO
                changes += 1
                idx += len(sig)
            else:
                idx += 1

        if changes > 0:
            patched_sample.write_bytes(bytes(raw))
            patched_sample.chmod(0o755)

        return []  # No candidates - patcher produces artifacts, not flags
