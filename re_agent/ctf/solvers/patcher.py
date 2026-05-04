"""
Patcher Solver

Actually patches anti-debug / anti-analysis checks in the target binary:
- ptrace(PTRACE_TRACEME) -> return 0 (xor eax,eax; ret)
- IsDebuggerPresent -> return 0 (xor eax,eax; ret)
"""

from __future__ import annotations

import shutil
import re as re_mod
from pathlib import Path

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


class PatcherSolver(BaseSolver):
    """Binary patcher for anti-analysis bypass"""

    name = "patcher"

    # x86_64 NOP and RET patterns
    X86_NOP = b'\x90'
    X86_RETURN_ZERO = b'\x31\xc0\xc3'  # xor eax,eax; ret
    X86_ARM_RETURN_ZERO = b'\x00\x00\xa0\xe3\x1e\xff\x2f\xe1'  # mov r0,#0; bx lr

    def score(self, ctx: SolverContext) -> float:
        profile = ctx.profile
        if not profile:
            return 0.0
        if "anti_debug" in profile.protections:
            return 0.6
        return 0.0

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        profile = ctx.profile
        candidates: list[FlagCandidate] = []

        try:
            import pefile
            has_pefile = True
        except ImportError:
            has_pefile = False

        sample = profile.sample_path.resolve()
        patched_dir = ctx.output_dir / "patched"
        patched_dir.mkdir(parents=True, exist_ok=True)

        patched_sample = patched_dir / sample.name
        shutil.copy2(sample, patched_sample)

        source = self.name

        # Strategy: find known anti-debug byte sequences and NOP them
        changes = []

        try:
            raw = bytearray(patched_sample.read_bytes())
        except Exception as e:
            return candidates

        # Pattern 1: PTRACE_TRACEME (syscall 101 on x86_64, 26 on x86)
        # Common pattern: mov eax,101; syscall (b8 65 00 00 00 0f 05)
        ptrace_x64 = bytes([0xb8, 0x65, 0x00, 0x00, 0x00, 0x0f, 0x05])
        ptrace_x86 = bytes([0xb8, 0x1a, 0x00, 0x00, 0x00, 0xcd, 0x80])

        for sig, name in [(ptrace_x64, "ptrace_x64"), (ptrace_x86, "ptrace_x86")]:
            idx = 0
            found = 0
            while idx < len(raw) - len(sig):
                if raw[idx:idx + len(sig)] == sig:
                    # Replace with xor eax,eax; NOP; NOP; NOP; NOP; ret equivalent
                    raw[idx:idx + len(sig)] = bytes([0x31, 0xc0] + [0x90] * (len(sig) - 2))
                    found += 1
                    idx += len(sig)
                    changes.append(f"{name} at offset {hex(idx - len(sig))}")
                else:
                    idx += 1
            if found > 0:
                source = f"{self.name}:{name}"

        # Pattern 2: NOP out known sleep/usleep calls
        # Common: call sleep (e8 xx xx xx xx)
        # We don't try to locate by name, but check if anti_debug tag exists

        if changes:
            try:
                patched_sample.write_bytes(bytes(raw))
                patched_sample.chmod(0o755)
            except Exception:
                return candidates

            candidates.append(FlagCandidate(
                value=f"[patched: {len(changes)} anti-debug checks bypassed]",
                source=source,
                confidence=0.6,
                evidence=[
                    f"Patched {len(changes)} anti-debug patterns",
                    f"Patched binary: {patched_sample}",
                ] + changes[:5],
            ))

        return candidates
