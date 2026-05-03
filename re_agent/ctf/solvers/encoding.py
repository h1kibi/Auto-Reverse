"""
EncodingSolver

用于处理常见 CTF reverse 低成本编码题：
- raw strings
- base64
- hex
- rot13
- reverse
- single-byte xor
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


class EncodingSolver(BaseSolver):
    name = "encoding"

    def score(self, ctx: SolverContext) -> float:
        if not ctx.profile.strings:
            return 0.0

        joined = "\n".join(ctx.profile.strings[:500])
        score = 0.25

        if re.search(r"[A-Za-z0-9+/]{16,}={0,2}", joined):
            score += 0.25
        if re.search(r"(?:[0-9a-fA-F]{2}){8,}", joined):
            score += 0.20
        if "xor" in joined.lower() or "\\x" in joined:
            score += 0.15

        return min(score, 0.80)

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        regex = re.compile(ctx.flag_regex, re.IGNORECASE)
        candidates: list[FlagCandidate] = []

        for s in ctx.profile.strings:
            for decoded, method in self._decode_candidates(s):
                for m in regex.finditer(decoded):
                    candidates.append(
                        FlagCandidate(
                            value=m.group(0),
                            source=self.name,
                            confidence=self._confidence(method),
                            evidence=[f"encoding solver decoded by {method}: {s[:160]}"],
                        )
                    )

        return _dedup(candidates)

    def _decode_candidates(self, s: str) -> list[tuple[str, str]]:
        raw = s.strip()
        out: list[tuple[str, str]] = []

        if raw:
            out.append((raw, "raw"))

        reversed_s = raw[::-1]
        if reversed_s != raw:
            out.append((reversed_s, "reverse"))

        try:
            rot13 = codecs.decode(raw, "rot_13")
            if rot13 != raw:
                out.append((rot13, "rot13"))
        except Exception:
            pass

        b64 = self._try_base64(raw)
        if b64 is not None:
            out.append((b64, "base64"))

        hx = self._try_hex(raw)
        if hx is not None:
            out.append((hx, "hex"))

        raw_bytes = raw.encode("latin1", errors="ignore")
        if 4 <= len(raw_bytes) <= 512:
            for key in range(1, 256):
                decoded = bytes(b ^ key for b in raw_bytes)
                if b"flag{" in decoded.lower() or b"ctf{" in decoded.lower():
                    text = decoded.decode("utf-8", errors="replace")
                    out.append((text, f"xor_single_byte_{key:#x}"))

        return out

    def _try_base64(self, raw: str) -> str | None:
        cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", raw)
        if len(cleaned) < 8:
            return None

        padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)

        try:
            data = base64.b64decode(padded, validate=False)
        except binascii.Error:
            return None

        if not _mostly_printable(data):
            return None

        return data.decode("utf-8", errors="replace")

    def _try_hex(self, raw: str) -> str | None:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", raw)
        if len(cleaned) < 8 or len(cleaned) % 2 != 0:
            return None

        try:
            data = binascii.unhexlify(cleaned)
        except Exception:
            return None

        if not _mostly_printable(data):
            return None

        return data.decode("utf-8", errors="replace")

    def _confidence(self, method: str) -> float:
        if method == "raw":
            return 0.90
        if method in {"base64", "hex", "rot13", "reverse"}:
            return 0.82
        if method.startswith("xor_single_byte"):
            return 0.78
        return 0.70


def _mostly_printable(data: bytes) -> bool:
    if not data:
        return False

    printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in data)
    return printable / len(data) >= 0.85


def _dedup(candidates: list[FlagCandidate]) -> list[FlagCandidate]:
    seen: set[str] = set()
    out: list[FlagCandidate] = []

    for c in sorted(candidates, key=lambda x: x.confidence, reverse=True):
        if c.value in seen:
            continue
        seen.add(c.value)
        out.append(c)

    return out
