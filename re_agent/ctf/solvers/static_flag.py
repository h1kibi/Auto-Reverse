"""
静态 Flag 求解器

从 strings 中直接提取 flag，或解码 base64/hex 后提取
"""

import base64
import binascii
import re

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


class StaticFlagSolver(BaseSolver):
    """静态 Flag 求解器"""

    name = "static_flag"

    def score(self, ctx: SolverContext) -> float:
        """有 strings 就值得尝试"""
        return 0.8 if ctx.profile.strings else 0.0

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        """从 strings 中提取 flag"""
        regex = re.compile(ctx.flag_regex, re.IGNORECASE)
        candidates: list[FlagCandidate] = []

        for s in ctx.profile.strings:
            # 直接匹配
            for m in regex.finditer(s):
                candidates.append(FlagCandidate(
                    value=m.group(0),
                    source=self.name,
                    confidence=0.95,
                    evidence=[f"matched flag regex in strings: {s[:160]}"],
                ))

            # 尝试解码后匹配
            for decoded, method in self._decode_candidates(s):
                for m in regex.finditer(decoded):
                    candidates.append(FlagCandidate(
                        value=m.group(0),
                        source=self.name,
                        confidence=0.85,
                        evidence=[f"decoded by {method}: {s[:160]}"],
                    ))

        return _dedup(candidates)

    def _decode_candidates(self, s: str) -> list[tuple[str, str]]:
        """尝试解码字符串"""
        raw = s.strip()
        out: list[tuple[str, str]] = []

        # base64
        if 8 <= len(raw) <= 512:
            try:
                b = base64.b64decode(raw, validate=True)
                if _mostly_printable(b):
                    out.append((b.decode("utf-8", errors="replace"), "base64"))
            except Exception:
                pass

        # hex
        if len(raw) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", raw or ""):
            try:
                b = binascii.unhexlify(raw)
                if _mostly_printable(b):
                    out.append((b.decode("utf-8", errors="replace"), "hex"))
            except Exception:
                pass

        return out


def _mostly_printable(b: bytes) -> bool:
    """检查字节是否大部分可打印"""
    if not b:
        return False
    printable = sum(32 <= x <= 126 or x in (9, 10, 13) for x in b)
    return printable / len(b) >= 0.85


def _dedup(candidates: list[FlagCandidate]) -> list[FlagCandidate]:
    """去重并按置信度排序"""
    seen: set[str] = set()
    out: list[FlagCandidate] = []

    for c in sorted(candidates, key=lambda x: x.confidence, reverse=True):
        if c.value in seen:
            continue
        seen.add(c.value)
        out.append(c)

    return out
