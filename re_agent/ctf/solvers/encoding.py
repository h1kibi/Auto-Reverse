"""
EncodingSolver - Beam search decoder for multi-layer CTF encoding.

Supports: raw, reverse, rot13/rot_all, base64, base32, base85,
hex, url decode, unicode_escape, single-byte xor, small repeating key xor.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass, field

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


@dataclass
class _DecodeNode:
    """A node in the beam search decode tree"""
    data: bytes
    chain: list[str] = field(default_factory=list)
    score: float = 0.0
    source: str = ""


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
        if re.search(r"[A-Z2-7=]{16,}", joined):
            score += 0.10

        return min(score, 0.85)

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        regex = re.compile(ctx.flag_regex, re.IGNORECASE)
        candidates: list[FlagCandidate] = []

        seed_values = []
        for s in ctx.profile.strings:
            s = s.strip()
            if not s:
                continue
            try:
                seed_values.append(s.encode("latin1"))
            except Exception:
                seed_values.append(s.encode("utf-8", errors="replace"))

        for node in _decode_beam(seed_values, max_depth=3, beam_size=80):
            try:
                text = node.data.decode("utf-8", errors="replace")
            except Exception:
                continue

            for m in regex.finditer(text):
                chain_str = " -> ".join(node.chain) if node.chain else "raw"
                candidates.append(
                    FlagCandidate(
                        value=m.group(0),
                        source=self.name,
                        confidence=0.82 + 0.03 * min(len(node.chain), 4),
                        evidence=[
                            f"encoding solver decoded {len(node.chain)} layers: {chain_str}",
                            f"origin: {node.source[:100]}...",
                        ],
                    )
                )

        return _dedup(candidates)


def _decode_beam(
    seed_values: list[bytes],
    max_depth: int = 4,
    beam_size: int = 100,
):
    beam: list[_DecodeNode] = [
        _DecodeNode(data=s, chain=[], score=_score_bytes(s), source=f"string({len(s)}B)")
        for s in seed_values[:200]
    ]
    seen: set[bytes] = set()

    for depth in range(max_depth):
        next_nodes: list[_DecodeNode] = []

        for node in beam[:beam_size]:
            for name, transform in TRANSFORMS:
                try:
                    results = transform(node.data)
                except Exception:
                    continue
                for out in results:
                    if not out or len(out) < 2:
                        continue
                    key = out[:64]
                    if key in seen:
                        continue
                    seen.add(key)
                    next_nodes.append(_DecodeNode(
                        data=out,
                        chain=node.chain + [name],
                        score=_score_bytes(out),
                        source=node.source,
                    ))

        beam = sorted(next_nodes, key=lambda n: n.score, reverse=True)[:beam_size]

        for node in beam:
            if _looks_like_flag(node.data):
                yield node

    for node in beam[:10]:
        if _score_bytes(node.data) > 0.5:
            yield node


def _score_bytes(data: bytes) -> float:
    """Score data as potential plaintext"""
    if not data:
        return 0.0
    score = 0.0
    total = len(data)

    printable = sum(32 <= b <= 126 for b in data)
    score += (printable / total) * 0.4

    lower = sum(97 <= b <= 122 for b in data)
    if lower > 0:
        score += 0.1

    special_ctf = sum(b in b"{}\\_-" for b in data)
    if special_ctf > 0:
        score += 0.1

    if b"flag" in data.lower() or b"ctf" in data.lower():
        score += 0.3

    if b"correct" in data.lower() or b"wrong" in data.lower():
        score += 0.1

    return min(score, 1.0)


def _looks_like_flag(data: bytes) -> bool:
    """Check if data looks like a CTF flag"""
    return bool(re.search(rb"(?:flag|ctf|picoctf|hgame)\{", data.lower()))


def _try_base64(data: bytes) -> list[bytes]:
    try:
        text = data.decode("ascii")
    except (UnicodeDecodeError, ValueError):
        return []
    cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", text)
    if len(cleaned) < 8:
        return []
    padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
    try:
        decoded = base64.b64decode(padded, validate=False)
    except Exception:
        return []
    if len(decoded) < 2:
        return []
    return [decoded]


def _try_base32(data: bytes) -> list[bytes]:
    try:
        text = data.decode("ascii").upper()
    except Exception:
        return []
    text = re.sub(r"[^A-Z2-7=]", "", text)
    if len(text) < 8:
        return []
    padding = (8 - len(text) % 8) % 8
    try:
        return [base64.b32decode(text + "=" * padding)]
    except Exception:
        return []


def _try_base85(data: bytes) -> list[bytes]:
    try:
        text = data.decode("ascii")
    except Exception:
        return []
    if len(text) < 4:
        return []
    try:
        return [base64.b85decode(text)]
    except Exception:
        return []


def _try_hex_decode(data: bytes) -> list[bytes]:
    try:
        text = data.decode("ascii")
    except Exception:
        return []
    cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(cleaned) < 8 or len(cleaned) % 2 != 0:
        return []
    try:
        return [binascii.unhexlify(cleaned)]
    except Exception:
        return []


def _try_url_decode(data: bytes) -> list[bytes]:
    try:
        text = data.decode("ascii")
    except Exception:
        return []
    if "%" not in text:
        return []
    try:
        from urllib.parse import unquote
        return [unquote(text).encode("utf-8")]
    except Exception:
        return []


def _try_rot13(data: bytes) -> list[bytes]:
    try:
        text = data.decode("ascii")
    except Exception:
        return []
    out = []
    for ch in text:
        code = ord(ch)
        if 65 <= code <= 90:
            out.append(chr(65 + (code - 65 + 13) % 26))
        elif 97 <= code <= 122:
            out.append(chr(97 + (code - 97 + 13) % 26))
        else:
            out.append(ch)
    result = "".join(out)
    if result == text:
        return []
    return [result.encode("utf-8")]


def _try_all_rot(data: bytes) -> list[bytes]:
    try:
        text = data.decode("ascii")
    except Exception:
        return []
    results = []
    for shift in range(1, 26):
        out = []
        for ch in text:
            code = ord(ch)
            if 65 <= code <= 90:
                out.append(chr(65 + (code - 65 + shift) % 26))
            elif 97 <= code <= 122:
                out.append(chr(97 + (code - 97 + shift) % 26))
            else:
                out.append(ch)
        results.append("".join(out).encode("utf-8"))
    return results


def _try_xor_single(data: bytes) -> list[bytes]:
    if len(data) < 4 or len(data) > 512:
        return []
    results = []
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        if b"flag{" in decoded.lower() or b"ctf{" in decoded.lower():
            results.append(decoded)
            if len(results) >= 5:
                break
    return results


def _try_repeating_xor(data: bytes) -> list[bytes]:
    if len(data) < 6:
        return []
    results = []
    for key_len in range(1, 17):
        if key_len > len(data):
            break
        key_candidates = []
        for offset in range(key_len):
            best_key = 0
            best_score = 0
            for k in range(256):
                count = 0
                for i in range(offset, len(data), key_len):
                    decoded = data[i] ^ k
                    if 32 <= decoded <= 126:
                        count += 1
                if count > best_score:
                    best_score = count
                    best_key = k
            key_candidates.append(best_key)

        decoded = bytearray()
        for i, b in enumerate(data):
            decoded.append(b ^ key_candidates[i % key_len])
        decoded_bytes = bytes(decoded)
        if b"flag" in decoded_bytes.lower():
            results.append(decoded_bytes)
            if len(results) >= 3:
                break
    return results


TRANSFORMS = [
    ("reverse", lambda b: [b[::-1]]),
    ("base64", _try_base64),
    ("base32", _try_base32),
    ("base85", _try_base85),
    ("hex", _try_hex_decode),
    ("url", _try_url_decode),
    ("rot13", _try_rot13),
    ("rot_all", _try_all_rot),
    ("xor_single", _try_xor_single),
    ("xor_repeating_small", _try_repeating_xor),
]


def _dedup(candidates: list[FlagCandidate]) -> list[FlagCandidate]:
    seen: set[str] = set()
    out: list[FlagCandidate] = []
    for c in sorted(candidates, key=lambda x: x.confidence, reverse=True):
        if c.value in seen:
            continue
        seen.add(c.value)
        out.append(c)
    return out
