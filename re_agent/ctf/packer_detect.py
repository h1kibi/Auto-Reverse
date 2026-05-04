"""
Packer detection - Stage 0 gate before solvers.

Detects UPX/VMP/high entropy/low strings, produces PackerProfile.
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field


class PackerSignal(BaseModel):
    name: str
    confidence: float
    evidence: list[str] = Field(default_factory=list)


class PackerProfile(BaseModel):
    is_packed: bool = False
    packer: str | None = None
    confidence: float = 0.0
    signals: list[PackerSignal] = Field(default_factory=list)
    should_unwrap_before_static: bool = False
    should_skip_static_solvers: bool = False
    should_prefer_dynamic: bool = False


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def approximate_ascii_string_count(data: bytes, min_len: int = 4) -> int:
    count = 0
    run = 0
    for b in data:
        if 32 <= b <= 126:
            run += 1
        else:
            if run >= min_len:
                count += 1
            run = 0
    if run >= min_len:
        count += 1
    return count


def detect_packer(sample: Path, analysis=None) -> PackerProfile:
    try:
        data = sample.read_bytes()
    except Exception:
        return PackerProfile()

    signals: list[PackerSignal] = []

    # UPX signatures
    head = data[:0x2000]
    if b"UPX!" in head or b"UPX0" in data or b"UPX1" in data or b".upx" in head.lower():
        signals.append(PackerSignal(
            name="upx_signature", confidence=0.95,
            evidence=["found UPX/UPX0/UPX1 signature"],
        ))

    # VMP hints
    lowered = data[:0x200000].lower()
    if b"vmp" in lowered or b"vmprotect" in lowered:
        signals.append(PackerSignal(
            name="vmp_signature", confidence=0.85,
            evidence=["found VMP/VMProtect-like signature"],
        ))

    # High entropy
    entropy = shannon_entropy(data[:min(len(data), 2 * 1024 * 1024)])
    if entropy > 7.25:
        signals.append(PackerSignal(
            name="high_entropy", confidence=0.65,
            evidence=[f"entropy={entropy:.2f}"],
        ))

    # Low strings
    sc = approximate_ascii_string_count(data)
    if sc < 20 and len(data) > 100_000:
        signals.append(PackerSignal(
            name="low_string_count", confidence=0.55,
            evidence=[f"ascii_string_count={sc}"],
        ))

    score = sum(s.confidence for s in signals)
    is_packed = any(s.name in {"upx_signature", "vmp_signature"} for s in signals) or score >= 1.2
    packer = None
    if any(s.name == "upx_signature" for s in signals):
        packer = "upx"
    elif any(s.name == "vmp_signature" for s in signals):
        packer = "vmp"
    elif is_packed:
        packer = "generic"

    return PackerProfile(
        is_packed=is_packed, packer=packer,
        confidence=min(score / 2.0, 1.0), signals=signals,
        should_unwrap_before_static=(packer == "upx"),
        should_skip_static_solvers=is_packed,
        should_prefer_dynamic=is_packed,
    )
