"""
Packer tools: detect_packer, repair_upx_sections, unpack_upx.
"""

import subprocess
from pathlib import Path
from types import SimpleNamespace

from ..core.observation import RuntimeObservation
from .packer_detect import detect_packer


def tool_detect_packer(args: dict) -> dict:
    sample = Path(args["sample_path"])
    profile = detect_packer(sample)
    return RuntimeObservation(
        tool="detect_packer", status="ok",
        summary=f"packed={profile.is_packed}, packer={profile.packer}, confidence={profile.confidence:.2f}",
        structured=profile.model_dump(),
        evidence_ids=[f"packer:{s.name}" for s in profile.signals],
        risk="read_only", token_hint=80,
    ).model_dump()


def tool_repair_upx_sections(args: dict) -> dict:
    sample = Path(args["sample_path"])
    output_dir = Path(args.get("output_dir", sample.parent))
    output_dir.mkdir(parents=True, exist_ok=True)

    data = bytearray(sample.read_bytes())
    hits = []
    replacements = [(b"VMP0", b"UPX0"), (b"VMP1", b"UPX1"),
                    (b".vmp0", b"UPX0"), (b".vmp1", b"UPX1")]

    for old, new in replacements:
        idx = data.find(old)
        while idx != -1:
            data[idx: idx + len(old)] = new
            hits.append({"offset": hex(idx), "old": old.decode(errors="replace"),
                          "new": new.decode(errors="replace")})
            idx = data.find(old, idx + 1)

    if not hits:
        return RuntimeObservation(
            tool="repair_upx_sections", status="skipped",
            summary="No VMP0/VMP1 markers found.", structured={"hits": []},
            risk="read_only", token_hint=40,
        ).model_dump()

    out = output_dir / f"{sample.stem}.upx_repaired{sample.suffix}"
    out.write_bytes(bytes(data))
    return RuntimeObservation(
        tool="repair_upx_sections", status="ok",
        summary=f"Repaired {len(hits)} UPX section marker(s).",
        structured={"hits": hits, "repaired_path": str(out)},
        artifacts=[str(out)], risk="read_only", token_hint=100,
    ).model_dump()


def _run_upx_decompress(sample: Path, out: Path, timeout: int = 30):
    cmd = ["upx", "-d", "-o", str(out), str(sample)]
    cp = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout)
    return SimpleNamespace(ok=cp.returncode == 0, stdout=cp.stdout,
                           stderr=cp.stderr, returncode=cp.returncode)


def tool_unpack_upx(args: dict) -> dict:
    sample = Path(args["sample_path"])
    output_dir = Path(args.get("output_dir", sample.parent))
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"{sample.stem}.unpacked{sample.suffix}"

    try:
        result = _run_upx_decompress(sample, out, timeout=int(args.get("timeout", 30)))
    except FileNotFoundError:
        return RuntimeObservation(
            tool="unpack_upx", status="error",
            summary="upx executable not found.", error="upx not found",
            risk="read_only",
        ).model_dump()
    except subprocess.TimeoutExpired:
        return RuntimeObservation(
            tool="unpack_upx", status="timeout",
            summary="UPX unpack timed out.", risk="read_only",
        ).model_dump()

    if result.ok and out.exists():
        return RuntimeObservation(
            tool="unpack_upx", status="ok",
            summary=f"UPX unpack succeeded: {out.name}",
            structured={"unpacked_path": str(out), "stdout_tail": result.stdout[-2000:]},
            artifacts=[str(out)], risk="read_only", token_hint=120,
        ).model_dump()

    return RuntimeObservation(
        tool="unpack_upx", status="error",
        summary="UPX unpack failed.", structured={"stdout_tail": result.stdout[-2000:]},
        error=result.stderr[-1000:], risk="read_only", token_hint=120,
    ).model_dump()
