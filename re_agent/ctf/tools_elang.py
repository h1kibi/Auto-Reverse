"""
E-language detection tool.

Detects: 易语言 (E-language) runtime hints, 加密数据, 字节集, etc.
"""

from pathlib import Path
from ..core.observation import RuntimeObservation


def tool_detect_e_language(args: dict) -> dict:
    strings = args.get("strings", [])
    imports = args.get("imports", [])
    sample_path = args.get("sample_path")

    hints = []
    joined = "\n".join(strings[:1000]) if strings else ""
    for token in ["易语言", "字节集", "到字节集", "到文本", "取文本长度",
                   "加密数据", "解压数据", "标准输入", "标准输出"]:
        if token in joined:
            hints.append(token)

    import_joined = "\n".join(imports).lower() if imports else ""
    for token in ["krnln", "eapi", "elib"]:
        if token in import_joined:
            hints.append(f"import:{token}")

    if sample_path:
        try:
            data = Path(sample_path).read_bytes()[:2_000_000]
            for token in ["加密数据", "字节集", "到字节集", "到文本"]:
                for enc in ["gbk", "utf-16le"]:
                    raw = token.encode(enc, errors="ignore")
                    if raw and raw in data:
                        hints.append(f"{enc}:{token}")
        except Exception:
            pass

    is_e = bool(hints)
    return RuntimeObservation(
        tool="detect_e_language", status="ok",
        summary=f"e_language={is_e}, hints={hints[:6]}",
        structured={"is_e_language": is_e, "hints": hints},
        risk="read_only", token_hint=100,
    ).model_dump()


def tool_extract_e_bytearray(args: dict) -> dict:
    sample = Path(args.get("sample_path", ""))
    address = args.get("address")
    if not address:
        return RuntimeObservation(
            tool="extract_e_bytearray", status="skipped",
            summary="No E-language bytearray address provided.", risk="read_only",
        ).model_dump()
    try:
        import pefile
        pe = pefile.PE(str(sample), fast_load=False)
        struct_va = int(str(address), 0)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        rva = struct_va - image_base
        off = pe.get_offset_from_rva(rva)
        length = int.from_bytes(pe.__data__[off + 4: off + 8], "little")
        data_va = int.from_bytes(pe.__data__[off + 8: off + 12], "little")
        if length <= 0 or length > 8192:
            raise ValueError(f"unreasonable length: {length}")
        rva2 = data_va - image_base
        off2 = pe.get_offset_from_rva(rva2)
        data = pe.__data__[off2: off2 + length]

        return RuntimeObservation(
            tool="extract_e_bytearray", status="ok",
            summary=f"Extracted E-language bytearray length={length} at {hex(struct_va)}.",
            structured={
                "struct_va": hex(struct_va), "length": length, "data_va": hex(data_va),
                "data_hex": data.hex().upper(), "ascii_preview": data[:64].decode("latin1", errors="replace"),
            },
            evidence_ids=[f"e_bytearray:{hex(struct_va)}"], risk="read_only", token_hint=120,
        ).model_dump()
    except Exception as exc:
        return RuntimeObservation(
            tool="extract_e_bytearray", status="error",
            summary=f"Extraction failed: {exc}", error=str(exc), risk="read_only",
        ).model_dump()


def tool_decode_e_bytearray_candidates(args: dict) -> dict:
    data_hex = args.get("data_hex") or args.get("hex", "")
    if not data_hex:
        return RuntimeObservation(
            tool="decode_e_bytearray_candidates", status="skipped",
            summary="No hex data provided.", risk="read_only",
        ).model_dump()
    data = bytes.fromhex(data_hex)
    candidates = []
    for enc in ("gbk", "utf-16le", "utf-8"):
        try:
            s = data.decode(enc)
            if len(s) >= 4 and any(c.isalpha() for c in s):
                candidates.append({"kind": enc, "value": s[:300], "confidence": 0.6})
        except UnicodeDecodeError:
            pass
    for key in range(256):
        x = bytes(b ^ key for b in data)
        pr = sum(32 <= c <= 126 or c in (9, 10, 13) for c in x) / max(len(x), 1)
        if pr > 0.85:
            candidates.append({"kind": "xor1", "key": key,
                               "value": x.decode("latin1", errors="replace")[:300],
                               "confidence": 0.5})
    return RuntimeObservation(
        tool="decode_e_bytearray_candidates", status="ok",
        summary=f"Decoded {len(candidates)} candidate views.",
        structured={"candidates": candidates[:50]},
        candidates=candidates[:10],
        risk="read_only", token_hint=180,
    ).model_dump()
