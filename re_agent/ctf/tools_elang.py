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
            for token in ["加密数据".encode("gbk", errors="ignore"),
                           "字节集".encode("gbk", errors="ignore")]:
                if token and token in data:
                    hints.append("gbk:e_language_token")
        except Exception:
            pass

    is_e = bool(hints)
    return RuntimeObservation(
        tool="detect_e_language", status="ok",
        summary=f"e_language={is_e}, hints={hints[:6]}",
        structured={"is_e_language": is_e, "hints": hints},
        risk="read_only", token_hint=100,
    ).model_dump()
