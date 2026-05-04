"""
挑战画像构建器

从分析结果中提取关键信息，构建增强版 ChallengeProfile
"""

import json
import re
from pathlib import Path

from ..schema import AnalysisResult, ArtifactType
from .models import ChallengeProfile


SUCCESS_PATTERNS = [
    r"correct", r"success", r"congrat", r"good job",
    r"you win", r"right", r"accepted", r"well done",
    r"hooray", r"flag is",
]

FAILURE_PATTERNS = [
    r"wrong", r"incorrect", r"fail", r"try again",
    r"invalid", r"nope", r"bad", r"you lose",
]

COMPARISON_APIS = [
    "strcmp", "strncmp", "memcmp", "wcscmp", "wcsncmp",
    "strcoll", "strcasecmp", "strncasecmp",
]

INPUT_APIS = [
    "scanf", "fgets", "read", "getchar", "getc", "fgetc",
    "fread", "gets", "cin", "argv",
]

CRYPTO_CONSTANTS = {
    "aes": ["aes", "rijndael", "sbox", "mixcolumns", "subbytes"],
    "rc4": ["rc4", "arc4", "ksa", "prga"],
    "md5": ["md5", "0x67452301", "0xefcdab89", "0x98badcfe", "0x10325476"],
    "sha256": ["sha256", "0x6a09e667", "0xbb67ae85", "0x3c6ef372"],
    "sha1": ["sha1", "0x67452301", "0xefcdab89"],
    "xor": ["xor", "0x23", "^=", "byte_xor"],
    "tea": ["tea", "xtea", "delta", "0x9e3779b9"],
    "base64": ["base64", "ABCDEFGHIJKLMNOP", "encode64"],
    "rot": ["rot13", "rot47", "caesar"],
}

ENCODING_INDICATORS = [
    (r"^[A-Za-z0-9+/]{16,}={0,2}$", "base64"),
    (r"^(?:[0-9a-fA-F]{2}){8,}$", "hex"),
    (r"^[A-Z2-7=]{16,}$", "base32"),
    (r"^[0-9A-Za-z!#$%&()*+,-./:;<=>?@[\]^_`{|}~]{12,}$", "base85"),
    (r"^%[0-9A-Fa-f]{2}", "url_encoded"),
    (r"\\u[0-9a-fA-F]{4}", "unicode_escape"),
]

PROTECTION_INDICATORS = {
    "upx0": "packed_upx",
    "upx1": "packed_upx",
    "ptrace": "anti_debug",
    "isdebuggerpresent": "anti_debug",
    "checkremotedebuggerpresent": "anti_debug",
    "/proc/self/status": "anti_debug",
    "pipe": "pie",
    "canary": "stack_canary",
    "__stack_chk": "stack_canary",
}

RUNTIME_INDICATORS = {
    "go.buildid": "go",
    "goroutine": "go",
    "runtime.h": "go",
    "rust": "rust",
    "cargo": "rust",
    "mscorlib": "dotnet",
    "System.": "dotnet",
    "java": "java",
    "JNI": "java",
    "PyInit": "python",
    "python": "python",
}


def _load_text(path: str, limit: int = 2_000_000) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")[:limit]


def build_profile(result: AnalysisResult) -> ChallengeProfile:
    """从分析结果构建增强版挑战画像"""
    profile = ChallengeProfile(
        sample_path=Path(result.sample.path),
        sha256=result.sample.sha256,
        file_type=result.sample.file_type or "",
        architecture=result.sample.architecture or "",
    )

    # 提取 strings、imports
    for tr in result.tool_results:
        for art in tr.artifacts:
            if art.type == ArtifactType.STRINGS:
                text = _load_text(art.path)
                profile.strings.extend([
                    s.strip() for s in text.splitlines() if s.strip()
                ])
            elif art.type == ArtifactType.IMPORTS:
                text = _load_text(art.path)
                profile.imports.extend([
                    s.strip() for s in text.splitlines() if s.strip()
                ])

    all_text = " ".join(profile.strings + profile.imports).lower()
    imports_lower = [i.lower() for i in profile.imports]

    # 1. success/failure 字符串
    for s in profile.strings:
        s_lower = s.lower()
        if any(re.search(p, s_lower) for p in SUCCESS_PATTERNS):
            profile.success_strings.append(s)
        if any(re.search(p, s_lower) for p in FAILURE_PATTERNS):
            profile.failure_strings.append(s)

    # 2. 输入通道检测
    if any(api in all_text for api in ["argv", "main(argc", "__libc_start_main"]):
        profile.input_channels.append("argv")
    if any(api in all_text for api in ["scanf", "fgets", "read(", "getchar", "stdin", "cin"]):
        profile.input_channels.append("stdin")
    if any(api in all_text for api in ["fopen", "ifstream", "open(", "readfile"]):
        profile.input_channels.append("file")
    if any(api in all_text for api in ["getenv", "environ", "envp"]):
        profile.input_channels.append("env")

    # 3. 比较 API 检测
    for api in COMPARISON_APIS:
        if api in all_text:
            profile.comparison_hints.append(api)

    # 4. 加密/编码提示
    for family, indicators in CRYPTO_CONSTANTS.items():
        if any(ind in all_text for ind in indicators):
            profile.crypto_hints.append(family)

    for pattern, name in ENCODING_INDICATORS:
        for s in profile.strings[:500]:
            if re.match(pattern, s):
                if name not in profile.encoding_hints:
                    profile.encoding_hints.append(name)

    # 5. 保护检测
    for indicator, tag in PROTECTION_INDICATORS.items():
        if indicator in all_text:
            profile.protections.append(tag)

    # 6. 运行时检测
    for indicator, runtime in RUNTIME_INDICATORS.items():
        if indicator.lower() in all_text:
            if runtime not in profile.runtimes:
                profile.runtimes.append(runtime)

    # 7. 标签识别
    if profile.success_strings:
        profile.tags.append("has_success_string")
    if profile.failure_strings:
        profile.tags.append("has_failure_string")
    if profile.comparison_hints:
        profile.tags.append("has_comparison")
    if profile.crypto_hints:
        profile.tags.append("has_crypto")
    if profile.encoding_hints:
        profile.tags.append("has_encoding")
    if "argv" in profile.input_channels:
        profile.tags.append("input_argv")
    if "stdin" in profile.input_channels:
        profile.tags.append("input_stdin")

    for tag in profile.protections:
        if tag not in profile.tags:
            profile.tags.append(tag)

    # 8. solver 提示
    has_flag_like = any(
        re.search(r"(?:flag|ctf|picoctf|hgame|nssctf|h1kibi)\{[^}\r\n]{1,160}\}", s, re.IGNORECASE)
        for s in profile.strings
    )
    if has_flag_like:
        profile.solver_hints.append("static_flag")

    if profile.encoding_hints:
        profile.solver_hints.append("decoding")

    if profile.comparison_hints:
        profile.solver_hints.append("dynamic_trace")
        profile.solver_hints.append("z3_constraints")

    if profile.success_strings:
        profile.solver_hints.append("angr_path")

    if profile.crypto_hints:
        profile.solver_hints.append("z3_constraints")

    # 9. 可疑常量
    const_pattern = re.compile(r"(?:0x[0-9a-fA-F]{2,8}|\d{8,})")
    seen_consts = set()
    for s in profile.strings:
        for match in const_pattern.finditer(s):
            val = match.group()
            if len(val) >= 8 and val not in seen_consts:
                seen_consts.add(val)
                profile.suspicious_constants.append(val)
                if len(profile.suspicious_constants) >= 20:
                    break
        if len(profile.suspicious_constants) >= 20:
            break

    return profile
