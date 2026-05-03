"""
挑战画像构建器

从分析结果中提取关键信息，构建 ChallengeProfile
"""

import json
import re
from pathlib import Path

from ..schema import AnalysisResult, ArtifactType
from .models import ChallengeProfile


SUCCESS_PATTERNS = [
    r"correct",
    r"success",
    r"congrat",
    r"good job",
    r"you win",
    r"right",
    r"accepted",
    r"well done",
]

FAILURE_PATTERNS = [
    r"wrong",
    r"incorrect",
    r"fail",
    r"try again",
    r"invalid",
    r"nope",
    r"bad",
]


def _load_text(path: str, limit: int = 2_000_000) -> str:
    """加载文本文件"""
    p = Path(path)
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")[:limit]


def build_profile(result: AnalysisResult) -> ChallengeProfile:
    """从分析结果构建挑战画像"""
    profile = ChallengeProfile(
        sample_path=Path(result.sample.path),
        sha256=result.sample.sha256,
        file_type=result.sample.file_type or "",
        architecture=result.sample.architecture or "",
    )

    # 提取 strings、imports、functions
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

    # 识别 success/failure 字符串
    for s in profile.strings:
        s_lower = s.lower()
        if any(re.search(p, s_lower) for p in SUCCESS_PATTERNS):
            profile.success_strings.append(s)
        if any(re.search(p, s_lower) for p in FAILURE_PATTERNS):
            profile.failure_strings.append(s)

    # 标签识别
    all_text = " ".join(profile.strings + profile.imports).lower()

    if any(kw in all_text for kw in ["ptrace", "isdebuggerpresent"]):
        profile.tags.append("anti_debug")

    if any(kw in all_text for kw in ["upx0", "upx1", "upx!"]):
        profile.tags.append("packed_upx")

    if profile.success_strings:
        profile.tags.append("has_success_string")

    return profile
