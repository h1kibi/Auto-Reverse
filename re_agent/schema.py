"""
Artifact Schema - 核心数据结构

大输出写 artifact 文件，小摘要进上下文。
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import json
import hashlib
from pathlib import Path


class ArtifactType(str, Enum):
    """Artifact 类型枚举"""
    STRINGS = "strings"
    IMPORTS = "imports"
    SECTIONS = "sections"
    FUNCTIONS = "functions"
    CALL_GRAPH = "call_graph"
    DECOMPILED_FUNCTION = "decompiled_function"
    DISASSEMBLY = "disassembly"
    YARA_MATCHES = "yara_matches"
    FILE_INFO = "file_info"
    HASH = "hash"
    REPORT = "report"


class ToolStatus(str, Enum):
    """工具执行状态"""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"


@dataclass
class Artifact:
    """单个 artifact 记录"""
    type: ArtifactType
    path: str  # artifact 文件路径
    name: str  # 具体名称（如函数名）
    address: Optional[str] = None  # 地址（如函数地址）
    metadata: dict = field(default_factory=dict)  # 额外元数据

    def to_dict(self) -> dict:
        d = {
            "type": self.type.value,
            "path": self.path,
            "name": self.name,
        }
        if self.address:
            d["address"] = self.address
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class ToolResult:
    """工具执行结果"""
    tool: str
    version: str
    sample_sha256: str
    status: ToolStatus
    artifacts: list[Artifact] = field(default_factory=list)
    summary: str = ""
    errors: list[str] = field(default_factory=list)
    runtime_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "version": self.version,
            "sample_sha256": self.sample_sha256,
            "status": self.status.value,
            "artifacts": [a.to_dict() for a in self.artifacts],
            "summary": self.summary,
            "errors": self.errors,
            "runtime_ms": self.runtime_ms,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


@dataclass
class SampleInfo:
    """样本基本信息"""
    path: str
    sha256: str
    md5: str
    sha1: str
    file_type: str = ""
    architecture: str = ""
    size: int = 0

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "md5": self.md5,
            "sha1": self.sha1,
            "file_type": self.file_type,
            "architecture": self.architecture,
            "size": self.size,
        }


@dataclass
class AnalysisResult:
    """完整分析结果"""
    sample: SampleInfo
    tool_results: list[ToolResult] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "sample": self.sample.to_dict(),
            "tool_results": [r.to_dict() for r in self.tool_results],
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


def compute_hashes(file_path: str) -> dict:
    """计算文件 hash"""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": path.stat().st_size,
    }
