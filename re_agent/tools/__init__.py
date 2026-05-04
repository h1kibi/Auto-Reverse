"""
工具集 - 逆向分析工具适配器 + 多后端接口 + GDB/R2 工具
"""

from .base import BaseTool
from .file_tool import FileTool
from .strings_tool import StringsTool
from .readelf_tool import ReadelfTool
from .objdump_tool import ObjdumpTool
from .yara_tool import YaraTool
from .ghidra_tool import GhidraTool
from .r2_tool import R2Tool
from .gdb_tool import GDBTool
from .pefile_tool import PEFileTool, HAS_PEFILE
from .backend import (
    ReverseBackend, BaseBackend, BackendAnalysis,
    QuickBackend, GhidraBackend, R2Backend, ObjdumpBackend, FakeBackend,
    BackendConfig, get_backend, ALLOWED_R2_ACTIONS, R2_COMMANDS,
    validate_r2_target, R2_TARGET_RE,
    BackendFunction, BackendString, BackendImport,
)

__all__ = [
    "BaseTool", "FileTool", "StringsTool", "ReadelfTool",
    "ObjdumpTool", "YaraTool", "GhidraTool", "R2Tool", "GDBTool",
    "PEFileTool", "HAS_PEFILE",
    "ReverseBackend", "BaseBackend", "BackendAnalysis",
    "QuickBackend", "GhidraBackend", "R2Backend", "ObjdumpBackend", "FakeBackend",
    "BackendConfig", "get_backend", "ALLOWED_R2_ACTIONS", "R2_COMMANDS",
    "validate_r2_target", "R2_TARGET_RE",
    "BackendFunction", "BackendString", "BackendImport",
]
