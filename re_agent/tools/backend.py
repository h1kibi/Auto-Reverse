"""
Reverse Backend Protocol

Unified interface for multiple reverse engineering backends:
- Ghidra (default, headless)
- r2/Rizin (lightweight, CI-friendly)
- Binary Ninja (premium, IL-level)

The tool layer calls into backends; solvers consume evidence from backends.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable


@dataclass
class BackendFunction:
    """Unified function representation across backends"""
    name: str
    address: int
    size: int | None = None
    tags: list[str] = field(default_factory=list)
    calls: list[int] = field(default_factory=list)
    xrefs_from: list[int] = field(default_factory=list)
    xrefs_to: list[int] = field(default_factory=list)
    decompile_artifact: str | None = None


@dataclass
class BackendString:
    """Unified string representation"""
    value: str
    address: int | None = None
    encoding: str | None = None
    xrefs: list[int] = field(default_factory=list)


@dataclass
class BackendImport:
    """Unified import representation"""
    name: str
    library: str | None = None
    address: int | None = None


@dataclass
class BackendAnalysis:
    """Complete backend analysis result"""
    functions: list[BackendFunction] = field(default_factory=list)
    strings: list[BackendString] = field(default_factory=list)
    imports: list[BackendImport] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)
    entry_point: int | None = None
    base_address: int | None = None
    architecture: str = ""
    bits: int = 64
    endian: str = "little"


@runtime_checkable
class ReverseBackend(Protocol):
    """Protocol for reverse engineering backends"""

    name: str

    def analyze(self, sample: Path) -> dict: ...
    def list_functions(self) -> list[dict]: ...
    def decompile(self, function: str | int) -> str: ...
    def get_xrefs_to(self, address: int) -> list[int]: ...
    def get_strings(self) -> list[dict]: ...
    def get_imports(self) -> list[dict]: ...
    def get_cfg(self, function: str | int) -> dict: ...


class BaseBackend(ABC):
    """Base class for reverse engineering backends"""

    name: str = "base"
    sample_path: str = ""
    output_dir: str = ""

    @abstractmethod
    def analyze(self, sample: Path, output_dir: Path) -> BackendAnalysis:
        """Perform full analysis and return structured results"""
        ...

    @abstractmethod
    def decompile(self, function: str) -> str:
        """Decompile a function by name or address"""
        ...

    def get_xrefs_to(self, address: int) -> list[int]:
        """Get cross-references to an address"""
        return []

    def get_strings(self) -> list[BackendString]:
        """Get strings from the binary"""
        return []

    def get_imports(self) -> list[BackendImport]:
        """Get imports from the binary"""
        return []

    def get_cfg(self, function: str) -> dict:
        """Get control flow graph for a function"""
        return {}

    def close(self):
        """Cleanup resources"""
        pass


class QuickBackend(BaseBackend):
    """Lightweight backend using strings + pefile/readelf (no heavy decompiler)"""

    name = "quick"

    def analyze(self, sample: Path, output_dir: Path) -> BackendAnalysis:
        import subprocess

        result = BackendAnalysis()
        result.functions = []
        result.strings = []
        result.imports = []

        # Strings
        try:
            proc = subprocess.run(
                ["strings", str(sample)],
                capture_output=True, text=True, timeout=30,
            )
            for i, line in enumerate(proc.stdout.split("\n")):
                line = line.strip()
                if line:
                    result.strings.append(BackendString(value=line))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return result

    def decompile(self, function: str) -> str:
        return ""


class GhidraBackend(BaseBackend):
    """Ghidra headless backend"""

    name = "ghidra"
    ghidra_home: str | None = None

    def analyze(self, sample: Path, output_dir: Path) -> BackendAnalysis:
        from ..tools.ghidra_tool import GhidraTool
        tool = GhidraTool(str(output_dir), self.ghidra_home)
        # Returns ToolResult; evidence extraction happens in profiler
        return BackendAnalysis()

    def decompile(self, function: str) -> str:
        return ""


class R2Backend(BaseBackend):
    """R2/Rizin lightweight backend - produces full BackendAnalysis"""

    name = "r2"

    def analyze(self, sample: Path, output_dir: Path) -> BackendAnalysis:
        import subprocess

        result = BackendAnalysis()
        result.architecture = "x86_64"
        result.bits = 64
        result.endian = "little"

        # Entry point
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "iej", str(sample)],
                capture_output=True, text=True, timeout=30,
            )
            if proc.stdout.strip():
                data = json.loads(proc.stdout)
                if isinstance(data, list):
                    for entry in data:
                        if isinstance(entry, dict) and entry.get("vaddr"):
                            result.entry_point = entry["vaddr"]
                            result.base_address = entry.get("baddr", 0)
                            break
        except Exception:
            pass

        # Functions
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "aaa;aflj", str(sample)],
                capture_output=True, text=True, timeout=60,
            )
            if proc.stdout.strip():
                data = json.loads(proc.stdout)
                if isinstance(data, list):
                    for f in data:
                        if isinstance(f, dict):
                            result.functions.append(BackendFunction(
                                name=f.get("name", "?"),
                                address=f.get("offset", 0),
                                size=f.get("size"),
                            ))
        except Exception:
            pass

        # Strings
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "izzj", str(sample)],
                capture_output=True, text=True, timeout=30,
            )
            if proc.stdout.strip():
                data = json.loads(proc.stdout)
                if isinstance(data, list):
                    for s in data:
                        if isinstance(s, dict):
                            val = s.get("string", "")
                            if val and len(val) >= 3:
                                result.strings.append(BackendString(
                                    value=val,
                                    address=s.get("paddr"),
                                ))
        except Exception:
            pass

        # Imports
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "iij", str(sample)],
                capture_output=True, text=True, timeout=30,
            )
            if proc.stdout.strip():
                data = json.loads(proc.stdout)
                if isinstance(data, list):
                    for imp in data:
                        if isinstance(imp, dict):
                            result.imports.append(BackendImport(
                                name=imp.get("name", "?"),
                                library=imp.get("libname"),
                            ))
        except Exception:
            pass

        # Sections
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "iSj", str(sample)],
                capture_output=True, text=True, timeout=30,
            )
            if proc.stdout.strip():
                data = json.loads(proc.stdout)
                if isinstance(data, list):
                    for sec in data:
                        if isinstance(sec, dict):
                            result.sections.append({
                                "name": sec.get("name", "?"),
                                "vaddr": sec.get("vaddr", 0),
                                "vsize": sec.get("vsize", 0),
                            })
        except Exception:
            pass

        # Architecture detection
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "e asm.arch;e asm.bits", str(sample)],
                capture_output=True, text=True, timeout=10,
            )
            lines = proc.stdout.strip().split("\n")
            if len(lines) >= 2:
                result.architecture = lines[0].strip()
                try:
                    result.bits = int(lines[1].strip())
                except ValueError:
                    pass
        except Exception:
            pass

        return result

    def decompile(self, function: str) -> str:
        import subprocess
        try:
            sample = Path(self.sample_path)
            proc = subprocess.run(
                ["r2", "-q", "-c", f"aaa;pdf @ {function}", str(sample)],
                capture_output=True, text=True, timeout=30,
            )
            return proc.stdout[:5000]
        except Exception:
            return ""


class ObjdumpBackend(BaseBackend):
    """Objdump-based fallback backend"""
    name = "objdump"

    def analyze(self, sample: Path, output_dir: Path) -> BackendAnalysis:
        return BackendAnalysis()

    def decompile(self, function: str) -> str:
        return ""


class FakeBackend(BaseBackend):
    """CI-friendly fake backend (no real tool dependencies)"""

    name = "fake"

    def analyze(self, sample: Path, output_dir: Path) -> BackendAnalysis:
        result = BackendAnalysis()
        result.functions = [
            BackendFunction(name="main", address=0x401000, size=100),
            BackendFunction(name="check_flag", address=0x401200, size=80),
        ]
        result.strings = [
            BackendString(value="Correct!", address=0x402000),
            BackendString(value="Wrong!", address=0x402010),
            BackendString(value="flag{fake_test}", address=0x402020),
        ]
        result.imports = [
            BackendImport(name="strcmp", library="libc.so.6"),
            BackendImport(name="printf", library="libc.so.6"),
        ]
        result.entry_point = 0x401000
        return result

    def decompile(self, function: str) -> str:
        if function == "main":
            return "int main() { check_flag(input); return 0; }"
        if function == "check_flag":
            return "int check_flag(char* s) { if(strcmp(s, 'flag{fake_test}')==0) return 1; return 0; }"
        return ""


@dataclass
class BackendConfig:
    """Backend selection configuration"""
    quick: bool = True
    ghidra: bool = False
    r2: bool = True
    objdump: bool = False
    fake: bool = False
    binary_ninja: bool = False
    ghidra_home: str | None = None


ALLOWED_R2_ACTIONS: set[str] = {
    "list_functions",
    "list_strings",
    "get_xrefs",
    "disassemble_function",
    "decompile_if_available",
    "emulate_basic_block",
}


def get_backend(config: BackendConfig, sample_path: str, output_dir: str) -> BaseBackend:
    """Factory: select the best available backend"""
    backends: list[BaseBackend] = []

    if config.quick:
        backends.append(QuickBackend())

    if config.ghidra:
        backend = GhidraBackend()
        backend.ghidra_home = config.ghidra_home
        backends.append(backend)

    if config.r2:
        backends.append(R2Backend())

    for backend in backends:
        backend.sample_path = sample_path
        backend.output_dir = output_dir

    return backends[0] if backends else QuickBackend()
