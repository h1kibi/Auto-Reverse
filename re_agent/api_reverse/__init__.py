"""
API Reverse Mode - program interface inference.

Not CTF flag solving, but recovering function prototypes,
generating harnesses, and inferring protocols from binaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class InferredFunction:
    address: str
    original_name: str | None = None
    likely_name: str = ""
    prototype: str = ""
    calling_convention: str | None = None
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    harness_path: str | None = None


@dataclass
class APIReverseResult:
    sample_sha256: str = ""
    exported_functions: list[InferredFunction] = field(default_factory=list)
    internal_candidates: list[InferredFunction] = field(default_factory=list)
    protocols: list[dict] = field(default_factory=list)
    generated_harnesses: list[str] = field(default_factory=list)
    report_path: str = ""


def analyze_exports(sample_path: Path, output_dir: Path) -> APIReverseResult:
    """Analyze exported functions from a binary (DLL/SO)"""

    from ..tools.backend import R2Backend
    backend = R2Backend()
    backend.sample_path = str(sample_path)

    result = APIReverseResult()

    try:
        import subprocess, hashlib
        sha = hashlib.sha256(sample_path.read_bytes()).hexdigest()
        result.sample_sha256 = sha

        # Use R2 to list exports
        proc = subprocess.run(
            ["r2", "-q", "-c", "iej", str(sample_path)],
            capture_output=True, text=True, timeout=30,
        )
        import json
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        result.exported_functions.append(InferredFunction(
                            address=hex(entry.get("vaddr", 0)),
                            original_name=entry.get("name"),
                            likely_name=entry.get("name", "unknown"),
                            prototype=f"unknown {entry.get('name', 'unknown')}()",
                            confidence=0.7,
                        ))
    except Exception:
        pass

    return result


def generate_ctypes_harness(func_name: str, sample_path: Path, output_dir: Path) -> Path | None:
    """Generate a ctypes Python harness stub for a function"""

    harness = f'''"""
Auto-generated ctypes harness for {func_name}
from {sample_path.name}
"""

import ctypes
import sys

lib = ctypes.CDLL("{sample_path.absolute()}")


def call_{func_name}(*args):
    \"\"\"Call {func_name} with given arguments\"\"\"
    func = getattr(lib, "{func_name}", None)
    if func is None:
        print("Function {func_name} not found")
        return None
    # TODO: set correct argtypes/restype
    result = func(*args)
    return result


if __name__ == "__main__":
    print("Calling {func_name}...")
    result = call_{func_name}()
    print(f"Result: {{result}}")
'''

    path = output_dir / f"harness_{func_name}.py"
    path.write_text(harness, encoding="utf-8")
    return path
