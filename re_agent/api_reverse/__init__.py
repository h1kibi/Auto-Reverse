"""
API Reverse Mode v2 - Integuru-style runnable output.

OGhidra-style auto-routing + Integuru-style dependency graph + harness validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class InferredArgument:
    index: int
    type: str
    role: str | None = None
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)


@dataclass
class InferredFunction:
    address: str
    original_name: str | None = None
    likely_name: str = ""
    prototype: str = ""
    calling_convention: str | None = None
    args: list[InferredArgument] = field(default_factory=list)
    return_type: str = "unknown"
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    harness_path: str | None = None
    validation_status: str | None = None
    dependencies: list[str] = field(default_factory=list)  # Integuru-style: dependency graph


@dataclass
class APIReverseResult:
    sample_sha256: str = ""
    exported_functions: list[InferredFunction] = field(default_factory=list)
    internal_candidates: list[InferredFunction] = field(default_factory=list)
    dependency_graph: dict[str, list[str]] = field(default_factory=dict)  # Integuru-style
    protocols: list[dict] = field(default_factory=list)
    generated_harnesses: list[str] = field(default_factory=list)
    validation_results: list[dict] = field(default_factory=list)
    report_path: str = ""


def analyze_exports(sample_path: Path, output_dir: Path) -> APIReverseResult:
    """Analyze exported functions + build dependency graph (Integuru-style)."""
    import subprocess, json, hashlib

    sha = hashlib.sha256(sample_path.read_bytes()).hexdigest()
    result = APIReverseResult(sample_sha256=sha)

    try:
        proc = subprocess.run(
            ["r2", "-q", "-c", "iej", str(sample_path)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        func = InferredFunction(
                            address=hex(entry.get("vaddr", 0)),
                            original_name=entry.get("name"),
                            likely_name=entry.get("name", "unknown"),
                            prototype=f"unknown {entry.get('name', 'unknown')}()",
                            confidence=0.7,
                            dependencies=[],
                        )
                        result.exported_functions.append(func)
    except Exception:
        pass

    # Build dependency graph: for each function, find its callees
    for func in result.exported_functions:
        deps = _find_callees(sample_path, func.likely_name) if func.likely_name else []
        func.dependencies = deps
        if deps:
            result.dependency_graph[func.likely_name] = deps

    return result


def _find_callees(sample_path: Path, function_name: str) -> list[str]:
    """Find function calls within a function (Integuru-style dependency resolution)."""
    import subprocess
    try:
        proc = subprocess.run(
            ["r2", "-q", "-c", f"aaa;axtj @ {function_name}", str(sample_path)],
            capture_output=True, text=True, timeout=15, check=False,
        )
        deps = []
        for line in proc.stdout.split("\n"):
            line = line.strip()
            if line and not line.startswith("["):
                deps.append(line.split()[-1] if line.split() else line)
        return deps[:10]
    except Exception:
        return []


def generate_ctypes_harness(func: InferredFunction, sample_path: Path, output_dir: Path) -> Path | None:
    """Generate a ctypes harness with dependency resolution (Integuru-style)."""
    deps_code = ""
    if func.dependencies:
        deps_code = "\n# Dependencies: " + ", ".join(func.dependencies)

    harness = f'''
"""Generated harness for {func.likely_name} from {sample_path.name}{deps_code}"""

import ctypes
import sys

lib = None
try:
    lib = ctypes.CDLL("{sample_path.absolute()}")
except OSError as e:
    print(f"Failed to load library: {{e}}", file=sys.stderr)


def call_{func.likely_name}(*args):
    """Call {func.likely_name} with arguments"""
    if lib is None:
        return None
    func = getattr(lib, "{func.likely_name}", None)
    if func is None:
        print(f"Function {func.likely_name} not found in library", file=sys.stderr)
        return None
    try:
        return func(*args)
    except Exception as e:
        print(f"Call to {func.likely_name} failed: {{e}}", file=sys.stderr)
        return None


def validate_harness():
    """Integuru-style: validate harness loads correctly."""
    if lib is None:
        return {{"status": "error", "reason": "library_load_failed"}}
    func = getattr(lib, "{func.likely_name}", None)
    if func is None:
        return {{"status": "error", "reason": "function_not_found"}}
    return {{"status": "ok", "function": "{func.likely_name}"}}


if __name__ == "__main__":
    result = validate_harness()
    print(result)
    if result["status"] == "ok":
        print("Harness loaded. Use call_{func.likely_name}() to invoke.")
'''

    path = output_dir / f"harness_{func.likely_name}.py"
    path.write_text(harness, encoding="utf-8")
    return path


def validate_harness(harness_path: Path, timeout: int = 5) -> dict:
    """Integuru-style: validate harness actually runs."""
    import subprocess
    try:
        proc = subprocess.run(
            ["python", str(harness_path)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        output = proc.stdout.strip()
        import json
        try:
            return json.loads(output.replace("'", '"'))
        except json.JSONDecodeError:
            return {"status": "partial", "output": output[:200]}
    except Exception as e:
        return {"status": "error", "reason": str(e)}
