"""
R2 / Rizin lightweight analysis tool.

Uses r2 in headless mode for quick static triage without Ghidra.
Provides: functions list, strings, imports, decompilation.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from .base import BaseTool
from ..schema import ToolResult, ToolStatus, Artifact, ArtifactType


class R2Tool(BaseTool):
    """R2/Rizin headless analysis tool"""

    name = "r2"
    version = "0.1.0"

    def run(self, sample_path: str, sample_sha256: str) -> ToolResult:
        sample = Path(sample_path).resolve()
        artifacts: list[Artifact] = []
        errors: list[str] = []

        if not sample.exists():
            return ToolResult(
                tool=self.name, version=self.version,
                sample_sha256=sample_sha256, status=ToolStatus.FAILED,
                errors=[f"File not found: {sample_path}"],
            )

        # Check r2 availability
        try:
            subprocess.run(["r2", "-v"], capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ToolResult(
                tool=self.name, version=self.version,
                sample_sha256=sample_sha256, status=ToolStatus.SKIPPED,
                summary="r2 not available",
            )

        # 1. Function list
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "aaa;aflj", str(sample)],
                capture_output=True, text=True, timeout=60,
            )
            if proc.stdout.strip():
                try:
                    func_data = json.loads(proc.stdout)
                    # Convert to list of {name, address, size}
                    func_list = []
                    for f in func_data:
                        func_list.append({
                            "name": f.get("name", "?"),
                            "address": f.get("offset", 0),
                            "size": f.get("size", 0),
                        })
                    func_path = self.output_dir / "functions_r2.json"
                    func_path.write_text(
                        json.dumps(func_list, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    artifacts.append(Artifact(
                        type=ArtifactType.FUNCTIONS,
                        path=str(func_path),
                        name="r2_functions",
                    ))
                except json.JSONDecodeError:
                    errors.append("Failed to parse r2 JSON output")
        except subprocess.TimeoutExpired:
            errors.append("r2 function analysis timed out")

        # 2. Strings
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "izzj", str(sample)],
                capture_output=True, text=True, timeout=30,
            )
            if proc.stdout.strip():
                try:
                    str_data = json.loads(proc.stdout)
                    str_list = []
                    for s in str_data:
                        if isinstance(s, dict):
                            str_list.append(s.get("string", ""))
                        else:
                            str_list.append(str(s))
                    str_path = self.output_dir / "strings_r2.json"
                    str_path.write_text(
                        json.dumps(str_list, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    artifacts.append(Artifact(
                        type=ArtifactType.STRINGS,
                        path=str(str_path),
                        name="r2_strings",
                    ))
                except json.JSONDecodeError:
                    errors.append("Failed to parse r2 strings JSON")
        except subprocess.TimeoutExpired:
            errors.append("r2 strings extraction timed out")

        # 3. Imports
        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", "iij", str(sample)],
                capture_output=True, text=True, timeout=30,
            )
            if proc.stdout.strip():
                try:
                    imp_data = json.loads(proc.stdout)
                    imp_list = []
                    for imp in imp_data:
                        if isinstance(imp, dict):
                            imp_list.append(f"{imp.get('name', '?')}  [{imp.get('libname', '?')}]")
                        else:
                            imp_list.append(str(imp))
                    imp_path = self.output_dir / "imports_r2.json"
                    imp_path.write_text(
                        json.dumps(imp_list, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    artifacts.append(Artifact(
                        type=ArtifactType.IMPORTS,
                        path=str(imp_path),
                        name="r2_imports",
                    ))
                except json.JSONDecodeError:
                    errors.append("Failed to parse r2 imports JSON")
        except subprocess.TimeoutExpired:
            errors.append("r2 imports extraction timed out")

        status = ToolStatus.SUCCESS if not errors else ToolStatus.PARTIAL
        return ToolResult(
            tool=self.name, version=self.version,
            sample_sha256=sample_sha256, status=status,
            artifacts=artifacts,
            summary=f"r2: {len(artifacts)} artifact(s)",
            errors=errors,
        )
