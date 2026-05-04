"""
GDB dynamic analysis tool.

Provides: breakpoint-based comparison hooking, call tracing.
Fallback when Frida/ltrace not available.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .base import BaseTool
from ..schema import ToolResult, ToolStatus, Artifact, ArtifactType


GDB_SCRIPT_TEMPLATE = r"""
set pagination off
set confirm off

# Break on comparison functions
break strcmp
break strncmp
break memcmp

# Print args
commands 1-3
  silent
  printf "GDB|%s|%s|%s\n", $_streq($rip, strcmp) ? "strcmp" : ($_streq($rip, strncmp) ? "strncmp" : "memcmp"), (char*)$rdi, (char*)$rsi
  continue
end

run {probe}
quit
"""


class GDBTool(BaseTool):
    """GDB-based dynamic analysis"""

    name = "gdb"
    version = "0.1.0"

    COMPARE_HOOKS = ["strcmp", "strncmp", "memcmp", "strlen"]

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

        try:
            subprocess.run(["gdb", "--version"], capture_output=True, timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ToolResult(
                tool=self.name, version=self.version,
                sample_sha256=sample_sha256, status=ToolStatus.SKIPPED,
                summary="gdb not available",
            )

        # Build GDB commands
        commands = ["set pagination off", "set confirm off"]
        for func in self.COMPARE_HOOKS:
            commands.append(f"break {func}")
            commands.append("commands")
            commands.append("  silent")
            commands.append(f"  printf \"GDB|{func}|%s|%s\\n\", (char*)$rdi, (char*)$rsi")
            commands.append("  continue")
            commands.append("end")

        # Probe inputs
        probes = [b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", b"flag{AAAAAAAAAAAAAAAAAAAAAAAAAA}"]
        all_output: list[str] = []

        for probe_bytes in probes:
            probe = probe_bytes.decode("utf-8", errors="replace")
            commands.append(f"run {probe}")
            commands.append("quit")

            gdb_input = "\n".join(commands)

            try:
                proc = subprocess.run(
                    ["gdb", "-batch", "-x", "/dev/stdin", str(sample)],
                    input=gdb_input.encode(),
                    capture_output=True, text=True, timeout=15,
                )
                all_output.extend(proc.stdout.split("\n"))
            except subprocess.TimeoutExpired:
                errors.append("gdb timed out")
            except FileNotFoundError:
                return ToolResult(
                    tool=self.name, version=self.version,
                    sample_sha256=sample_sha256, status=ToolStatus.SKIPPED,
                    summary="gdb not available",
                )

        # Parse GDB output for comparison arguments
        extracted = []
        for line in all_output:
            if not line.startswith("GDB|"):
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                func_name = parts[1]
                arg0 = parts[2].strip()
                arg1 = parts[3].strip()
                extracted.append({
                    "function": func_name,
                    "arg0": arg0,
                    "arg1": arg1,
                })

        if extracted:
            out_path = self.output_dir / "gdb_comparisons.json"
            import json
            out_path.write_text(
                json.dumps(extracted, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            artifacts.append(Artifact(
                type=ArtifactType.FUNCTIONS,
                path=str(out_path),
                name="gdb_comparisons",
            ))

        status = ToolStatus.SUCCESS if extracted else ToolStatus.PARTIAL
        return ToolResult(
            tool=self.name, version=self.version,
            sample_sha256=sample_sha256, status=status,
            artifacts=artifacts,
            summary=f"gdb: {len(extracted)} comparison(s) captured",
            errors=errors,
        )
