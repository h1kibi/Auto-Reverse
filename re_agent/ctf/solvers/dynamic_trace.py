"""
Dynamic Trace Solver (v0.5.2)

Sandbox-only. Supports argv/stdin probe channels.
Uses ctx.output_dir (not sample.parent). CompareEvent-ready.
"""

from pathlib import Path
from dataclasses import dataclass

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


COMPARISON_FUNCTIONS = [
    "strcmp", "strncmp", "memcmp", "wcscmp",
    "strcasecmp", "strncasecmp", "strstr",
]

PROBE_INPUTS: list[bytes] = [
    b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    b"flag{AAAAAAAAAAAAAAAAAAAAAAAAAA}",
    b"00000000000000000000000000000000",
    b"testtesttesttesttesttesttesttest",
    b"A" * 64,
    b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
]


@dataclass
class CompareEvent:
    source: str
    function: str
    input_channel: str
    probe: str
    arg0_preview: str = ""
    arg1_preview: str = ""
    n: int | None = None
    return_value: int | None = None
    raw_line: str = ""
    evidence_artifact: str | None = None


class DynamicTraceSolver(BaseSolver):
    name = "dynamic_trace"

    def score(self, ctx: SolverContext) -> float:
        profile = ctx.profile
        if not profile:
            return 0.0
        score = 0.0
        if profile.comparison_hints: score += 0.40
        if profile.has_success_string or profile.has_failure_string: score += 0.30
        if profile.input_channels: score += 0.10
        if profile.protections:
            if "anti_debug" in profile.protections: score -= 0.20
            if "packed_upx" in profile.protections: score -= 0.15
        return min(max(score, 0.0), 1.0)

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        candidates: list[FlagCandidate] = []
        channels = ctx.profile.input_channels if ctx.profile.input_channels else ["argv"]

        for channel in channels:
            if channel not in ("argv", "stdin"):
                continue
            for tool in ("ltrace",):
                try:
                    result = self._trace_channel(ctx, tool, channel)
                    candidates.extend(result)
                except Exception:
                    continue
                if len(candidates) >= 3:
                    break
            if len(candidates) >= 3:
                break

        return candidates

    def _trace_channel(self, ctx: SolverContext, tool: str, channel: str) -> list[FlagCandidate]:
        sample = ctx.profile.sample_path.resolve()
        if not sample.exists():
            return []
        timeout = min(ctx.timeout or 10, 10)
        candidates: list[FlagCandidate] = []
        seen: set[str] = set()

        for probe_bytes in PROBE_INPUTS[:4]:
            try:
                probe_text = probe_bytes.decode("utf-8", errors="replace")
            except Exception:
                continue

            events = self._run_ltrace_channel(ctx, sample, probe_text, channel, timeout)

            for evt in events:
                extracted = self._candidate_from_event(evt)
                if extracted and extracted not in seen and 4 <= len(extracted) <= 256:
                    seen.add(extracted)
                    candidates.append(FlagCandidate(
                        value=extracted,
                        source=f"dynamic_trace:ltrace:{evt.function}",
                        confidence=0.95,
                        input_channel=evt.input_channel,
                        evidence=[
                            f"ltrace captured {evt.function} via {channel}",
                            f"raw={evt.raw_line[:240]}",
                        ],
                    ))

        return candidates

    def _run_ltrace_channel(self, ctx, sample, probe, channel, timeout):
        try:
            from ...sandbox import DockerSandbox, DockerSandboxConfig
            config = DockerSandboxConfig(timeout=timeout)
            sandbox = DockerSandbox(config)
        except Exception:
            return []

        if channel == "argv":
            result = sandbox.run_tool_with_sample(
                sample_path=sample,
                tool_argv=["ltrace", "-e", "+strcmp+strncmp+memcmp+strlen",
                           "/input/sample", probe],
                output_dir=ctx.output_dir,
            )
        elif channel == "stdin":
            result = sandbox.run_tool_with_sample(
                sample_path=sample,
                tool_argv=["ltrace", "-e", "+strcmp+strncmp+memcmp+strlen",
                           "/input/sample"],
                stdin=(probe + "\n").encode(),
                output_dir=ctx.output_dir,
            )
        else:
            return []

        if not result:
            return []
        return _parse_compare_events(
            (result.stderr + "\n" + result.stdout).split("\n"),
            probe=probe, channel=channel,
        )

    @staticmethod
    def _candidate_from_event(evt: CompareEvent) -> str | None:
        sides = [evt.arg0_preview, evt.arg1_preview]
        if evt.probe not in sides:
            return None
        other = sides[1] if sides[0] == evt.probe else sides[0]
        if not other or len(other) < 4:
            return None
        pr = sum(32 <= ord(c) <= 126 or c in "\n\r\t" for c in other) / max(len(other), 1)
        if pr < 0.6:
            return None
        low = other.lower()
        if any(k in low for k in ("flag", "ctf", "{", "}", "correct", "wrong", "key", "pass")):
            return other
        return other


def _parse_compare_events(lines, probe, channel):
    events = []
    for line in lines:
        if not line or "(" not in line:
            continue
        for func in COMPARISON_FUNCTIONS:
            if func not in line:
                continue
            try:
                paren = line.index("(")
                args_raw = line[paren + 1:]
                depth, end = 0, 0
                for i, ch in enumerate(args_raw):
                    if ch == "(": depth += 1
                    elif ch == ")":
                        if depth == 0: end = i; break
                        depth -= 1
                args_part = args_raw[:end]
                parts, in_q, cur = [], False, ""
                for ch in args_part:
                    if ch in ('"', "'"):
                        if in_q: parts.append(cur); cur = ""
                        in_q = not in_q; continue
                    if in_q: cur += ch; continue
                if cur: parts.append(cur)
                args = [p.strip().strip('"') for p in parts if p.strip()]
                while len(args) < 2: args.append("")
                events.append(CompareEvent(
                    source="ltrace", function=func, input_channel=channel,
                    probe=probe, arg0_preview=args[0] if len(args) > 0 else "",
                    arg1_preview=args[1] if len(args) > 1 else "",
                    raw_line=line[:240],
                ))
                break
            except Exception:
                continue
    return events
