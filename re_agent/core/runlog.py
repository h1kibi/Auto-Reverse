"""
Solve Trace - structured logging for audit and replay.

Every solver step, tool call, and verification is recorded in JSONL format.
"""

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime


@dataclass
class TraceEvent:
    """Single event in a solve trace"""
    event: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    step: int = 0
    solver: str | None = None
    tool: str | None = None
    score: float | None = None
    candidates: list[str] = field(default_factory=list)
    verified: bool = False
    error: str | None = None
    artifacts: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


class SolveTrace:
    """Structured solve trace writer"""

    def __init__(self, output_dir: Path, run_id: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.trace_path = self.output_dir / "solve_trace.jsonl"
        self.report_path = self.output_dir / "report.md"

    def log(self, event: TraceEvent) -> None:
        """Append an event to the trace"""
        data = asdict(event)
        data["run_id"] = self.run_id
        with self.trace_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def log_start(self, sample_path: str, config: dict) -> None:
        self.log(TraceEvent(event="solve_start", extra={
            "sample_path": sample_path,
            "config": config,
        }))

    def log_solver_start(self, step: int, solver: str, score: float) -> None:
        self.log(TraceEvent(event="solver_start", step=step, solver=solver, score=score))

    def log_solver_skip(self, step: int, solver: str, reason: str) -> None:
        self.log(TraceEvent(event="solver_skip", step=step, solver=solver, extra={"reason": reason}))

    def log_solver_done(self, step: int, solver: str, candidates: list[str]) -> None:
        self.log(TraceEvent(event="solver_done", step=step, solver=solver, candidates=candidates))

    def log_solver_error(self, step: int, solver: str, error: str) -> None:
        self.log(TraceEvent(event="solver_error", step=step, solver=solver, error=error))

    def log_tool_call(self, step: int, tool: str, artifacts: list[str]) -> None:
        self.log(TraceEvent(event="tool_call", step=step, tool=tool, artifacts=artifacts))

    def log_verification(self, step: int, candidate: str, accepted: bool, mode: str) -> None:
        self.log(TraceEvent(event="verification", step=step, candidates=[candidate], verified=accepted, extra={"mode": mode}))

    def log_solve_end(self, step: int, solved: bool, method: str, best_flag: str | None) -> None:
        self.log(TraceEvent(event="solve_end", step=step, verified=solved, solver=method, candidates=[best_flag] if best_flag else []))

    def write_report(self, profile: dict, result: dict, solver_runs: list[dict]) -> None:
        """Generate a human-readable markdown report"""
        solved = result.get("verified", False)
        winning = result.get("winning_candidate", {})
        candidates = result.get("candidates", [])

        lines = [
            "# Auto-Reverse Solve Report",
            "",
            "## Summary",
            f"- **Verified**: {solved}",
            f"- **Status**: {result.get('status', 'unknown')}",
            f"- **Method**: {result.get('method', '-')}",
        ]

        if winning:
            lines.append(f"- **Winning solver**: {winning.get('source', '-')}")
            lines.append(f"- **Input channel**: {winning.get('input_channel', winning.get('validation_mode', '-'))}")

        lines.extend([
            "",
            "## Challenge Profile",
            f"- File type: {profile.get('file_type', '-')}",
            f"- Architecture: {profile.get('architecture', '-')}",
            f"- Tags: {', '.join(profile.get('tags', []))}",
            f"- Success strings: {len(profile.get('success_strings', []))}",
            f"- Failure strings: {len(profile.get('failure_strings', []))}",
        ])

        if profile.get("input_channels"):
            lines.append(f"- Input channels: {', '.join(profile['input_channels'])}")
        if profile.get("comparison_hints"):
            lines.append(f"- Comparison hints: {', '.join(profile['comparison_hints'])}")
        if profile.get("protections"):
            lines.append(f"- Protections: {', '.join(profile['protections'])}")

        lines.extend([
            "",
            "## Solver Timeline",
            "| Step | Solver | Status | Score | Candidates |",
            "|------|--------|--------|-------|------------|",
        ])

        for i, sr in enumerate(solver_runs, 1):
            status = sr.get("status", "?")
            name = sr.get("solver", "?")
            score = sr.get("score", 0)
            count = len(sr.get("candidates", []))
            lines.append(f"| {i} | {name} | {status} | {score:.2f} | {count} |")

        if candidates:
            lines.extend([
                "",
                "## Candidates",
            ])
            for i, c in enumerate(candidates[:20], 1):
                verified_mark = " [VERIFIED]" if c.get("verified") else ""
                lines.append(f"{i}. `{c.get('value', '')}` (source: {c.get('source', '-')}, confidence: {c.get('confidence', 0):.0%}){verified_mark}")

        self.report_path.write_text("\n".join(lines), encoding="utf-8")
