"""
Flag Validator (v2)

Multi-signal oracle:
- success/failure pattern matching
- exit code analysis
- timing differential (optional)
- output pattern analysis
- confidence scoring
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..sandbox import DockerSandbox, DockerSandboxConfig


SUCCESS_PATTERNS = [
    r"\bcorrect\b", r"\bsuccess\b", r"\baccepted\b",
    r"congrat", r"good job", r"you win", r"well done",
    r"hooray", r"flag is", r"right",
]

FAILURE_PATTERNS = [
    r"\bwrong\b", r"\bincorrect\b", r"\bfailed?\b",
    r"\binvalid\b", r"try again", r"nope", r"\bbad\b",
    r"you lose", r"incorrect flag",
]


@dataclass
class OracleResult:
    """Multi-signal oracle evaluation result"""
    accepted: bool
    confidence: float
    reasons: list[str] = field(default_factory=list)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    exit_code: int | None = None
    timed_out: bool = False


@dataclass
class ValidationResult:
    """Validation result (backward compatible)"""
    accepted: bool
    candidate: str
    mode: str
    exit_code: int | None
    stdout: str
    stderr: str
    matched_success: bool
    matched_failure: bool
    command: str
    evidence: list[str]
    oracle: OracleResult | None = None
    confidence: float = 0.0


class OutputOracle:
    """Multi-signal output oracle"""

    def __init__(
        self,
        success_patterns: list[str] | None = None,
        failure_patterns: list[str] | None = None,
    ):
        self.success_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (success_patterns or SUCCESS_PATTERNS)
        ]
        self.failure_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (failure_patterns or FAILURE_PATTERNS)
        ]

    def evaluate(self, stdout: str, stderr: str, exit_code: int | None, timed_out: bool = False) -> OracleResult:
        return self._evaluate(stdout, stderr, exit_code, timed_out)

    def evaluate_differential(
        self,
        candidate_stdout: str,
        candidate_stderr: str,
        wrong_stdout: str,
        wrong_stderr: str,
        exit_code: int | None,
    ) -> OracleResult:
        """Differential oracle: compare candidate output vs wrong-input output."""
        r = self._evaluate(candidate_stdout, candidate_stderr, exit_code)
        if not r.accepted:
            return r

        if candidate_stdout.strip() != wrong_stdout.strip():
            r.reasons.append("output_different_from_wrong_input")
            r.confidence = min(1.0, r.confidence + 0.1)
            r.accepted = r.confidence >= 0.7
        if candidate_stderr.strip() != wrong_stderr.strip():
            r.reasons.append("stderr_different_from_wrong_input")
            r.confidence = min(1.0, r.confidence + 0.05)
            r.accepted = r.confidence >= 0.7

        return r

    def _evaluate(self, stdout: str, stderr: str, exit_code: int | None, timed_out: bool = False) -> OracleResult:
        reasons: list[str] = []
        score = 0.0
        merged = f"{stdout}\n{stderr}"

        if timed_out:
            return OracleResult(
                accepted=False, confidence=0.0,
                reasons=["timed out"], timed_out=True,
                stdout_excerpt=stdout[:2000], stderr_excerpt=stderr[:2000],
                exit_code=exit_code,
            )

        # Check success patterns
        matched_success = any(p.search(merged) for p in self.success_patterns)
        if matched_success:
            score += 0.7
            reasons.append("success_pattern_matched")

        # Check failure patterns
        matched_failure = any(p.search(merged) for p in self.failure_patterns)
        if matched_failure:
            score -= 0.7
            reasons.append("failure_pattern_matched")

        # Exit code signals
        if exit_code == 0:
            score += 0.1
            reasons.append("exit_code_zero")

        if exit_code is not None and exit_code > 0:
            score -= 0.1
            reasons.append("exit_code_nonzero")

        # Content quality signals
        merged_lower = merged.lower()
        if len(stdout.strip()) > 0 and "wrong" not in merged_lower:
            score += 0.05

        if "incorrect" not in merged_lower:
            score += 0.05

        # Flag-like in output
        if re.search(r"(?:flag|ctf)\{[^}]+\}", merged, re.IGNORECASE):
            score += 0.05
            reasons.append("flag_like_in_output")

        confidence = max(0.0, min(1.0, score))
        accepted = confidence >= 0.7

        return OracleResult(
            accepted=accepted,
            confidence=confidence,
            reasons=reasons,
            stdout_excerpt=stdout[:2000],
            stderr_excerpt=stderr[:2000],
            exit_code=exit_code,
        )


class FlagValidator:
    """Flag validator with multi-signal oracle"""

    def __init__(
        self,
        timeout: int = 10,
        success_patterns: list[str] | None = None,
        failure_patterns: list[str] | None = None,
    ):
        self.timeout = timeout
        self.oracle = OutputOracle(success_patterns, failure_patterns)

    def validate(
        self,
        sample_path: Path,
        candidate: str,
        output_dir: Path | None = None,
        modes: list[str] | None = None,
    ) -> ValidationResult:
        sample_path = Path(sample_path).resolve()
        output_dir = Path(output_dir or sample_path.parent).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)

        modes = modes or ["argv", "stdin"]
        sandbox = DockerSandbox(DockerSandboxConfig(timeout=self.timeout))

        results: list[ValidationResult] = []

        for mode in modes:
            result = self._run_one_mode(
                sandbox=sandbox,
                sample_path=sample_path,
                output_dir=output_dir,
                candidate=candidate,
                mode=mode,
            )
            results.append(result)
            self._append_jsonl(output_dir / "validation_results.jsonl", result)

            if result.accepted:
                self._write_json(output_dir / "validation_result.json", result)
                self._write_reproducer(output_dir / "reproduce.py", sample_path, candidate, mode)
                return result

        best = self._pick_best(results)
        self._write_json(output_dir / "validation_result.json", best)
        return best

    def _run_one_mode(
        self,
        sandbox: DockerSandbox,
        sample_path: Path,
        output_dir: Path,
        candidate: str,
        mode: str,
    ) -> ValidationResult:
        if mode == "argv":
            command = f"/input/sample {candidate}"
            result = sandbox.run_exec(
                sample_path=sample_path,
                argv=[candidate],
                output_dir=output_dir,
            )
        elif mode == "stdin":
            command = f"/input/sample (stdin={candidate[:20]}...)"
            result = sandbox.run_exec(
                sample_path=sample_path,
                argv=[],
                stdin=(candidate + "\n").encode(),
                output_dir=output_dir,
            )
        else:
            raise ValueError(f"unsupported validation mode: {mode}")

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        oracle = self.oracle.evaluate(
            stdout=stdout,
            stderr=stderr,
            exit_code=result.exit_code,
            timed_out=(result.error == "timeout"),
        )

        evidence: list[str] = []
        evidence.extend(oracle.reasons)
        if result.error:
            evidence.append(f"mode={mode}: sandbox error: {result.error}")

        return ValidationResult(
            accepted=oracle.accepted,
            candidate=candidate,
            mode=mode,
            exit_code=result.exit_code,
            stdout=stdout[-4000:],
            stderr=stderr[-4000:],
            matched_success="success_pattern_matched" in oracle.reasons,
            matched_failure="failure_pattern_matched" in oracle.reasons,
            command=command,
            evidence=evidence,
            oracle=oracle,
            confidence=oracle.confidence,
        )

    def _pick_best(self, results: list[ValidationResult]) -> ValidationResult:
        if not results:
            raise ValueError("no validation results")

        success_like = [r for r in results if r.matched_success and not r.matched_failure]
        if success_like:
            return success_like[0]

        return max(results, key=lambda r: r.confidence)

    def _write_json(self, path: Path, result: ValidationResult) -> None:
        data = asdict(result)
        if result.oracle:
            data["oracle"] = asdict(result.oracle)
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _append_jsonl(self, path: Path, result: ValidationResult) -> None:
        data = asdict(result)
        if result.oracle:
            data["oracle"] = asdict(result.oracle)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def _write_reproducer(
        self,
        path: Path,
        sample_path: Path,
        candidate: str,
        mode: str,
    ) -> None:
        if mode == "argv":
            body = f'''\
import subprocess

candidate = {candidate!r}

p = subprocess.run(
    ["./{sample_path.name}", candidate],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    timeout={self.timeout},
)

print(p.stdout.decode(errors="replace"))
print(p.stderr.decode(errors="replace"))
print("exit:", p.returncode)
'''
        else:
            body = f'''\
import subprocess

candidate = {candidate!r}

p = subprocess.run(
    ["./{sample_path.name}"],
    input=(candidate + "\\n").encode(),
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    timeout={self.timeout},
)

print(p.stdout.decode(errors="replace"))
print(p.stderr.decode(errors="replace"))
print("exit:", p.returncode)
'''

        path.write_text(body, encoding="utf-8")


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
