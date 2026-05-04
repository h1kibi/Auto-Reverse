"""
Flag Validator (v0.5.1)

Multi-signal oracle + differential oracle + wrong baseline.
"""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

from ..sandbox import DockerSandbox, DockerSandboxConfig


SUCCESS_PATTERNS = [
    r"\bcorrect\b", r"\bsuccess\b", r"\baccepted\b",
    r"congrat", r"good job", r"you win", r"well done",
]

FAILURE_PATTERNS = [
    r"\bwrong\b", r"\bincorrect\b", r"\bfailed?\b",
    r"\binvalid\b", r"try again", r"nope", r"\bbad\b",
    r"you lose",
]


class RedactionMode(str, Enum):
    NONE = "none"
    LOGS = "logs"
    STRICT = "strict"


@dataclass
class OracleResult:
    accepted: bool
    confidence: float
    reasons: list[str] = field(default_factory=list)
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    exit_code: int | None = None
    timed_out: bool = False


@dataclass
class ValidationResult:
    accepted: bool
    candidate: str
    mode: str
    exit_code: int | None
    stdout: str
    stderr: str
    matched_success: bool = False
    matched_failure: bool = False
    command: str = ""
    evidence: list[str] = field(default_factory=list)
    oracle: OracleResult | None = None
    confidence: float = 0.0
    redacted: bool = False


class OutputOracle:

    def __init__(self, success_patterns=None, failure_patterns=None):
        self.success_patterns = [re.compile(p, re.IGNORECASE)
                                 for p in (success_patterns or SUCCESS_PATTERNS)]
        self.failure_patterns = [re.compile(p, re.IGNORECASE)
                                 for p in (failure_patterns or FAILURE_PATTERNS)]

    def evaluate(self, stdout: str, stderr: str, exit_code: int | None,
                 timed_out: bool = False) -> OracleResult:
        return self._evaluate(stdout, stderr, exit_code, timed_out)

    def evaluate_differential(
        self, candidate_stdout: str, candidate_stderr: str,
        wrong_stdout: str, wrong_stderr: str,
        exit_code: int | None,
    ) -> OracleResult:
        r = self._evaluate(candidate_stdout, candidate_stderr, exit_code)

        cand_text = (candidate_stdout + "\n" + candidate_stderr).strip()
        wrong_text = (wrong_stdout + "\n" + wrong_stderr).strip()

        if cand_text and cand_text != wrong_text:
            r.confidence = min(1.0, r.confidence + 0.30)
            r.reasons.append("output_differs_from_wrong_input")

        if len(candidate_stdout.strip()) > len(wrong_stdout.strip()) + 5:
            r.confidence = min(1.0, r.confidence + 0.15)
            r.reasons.append("candidate_output_longer_than_wrong")

        if exit_code == 0:
            r.confidence = min(1.0, r.confidence + 0.10)

        # Allow acceptance even without explicit success pattern if output differs
        if "failure_pattern_matched" not in r.reasons and r.confidence >= 0.50:
            r.accepted = True
        return r

    def _evaluate(self, stdout: str, stderr: str, exit_code: int | None,
                  timed_out: bool = False) -> OracleResult:
        reasons: list[str] = []
        score = 0.0
        merged = f"{stdout}\n{stderr}"
        if timed_out:
            return OracleResult(accepted=False, confidence=0.0, reasons=["timed out"],
                                timed_out=True, stdout_excerpt=stdout[:2000],
                                stderr_excerpt=stderr[:2000], exit_code=exit_code)
        if any(p.search(merged) for p in self.success_patterns):
            score += 0.75; reasons.append("success_pattern_matched")
        if any(p.search(merged) for p in self.failure_patterns):
            score -= 0.75; reasons.append("failure_pattern_matched")
        if exit_code == 0: score += 0.10; reasons.append("exit_code_zero")
        if exit_code is not None and exit_code > 0: score -= 0.10; reasons.append("exit_code_nonzero")
        merged_lower = merged.lower()
        if len(stdout.strip()) > 0 and "wrong" not in merged_lower: score += 0.05
        if "incorrect" not in merged_lower: score += 0.05
        if re.search(r"(?:flag|ctf)\{[^}]+\}", merged, re.IGNORECASE):
            score += 0.05; reasons.append("flag_like_in_output")
        confidence = max(0.0, min(1.0, score))
        return OracleResult(accepted=confidence >= 0.7, confidence=confidence,
                            reasons=reasons, stdout_excerpt=stdout[:2000],
                            stderr_excerpt=stderr[:2000], exit_code=exit_code)


class FlagValidator:

    def __init__(self, timeout: int = 10, success_patterns=None, failure_patterns=None,
                 redaction: RedactionMode = RedactionMode.NONE):
        self.timeout = timeout
        self.oracle = OutputOracle(success_patterns, failure_patterns)
        self.redaction = redaction

    def validate(self, sample_path: Path, candidate: str,
                 output_dir: Path | None = None,
                 modes: list[str] | None = None) -> ValidationResult:
        sample_path = Path(sample_path).resolve()
        output_dir = (output_dir or sample_path.parent).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        modes = modes or ["argv", "stdin"]
        sandbox = DockerSandbox(DockerSandboxConfig(timeout=self.timeout))

        # Run wrong baseline first
        wrong_len = min(max(len(candidate), 8), 64)
        wrong_str = "A" * wrong_len
        wrong_run = sandbox.run_exec(sample_path=sample_path, argv=[wrong_str],
                                     output_dir=output_dir)

        results: list[ValidationResult] = []
        for mode in modes:
            result = self._run_one_mode(sandbox, sample_path, output_dir,
                                        candidate, mode, wrong_run)
            results.append(result)
            self._append_jsonl(output_dir / "validation_results.jsonl", result)
            if result.accepted:
                self._write_output(output_dir, result, sample_path, candidate, mode)
                return result

        best = self._pick_best(results)
        self._write_output(output_dir, best, sample_path, candidate,
                           best.mode if best.mode else "unknown")
        return best

    def _run_one_mode(self, sandbox, sample_path, output_dir, candidate, mode,
                      wrong_run) -> ValidationResult:
        if mode == "argv":
            command = f"/input/sample {candidate}"
            result = sandbox.run_exec(sample_path=sample_path, argv=[candidate],
                                      output_dir=output_dir)
        elif mode == "stdin":
            command = f"/input/sample (stdin)"
            result = sandbox.run_exec(sample_path=sample_path, argv=[],
                                      stdin=(candidate + "\n").encode(),
                                      output_dir=output_dir)
        else:
            raise ValueError(f"unsupported: {mode}")

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        oracle = self.oracle.evaluate_differential(
            candidate_stdout=stdout, candidate_stderr=stderr,
            wrong_stdout=wrong_run.stdout or "",
            wrong_stderr=wrong_run.stderr or "",
            exit_code=result.exit_code,
        )

        evidence = list(oracle.reasons)
        if result.error:
            evidence.append(f"mode={mode}: sandbox error: {result.error}")

        return ValidationResult(
            accepted=oracle.accepted, candidate=candidate, mode=mode,
            exit_code=result.exit_code, stdout=stdout[-4000:], stderr=stderr[-4000:],
            matched_success="success_pattern_matched" in oracle.reasons,
            matched_failure="failure_pattern_matched" in oracle.reasons,
            command=command, evidence=evidence, oracle=oracle,
            confidence=oracle.confidence, redacted=self.redaction != RedactionMode.NONE,
        )

    @staticmethod
    def _pick_best(results):
        success_like = [r for r in results if r.matched_success and not r.matched_failure]
        if success_like: return success_like[0]
        return max(results, key=lambda r: r.confidence)

    def _write_output(self, output_dir: Path, result: ValidationResult,
                      sample_path: Path, candidate: str, mode: str):
        data = {"accepted": result.accepted, "candidate":
                _redact(candidate, self.redaction) if self.redaction != RedactionMode.NONE else candidate,
                "mode": mode, "exit_code": result.exit_code,
                "confidence": result.confidence, "evidence": result.evidence}
        (output_dir / "validation_result.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self._write_reproducer(output_dir / "reproduce.py", sample_path, candidate, mode)

    def _append_jsonl(self, path: Path, result: ValidationResult):
        data = asdict(result)
        if result.oracle: data["oracle"] = asdict(result.oracle)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

    def _write_reproducer(self, path: Path, sample: Path, candidate: str, mode: str):
        body = f'''import os, subprocess, sys
candidate = os.environ.get("AUTO_REVERSE_CANDIDATE")
if not candidate: raise SystemExit("Set AUTO_REVERSE_CANDIDATE env var")
mode = "{mode}"
if mode == "argv":
    p = subprocess.run(["./{sample.name}", candidate], capture_output=True, timeout=10)
else:
    p = subprocess.run(["./{sample.name}"], input=(candidate+"\\n").encode(), capture_output=True, timeout=10)
print(p.stdout.decode(errors="replace"))
print(p.stderr.decode(errors="replace"))
sys.exit(0 if p.returncode == 0 else 1)
'''
        path.write_text(body, encoding="utf-8")


def _redact(value: str, mode: RedactionMode) -> str:
    if mode == RedactionMode.NONE: return value
    if not value: return ""
    digest = hashlib.sha256(value.encode()).hexdigest()[:12]
    return f"[REDACTED len={len(value)} sha256={digest}]"


def redact_candidate(value: str, mode: RedactionMode) -> str:
    return _redact(value, mode)
