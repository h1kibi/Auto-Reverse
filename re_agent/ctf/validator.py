"""
Flag 验证器

原则：
- solver 只产生候选；
- validator 才能给 verified verdict；
- 每次验证都保留结构化 JSON；
- solved candidate 生成 reproduce.py。
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from ..sandbox import DockerSandbox, DockerSandboxConfig


SUCCESS_PATTERNS = [
    r"\bcorrect\b",
    r"\bsuccess\b",
    r"\baccepted\b",
    r"congrat",
    r"good job",
    r"you win",
    r"well done",
]

FAILURE_PATTERNS = [
    r"\bwrong\b",
    r"\bincorrect\b",
    r"\bfailed?\b",
    r"\binvalid\b",
    r"try again",
    r"nope",
    r"\bbad\b",
]


@dataclass
class ValidationResult:
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


class FlagValidator:
    """Flag 验证器。"""

    def __init__(
        self,
        timeout: int = 10,
        success_patterns: list[str] | None = None,
        failure_patterns: list[str] | None = None,
    ):
        self.timeout = timeout
        self.success_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (success_patterns or SUCCESS_PATTERNS)
        ]
        self.failure_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (failure_patterns or FAILURE_PATTERNS)
        ]

    def validate(
        self,
        sample_path: Path,
        candidate: str,
        output_dir: Path | None = None,
        modes: list[str] | None = None,
    ) -> ValidationResult:
        """验证候选 flag。

        默认依次尝试 argv 和 stdin。任一模式 accepted 即返回。
        """
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
            command = f"/samples/{sample_path.name} {_shell_quote(candidate)}"
            result = sandbox.run_argv(
                sample_path=sample_path,
                output_dir=output_dir,
                argv=["{sample}", candidate],
            )
        elif mode == "stdin":
            command = f"printf '%s\\n' {_shell_quote(candidate)} | /samples/{sample_path.name}"
            result = sandbox.run_shell(
                sample_path=sample_path,
                output_dir=output_dir,
                shell_cmd=command,
            )
        else:
            raise ValueError(f"unsupported validation mode: {mode}")

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        merged = f"{stdout}\n{stderr}"

        matched_success = any(p.search(merged) for p in self.success_patterns)
        matched_failure = any(p.search(merged) for p in self.failure_patterns)

        evidence: list[str] = []
        if matched_success:
            evidence.append(f"mode={mode}: program output matched success pattern")
        if matched_failure:
            evidence.append(f"mode={mode}: program output matched failure pattern")
        if result.error:
            evidence.append(f"mode={mode}: sandbox error: {result.error}")

        accepted = matched_success and not matched_failure

        return ValidationResult(
            accepted=accepted,
            candidate=candidate,
            mode=mode,
            exit_code=result.exit_code,
            stdout=stdout[-4000:],
            stderr=stderr[-4000:],
            matched_success=matched_success,
            matched_failure=matched_failure,
            command=command,
            evidence=evidence,
        )

    def _pick_best(self, results: list[ValidationResult]) -> ValidationResult:
        if not results:
            raise ValueError("no validation results")

        success_like = [r for r in results if r.matched_success]
        if success_like:
            return success_like[0]

        return results[0]

    def _write_json(self, path: Path, result: ValidationResult) -> None:
        path.write_text(
            json.dumps(asdict(result), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _append_jsonl(self, path: Path, result: ValidationResult) -> None:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")

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
