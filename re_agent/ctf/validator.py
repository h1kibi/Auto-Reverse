"""
Flag 验证器

核心原则：flag 必须由 solver 产生、validator 验证
"""

import re
from dataclasses import dataclass
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
    """验证结果"""
    accepted: bool
    stdout: str
    stderr: str
    evidence: list[str]


class FlagValidator:
    """Flag 验证器"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def validate(self, sample_path: Path, candidate: str) -> ValidationResult:
        """验证候选 flag"""
        sandbox = DockerSandbox(DockerSandboxConfig(timeout=self.timeout))

        # argv 模式: ./challenge flag{...}
        argv_result = sandbox.run_argv(
            sample_path=sample_path,
            output_dir=sample_path.parent,
            argv=["{sample}", candidate],
        )

        # stdin 模式: echo flag{...} | ./challenge
        stdin_result = sandbox.run_shell(
            sample_path=sample_path,
            output_dir=sample_path.parent,
            shell_cmd=f"printf '%s\\n' {_shell_quote(candidate)} | /samples/{sample_path.name}",
        )

        stdout = "\n".join(filter(None, [argv_result.stdout, stdin_result.stdout]))
        stderr = "\n".join(filter(None, [argv_result.stderr, stdin_result.stderr]))
        merged = f"{stdout}\n{stderr}"

        has_success = any(re.search(p, merged, re.IGNORECASE) for p in SUCCESS_PATTERNS)
        has_failure = any(re.search(p, merged, re.IGNORECASE) for p in FAILURE_PATTERNS)

        evidence = []
        if has_success:
            evidence.append("program output matched success pattern")
        if has_failure:
            evidence.append("program output matched failure pattern")

        return ValidationResult(
            accepted=has_success and not has_failure,
            stdout=stdout[-4000:],
            stderr=stderr[-4000:],
            evidence=evidence,
        )


def _shell_quote(value: str) -> str:
    """Shell 引号转义"""
    return "'" + value.replace("'", "'\"'\"'") + "'"
