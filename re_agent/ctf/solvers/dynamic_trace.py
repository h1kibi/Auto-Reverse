"""
Dynamic Trace Solver (v2)

Structured probe-based ltrace extraction:
- Sends known probes (AAAA…, flag{…}, 000…)
- Hooks strcmp/memcmp/strncmp/strlen
- Extracts the "other side" (the expected value)
- Returns high-confidence candidates
"""

from pathlib import Path

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


class DynamicTraceSolver(BaseSolver):
    name = "dynamic_trace"

    def score(self, ctx: SolverContext) -> float:
        profile = ctx.profile
        if not profile:
            return 0.0
        score = 0.0
        if profile.comparison_hints:
            score += 0.40
        if profile.has_success_string or profile.has_failure_string:
            score += 0.30
        if profile.input_channels:
            score += 0.10
        if profile.protections:
            if "anti_debug" in profile.protections:
                score -= 0.20
            if "packed_upx" in profile.protections:
                score -= 0.15
        return min(max(score, 0.0), 1.0)

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        candidates: list[FlagCandidate] = []

        for mode in ("ltrace", "frida"):
            try:
                result = self._trace(ctx, mode)
                candidates.extend(result)
            except Exception:
                continue
            if len(candidates) >= 3:
                break

        return candidates

    def _trace(self, ctx: SolverContext, tool: str) -> list[FlagCandidate]:
        sample = ctx.profile.sample_path.resolve()
        if not sample.exists():
            return []

        timeout = min(ctx.timeout or 10, 10)
        candidates: list[FlagCandidate] = []
        seen: set[str] = set()

        for probe_bytes in PROBE_INPUTS:
            try:
                probe_text = probe_bytes.decode("utf-8", errors="replace")
            except Exception:
                continue

            if tool == "ltrace":
                lines = self._run_ltrace(sample, probe_text, timeout)
            else:
                lines = self._run_frida(sample, probe_text, timeout)

            for line in lines:
                extracted = self._extract_arg(line, probe_text)
                if extracted and extracted not in seen and 4 <= len(extracted) <= 256:
                    seen.add(extracted)
                    candidates.append(FlagCandidate(
                        value=extracted,
                        source=f"dynamic_trace:{tool}",
                        confidence=0.95,
                        evidence=[
                            f"{tool} captured comparison argument",
                            f"raw: {line[:240]}",
                        ],
                    ))

        return candidates

    def _run_ltrace(self, sample: Path, probe: str, timeout: int) -> list[str]:
        """Run ltrace INSIDE Docker sandbox (never on host)"""
        try:
            import subprocess
        except ImportError:
            return []

        # Try sandbox first
        try:
            from ...sandbox import DockerSandbox, DockerSandboxConfig
            config = DockerSandboxConfig(timeout=timeout)
            sandbox = DockerSandbox(config)
            result = sandbox.run_tool_with_sample(
                sample_path=sample,
                tool_argv=["ltrace", "-e", "+strcmp+strncmp+memcmp+strlen",
                           "/input/sample", probe],
                output_dir=sample.parent,
            )
            if result and result.stdout:
                return (result.stderr + "\n" + result.stdout).split("\n")
        except (FileNotFoundError, Exception):
            pass

        # Fallback: direct (will fail on Windows/non-Docker env)
        try:
            proc = subprocess.run(
                ["ltrace", "-e", "+" + "+".join(COMPARISON_FUNCTIONS),
                 str(sample), probe],
                capture_output=True, text=True, timeout=timeout,
            )
            return (proc.stderr + "\n" + proc.stdout).split("\n")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def _run_frida(self, sample: Path, probe: str, timeout: int) -> list[str]:
        """Run Frida INSIDE Docker sandbox (never on host)"""
        script = r"""
const funcs=["strcmp","strncmp","memcmp"];
for(const n of funcs){
  const a=Module.findExportByName(null,n);
  if(!a)continue;
  Interceptor.attach(a,{
    onEnter(args){this.a=args[0];this.b=args[1]},
    onLeave(ret){
      try{send(JSON.stringify({
        f:n, a:Memory.readCString(this.a), b:Memory.readCString(this.b), r:ret.toInt32()
      }));}catch(e){}
    }
  });
}
"""
        # Sandbox attempt
        try:
            from ...sandbox import DockerSandbox, DockerSandboxConfig
            config = DockerSandboxConfig(timeout=timeout)
            sandbox = DockerSandbox(config)
            result = sandbox.run_tool_with_sample(
                sample_path=sample,
                tool_argv=["frida", "-q", "-n", sample.name],
                output_dir=sample.parent,
            )
            if result and result.stdout:
                return result.stdout.split("\n")
        except Exception:
            pass

        # Direct fallback
        import subprocess
        try:
            proc = subprocess.run(
                ["frida", "-q", "-n", sample.name],
                input=script.encode() + b"\n",
                capture_output=True, text=True, timeout=timeout,
            )
            return (proc.stdout or "").split("\n")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def _extract_arg(self, line: str, probe: str) -> str | None:
        """Extract the non-probe argument from a comparison call line"""
        if not line or "(" not in line:
            return None

        # JSON-style Frida output
        if line.strip().startswith("{"):
            import json
            try:
                data = json.loads(line.strip())
                for key in ("a", "b"):
                    val = data.get(key, "")
                    if isinstance(val, str) and val and val != probe and len(val) >= 4:
                        if self._is_interesting(val):
                            return val
            except json.JSONDecodeError:
                pass

        # Text-style ltrace output
        for func in COMPARISON_FUNCTIONS:
            if func not in line:
                continue
            try:
                paren = line.index("(")
                args_raw = line[paren + 1:]
                depth = 0
                end = 0
                for i, ch in enumerate(args_raw):
                    if ch == "(": depth += 1
                    elif ch == ")":
                        if depth == 0:
                            end = i; break
                        depth -= 1
                args_part = args_raw[:end]

                # Extract quoted arguments
                parts = []
                in_q = False
                cur = ""
                for ch in args_part:
                    if ch == '"' or ch == "'":
                        if in_q:
                            parts.append(cur); cur = ""
                        in_q = not in_q
                        continue
                    if in_q:
                        cur += ch
                        continue
                if cur:
                    parts.append(cur)

                for arg in parts:
                    arg = arg.strip().strip('"')
                    if arg and arg != probe and len(arg) >= 4:
                        pr = self._printable_ratio(arg)
                        if pr > 0.6 and self._is_interesting(arg):
                            return arg
            except Exception:
                continue

        return None

    @staticmethod
    def _printable_ratio(s: str) -> float:
        if not s:
            return 0.0
        cnt = sum(32 <= ord(c) <= 126 or c in "\n\r\t" for c in s)
        return cnt / len(s)

    @staticmethod
    def _is_interesting(s: str) -> bool:
        low = s.lower()
        return any(k in low for k in ("flag", "ctf", "{", "}",
                                        "correct", "wrong", "key", "pass"))
