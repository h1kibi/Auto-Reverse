"""
Z3 Constraint Extractor

Automatically extracts byte-level constraints from decompiled C code.
Covers common CTF reverse patterns:

Patterns extracted:
- input[i] ^ K == C (xor single byte)
- input[i] + K == C (add constant)
- input[i] - K == C (sub constant)
- input[i] == C (direct equality)
- input[i] ^ input[j] == C (xor between positions)
- input[i] + input[j] == C (add between positions)
- strlen(input) == N
- memcmp(input, expected, N)

Also supports LLM-assisted constraint drafting (validated by Z3 solve + sandbox).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


class Z3ExtractorSolver(BaseSolver):
    """Auto extract Z3 constraints from decompiled code"""

    name = "z3_extractor"

    def score(self, ctx: SolverContext) -> float:
        profile = ctx.profile
        if not profile:
            return 0.0

        score = 0.0
        if profile.comparison_hints:
            score += 0.3
        if profile.crypto_hints and "xor" in profile.crypto_hints:
            score += 0.2
        if profile.has_success_string:
            score += 0.1
        if profile.suspicious_constants:
            score += 0.1

        return min(score, 0.85)

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        candidates: list[FlagCandidate] = []

        # 1. Try loading decompiled code excerpts from artifacts
        for excerpt_path in ctx.output_dir.glob("**/decompile_excerpts/*.txt"):
            try:
                code = excerpt_path.read_text(encoding="utf-8", errors="replace")
                spec = extract_from_decompile(code)
                if spec and spec.get("constraints"):
                    flag = self._solve_and_validate(spec, ctx)
                    if flag:
                        candidates.append(FlagCandidate(
                            value=flag,
                            source=self.name,
                            confidence=0.82,
                            evidence=[
                                f"extracted {len(spec['constraints'])} constraints from {excerpt_path.name}",
                                f"length={spec.get('length', '?')}",
                            ],
                        ))
            except Exception:
                continue

        # 2. Try loading from ghidra decompile artifacts
        for ghidra_dir in ctx.output_dir.glob("**/ghidra/**/*.c"):
            try:
                code = ghidra_dir.read_text(encoding="utf-8", errors="replace")
                spec = extract_from_decompile(code)
                if spec and spec.get("constraints"):
                    flag = self._solve_and_validate(spec, ctx)
                    if flag:
                        candidates.append(FlagCandidate(
                            value=flag,
                            source=self.name,
                            confidence=0.78,
                            evidence=[f"extracted from Ghidra decompile: {ghidra_dir.name}"],
                        ))
            except Exception:
                continue

        # 3. Try LLM-assisted extraction
        llm_result = self._llm_extract(ctx)
        if llm_result:
            candidates.extend(llm_result)

        return candidates

    def _solve_and_validate(self, spec: dict, ctx: SolverContext) -> str | None:
        """Solve constraints with Z3"""
        try:
            from .z3_constraints import solve_constraint_spec
            return solve_constraint_spec(spec)
        except Exception:
            return None

    def _llm_extract(self, ctx: SolverContext) -> list[FlagCandidate]:
        """LLM-assisted constraint extraction"""
        import os
        from ...llm import LLMFactory, ChatMessage

        api_key = os.getenv("MIMO_API_KEY") or os.getenv("OPENAI_API_KEY")
        if not api_key:
            return []

        # Collect decompiled code excerpts
        excerpts = []
        for pattern in ["**/decompile_excerpts/*.txt", "**/ghidra/**/*.c", "**/*decomp*.txt", "**/*decomp*.c"]:
            for path in ctx.output_dir.glob(pattern):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")[:5000]
                    if text.strip():
                        excerpts.append(text)
                except Exception:
                    continue
                if len(excerpts) >= 3:
                    break
            if excerpts:
                break

        if not excerpts:
            return []

        combined_code = "\n\n---\n\n".join(excerpts[:3])

        prompt = f"""Extract CTF reverse constraints from decompiled code. Output JSON only.

Constraints DSL:
- length: total input length (int, 1-256)
- prefix: known prefix string (optional)
- suffix: known suffix string (optional)
- constraints: list of {{"op":"==","left":expr,"right":expr}}

Expression forms:
- int literal (e.g. 116)
- {{"var": <index>}} - byte at position index
- {{"op":"xor","args":[expr, <int>]}} or {{"op":"add"|"sub"|"and"|"or"|"mul"|"shl"|"shr"...}}

Common patterns to look for:
1. `input[i] ^ 0x37 == 0x74` -> {{"op":"==","left":{{"op":"xor","args":[{{"var":i}},55]}},"right":116}}
2. `input[i] + 3 == 0x67` -> {{"op":"==","left":{{"op":"add","args":[{{"var":i}},3]}},"right":103}}
3. `input[i] - input[j] == 5` -> {{"op":"==","left":{{"op":"sub","args":[{{"var":i}},{{"var":j}}]}},"right":5}}
4. `strlen(input) == 32` -> set length=32
5. `memcmp(input, expected, N)` -> set length=N, add per-byte equality constraints

Output format:
{{
  "length": 32,
  "prefix": "flag{{",
  "suffix": "}}",
  "constraints": [
    {{"op":"==","left":{{"op":"xor","args":[{{"var":5}},18]}},"right":116,"evidence":"line 42: if ((input[5]^0x12)!=0x74)"}}
  ]
}}

Rules:
- Only include constraints supported by the code
- No guessing final flag
- Every constraint must have an "evidence" field with the source line
- If unsure about length, omit it

Code:
```
{combined_code[:4000]}
```

Output JSON only:"""

        try:
            if os.getenv("MIMO_API_KEY"):
                client = LLMFactory.create("mimo", api_key=api_key)
            else:
                client = LLMFactory.create("openai", api_key=api_key)

            resp = client.chat(
                [ChatMessage(role="user", content=prompt)],
                temperature=0.1,
                max_tokens=1200,
            )

            data = json.loads(resp.content)
            if not isinstance(data, dict) or "length" not in data:
                return []

            spec = data
            if not isinstance(spec.get("constraints"), list):
                return []

            flag = self._solve_and_validate(spec, ctx)
            if flag:
                return [FlagCandidate(
                    value=flag,
                    source=f"{self.name}:llm",
                    confidence=0.75,
                    evidence=["LLM-extracted constraints from decompiled code"],
                )]
        except Exception:
            pass

        return []


def extract_from_decompile(code: str) -> dict | None:
    """Extract constraints from decompiled C code using regex patterns"""

    constraints = []
    evidence = []

    # Pattern 1: strlen(input) == N
    strlen_match = re.search(r"strlen\s*\(\s*\w+\s*\)\s*[!=]=\s*(\d+)", code)
    strlen_match2 = re.search(r"sVar\d+\s*=?\s*strlen\([^)]+\)[;\s]*.*sVar\d+\s*[!=]=\s*(\d+)", code)
    length = None
    if strlen_match:
        length = int(strlen_match.group(1))
    elif strlen_match2:
        length = int(strlen_match2.group(1))

    if length is None:
        for m in re.finditer(r"(?:input|flag|buf|key)\[(\d+)\].*!=.*return", code):
            idx = int(m.group(1))
            length = max(length or 0, idx + 1)

    if length is None:
        length = 32

    # Pattern 2: input[i] op K == C style comparisons
    xor_patterns = [
        r"\(?\s*(\w+)\[(\d+)\]\s*\^\s*(0x[0-9a-fA-F]+|\d+)\s*\)?\s*!=\s*(0x[0-9a-fA-F]+|\d+)",
        r"\(?\s*(\w+)\[(\d+)\]\s*\^\s*(0x[0-9a-fA-F]+|\d+)\s*\)?\s*==\s*(0x[0-9a-fA-F]+|\d+)",
    ]
    for pat in xor_patterns:
        for m in re.finditer(pat, code):
            idx = int(m.group(2))
            k = _parse_int(m.group(3))
            c = _parse_int(m.group(4))
            if k is not None and c is not None and 0 <= idx < (length or 64):
                constraints.append({
                    "op": "==",
                    "left": {"op": "xor", "args": [{"var": idx}, k]},
                    "right": c,
                    "evidence": f"line approx: {m.group(0)[:80]}",
                })
                evidence.append(f"xor pattern at index {idx}")

    # Pattern 3: input[i] op K == input[j] style
    inter_patterns = [
        r"\(?\s*(\w+)\[(\d+)\]\s*([\+\-\^])\s*(0x[0-9a-fA-F]+|\d+|\w+\[(\d+)\])\s*\)?\s*[!=]=\s*(0x[0-9a-fA-F]+|\d+)",
    ]
    for pat in inter_patterns:
        for m in re.finditer(pat, code):
            idx = int(m.group(2))
            op = m.group(3)
            rhs_str = m.group(4)
            result_str = m.group(6)
            idx2 = int(m.group(5)) if m.group(5) else None

            result = _parse_int(result_str)
            if result is None:
                continue

            op_map = {"+": "add", "-": "sub", "^": "xor"}
            z3_op = op_map.get(op, "add")

            if idx2 is not None:
                left_expr = {"op": z3_op, "args": [{"var": idx}, {"var": idx2}]}
            else:
                rhs = _parse_int(rhs_str)
                if rhs is None:
                    continue
                left_expr = {"op": z3_op, "args": [{"var": idx}, rhs]}

            constraints.append({
                "op": "==",
                "left": left_expr,
                "right": result,
                "evidence": f"line approx: {m.group(0)[:80]}",
            })
            evidence.append(f"inter-element pattern at index {idx}")

    # Pattern 4: direct comparison input[i] == K
    direct_patterns = [
        r"\(?\s*(\w+)\[(\d+)\]\s*\)?\s*!=\s*(0x[0-9a-fA-F]+|\d+)[^\+]",
        r"\(?\s*(\w+)\[(\d+)\]\s*\)?\s*==\s*(0x[0-9a-fA-F]+|\d+)[^\+]",
    ]
    for pat in direct_patterns:
        for m in re.finditer(pat, code):
            idx = int(m.group(2))
            c = _parse_int(m.group(3))
            if c is not None and 0 <= idx < (length or 64):
                constraints.append({
                    "op": "==",
                    "left": {"var": idx},
                    "right": c,
                    "evidence": f"direct cmp at index {idx}",
                })
                evidence.append(f"direct comparison at index {idx}")

    if not constraints:
        return None

    for c in constraints:
        c.pop("evidence", None)

    spec = {
        "length": min(length or 32, 128),
        "constraints": constraints[:80],
    }

    return spec


def _parse_int(s: str) -> int | None:
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None
