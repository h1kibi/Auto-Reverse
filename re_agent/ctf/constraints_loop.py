"""
LLM Constraint Draft -> Validate -> Repair Loop

Flow:
1. LLM sees decompiled snippet -> proposes constraints.json
2. Schema validation (Pydantic / manual check)
3. Z3 solve -> check sat
4. Docker validator -> check if accepted
5. If failed: feed counterexample + trace back to LLM for repair
6. Repeat up to max_rounds

Design principle:
- LLM proposes, tools verify
- Never trust LLM output without sandbox validation
- Every constraint draft must include evidence references
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def repair_constraints_with_llm(
    decompiled_code: str,
    prev_spec: dict,
    error_info: str,
    max_rounds: int = 3,
) -> dict | None:
    """LLM constraint repair loop: propose -> validate -> repair"""

    import os
    try:
        from ..llm import LLMFactory, ChatMessage
    except ImportError:
        return None

    api_key = os.getenv("MIMO_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    provider = "mimo" if os.getenv("MIMO_API_KEY") else "openai"
    client = LLMFactory.create(provider, api_key=api_key)

    current_spec = prev_spec

    for round_num in range(max_rounds):
        # 1. Validate schema
        spec_error = _validate_spec(current_spec)
        if spec_error:
            # Ask LLM to fix the schema error
            repair_prompt = (
                f"The constraints JSON has a schema error:\n{spec_error}\n\n"
                f"Invalid spec: {json.dumps(current_spec, indent=2)[:2000]}\n\n"
                f"Decompiled code:\n```c\n{decompiled_code[:3000]}\n```\n\n"
                f"Fix the schema error and output valid JSON only."
            )
        else:
            # 2. Try Z3 solve
            try:
                from .solvers.z3_constraints import solve_constraint_spec
                flag = solve_constraint_spec(current_spec)
            except Exception as z3_error:
                flag = None
                error_info = f"Z3 solver error: {z3_error}"

            if flag:
                return current_spec  # Success

            # 3. Unsolved - ask LLM to repair
            repair_prompt = (
                f"Z3 found no solution for these constraints:\n"
                f"```json\n{json.dumps(current_spec, indent=2)[:2000]}\n```\n\n"
                f"Error: {error_info}\n\n"
                f"Decompiled code:\n```c\n{decompiled_code[:3000]}\n```\n\n"
                f"Please revise the constraints. Check:\n"
                f"1. Are the byte indices correct?\n"
                f"2. Are the operations correct (xor/add/sub)?\n"
                f"3. Are the expected values correct?\n"
                f"4. Is the length reasonable?\n\n"
                f"Output revised constraints JSON only."
            )

        try:
            resp = client.chat(
                [ChatMessage(role="user", content=repair_prompt)],
                temperature=0.1,
                max_tokens=1000,
            )
            content = _extract_json(resp.content)
            new_spec = json.loads(content)
            current_spec = new_spec
        except Exception:
            break

    return None


def validate_candidate_full(
    sample_path: Path,
    candidate: str,
    output_dir: Path,
) -> dict:
    """Full validation: Z3 solve -> Docker sandbox -> oracle"""
    from .validator import FlagValidator
    from .validator import OutputOracle

    validator = FlagValidator(timeout=10)
    vr = validator.validate(sample_path, candidate, output_dir)

    return {
        "accepted": vr.accepted,
        "candidate": candidate,
        "mode": vr.mode,
        "exit_code": vr.exit_code,
        "confidence": vr.confidence,
        "evidence": vr.evidence,
        "stdout_excerpt": vr.stdout[-1000:],
        "stderr_excerpt": vr.stderr[-1000:],
    }


def _validate_spec(spec: dict) -> str | None:
    """Validate constraints spec schema"""
    if not isinstance(spec, dict):
        return "spec must be a dict"

    if "length" not in spec:
        return "missing length"

    length = spec["length"]
    if not isinstance(length, int) or length <= 0 or length > 256:
        return f"invalid length: {length}"

    constraints = spec.get("constraints", [])
    if not isinstance(constraints, list):
        return "constraints must be a list"

    for i, c in enumerate(constraints):
        if not isinstance(c, dict):
            return f"constraints[{i}] is not a dict"
        if "left" not in c:
            return f"constraints[{i}] missing left"
        if "right" not in c:
            return f"constraints[{i}] missing right"

    return None


def _extract_json(text: str) -> str:
    """Extract JSON from text (handle ```json fences)"""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return text


def llm_propose_constraints(
    decompiled_code: str,
    profile_hints: dict | None = None,
) -> dict | None:
    """LLM proposes constraints from decompiled code (one-shot, no repair)"""
    import os
    try:
        from ..llm import LLMFactory, ChatMessage
    except ImportError:
        return None

    api_key = os.getenv("MIMO_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    hints_text = ""
    if profile_hints:
        hints_text = f"\nProfile hints: {json.dumps(profile_hints, ensure_ascii=False)[:500]}\n"

    prompt = f"""Extract CTF reverse byte-level constraints from the decompiled code.
Output valid JSON only. Do NOT guess the final flag.

{hints_text}
Decompiled code:
```c
{decompiled_code[:4000]}
```

Output format:
{{
  "length": <input length>,
  "prefix": "<known prefix or empty>",
  "suffix": "<known suffix or empty>",
  "constraints": [
    {{"op":"==","left":{{"op":"xor","args":[{{"var":<index>}},<constant>]}},"right":<constant>}},
    {{"op":"==","left":{{"var":<index>}},"right":<constant>}}
  ]
}}

Supported ops: xor, add, sub, and, or, mul, shl, shr
Every constraint must be evidence-backed from the code.
Output ONLY the JSON object, no explanation."""

    provider = "mimo" if os.getenv("MIMO_API_KEY") else "openai"
    client = LLMFactory.create(provider, api_key=api_key)

    try:
        resp = client.chat(
            [ChatMessage(role="user", content=prompt)],
            temperature=0.1,
            max_tokens=1200,
        )
        data = json.loads(_extract_json(resp.content))
        if isinstance(data, dict) and "constraints" in data:
            return data
    except Exception:
        pass

    return None
