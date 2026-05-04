"""
OpenAI-compatible Brain adapter.

GPT requirement: one base class, DeepSeek/GPT/Ollama all reuse.
"""

from __future__ import annotations

import os
import json
from openai import OpenAI

from .context import BrainContext
from .actions import BrainResult, BrainAction
from .base import parse_brain_result
from .prompts import PLANNER_SYSTEM_PROMPT


class OpenAICompatibleBrain:
    name = "openai_compat"

    def __init__(self, base_url: str, api_key: str, model: str):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model

    def plan(self, ctx: BrainContext) -> BrainResult:
        try:
            evidence = ctx.evidence_summary or {}
            profile = ctx.profile or {}
            packer = profile.get("packer", {})
            failed_actions = profile.get("failed_action_keys", profile.get("failed_solvers", []))
            hints = []
            for k in ["file_type", "crypto_hints", "comparison_hints", "encoding_hints",
                       "protections", "solver_hints", "input_channels"]:
                v = evidence.get(k)
                if v:
                    hints.append(f"{k}: {v}")
            if packer.get("is_packed"):
                hints.append(f"PACKED: {packer.get('packer', '?')} (do NOT use static_flag/encoding)")
            if failed_actions:
                hints.append(f"FAILED: {failed_actions}")

            prev_text = ""
            if ctx.previous_observations:
                prev_summaries = [
                    o.get("summary", "")[:80] for o in ctx.previous_observations[-3:]
                    if isinstance(o, dict)
                ]
                prev_text = "Previous: " + "; ".join(prev_summaries) + ". "

            prompt = (
                f"CTF binary profile: {', '.join(hints)}.\n"
                f"Available solvers: {', '.join(ctx.allowed_solvers)}.\n"
                f"{prev_text}"
                "Which ONE solver should I run? Start answer with solver name."
            )

            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You help pick the best reverse engineering solver for CTF challenges."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=200,
                temperature=0.1,
            )
            text = (resp.choices[0].message.content or "").lower()

            # Smart fallback: if MiMo returned empty, use profile hints
            if not text or len(text) < 5:
                # Evidence-driven heuristic
                if evidence.get("comparison_hints"):
                    solver = "dynamic_trace"
                elif evidence.get("crypto_hints"):
                    solver = "z3_extractor"
                elif evidence.get("encoding_hints"):
                    solver = "encoding"
                elif profile.get("protections") and "anti_debug" in str(profile.get("protections")):
                    solver = "patcher"
                else:
                    solver = "static_flag"
            else:
                # Smart parser: skip negated, pick last-mentioned positive
                solver = "static_flag"
                best_pos = -1
                for name in ctx.allowed_solvers:
                    pos = text.rfind(name)
                    if pos > best_pos:
                        before = text[max(0, pos - 40):pos]
                        if not any(w in before for w in ["don't use", "do not", "avoid", "skip", "not"]):
                            best_pos = pos
                            solver = name
            return BrainResult(actions=[
                BrainAction(
                    action_id="step_1", kind="run_solver", name=solver,
                    rationale=text[:200], risk="read_only", created_from="brain",
                )
            ])
        except Exception as e:
            return BrainResult(actions=[], stop_reason="brain_api_error",
                               assumptions=[str(e)[:200]])

    def extract_constraints(self, bundle: dict) -> dict | None:
        prompt = f"""Extract CTF byte-level constraints from this decompiled function.
Output ONLY valid JSON with 'length' and 'constraints' fields.

Decompiled:
```c
{bundle.get("decompile_excerpt", "")[:4000]}
```

Output format:
{{"length": <int>, "constraints": [{{"op":"==","left":{{"var":0}},"right":<int>}}]}}"""

        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                max_tokens=1000,
                temperature=0.1,
            )
            return json.loads(resp.choices[0].message.content)
        except Exception:
            return None


class DeepSeekBrain(OpenAICompatibleBrain):
    name = "deepseek"

    def __init__(self, model: str = "deepseek-chat", api_key: str | None = None):
        super().__init__(
            base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
            api_key=api_key or os.getenv("DEEPSEEK_API_KEY", ""),
            model=model,
        )


class OpenAIBrain(OpenAICompatibleBrain):
    name = "openai"

    def __init__(self, model: str = "gpt-4o", api_key: str | None = None):
        super().__init__(
            base_url="https://api.openai.com/v1",
            api_key=api_key or os.getenv("OPENAI_API_KEY", ""),
            model=model,
        )


class MiMoBrain(OpenAICompatibleBrain):
    name = "mimo"

    def __init__(self, model: str = "mimo-v2.5-pro", api_key: str | None = None):
        super().__init__(
            base_url=os.getenv("MIMO_BASE_URL", "https://token-plan-cn.xiaomimimo.com/v1"),
            api_key=api_key or os.getenv("MIMO_API_KEY", ""),
            model=model,
        )
