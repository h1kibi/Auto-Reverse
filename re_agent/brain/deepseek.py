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
from .prompts import PLANNER_SYSTEM_PROMPT, PROMPT_VERSION


class OpenAICompatibleBrain:
    name = "openai_compat"

    def __init__(self, base_url: str, api_key: str, model: str):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model

    def plan(self, ctx: BrainContext) -> BrainResult:
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
                    {"role": "user", "content": ctx.model_dump_json()},
                ],
                response_format={"type": "json_object"},
                max_tokens=2048,
                temperature=0.1,
            )
            return parse_brain_result(resp.choices[0].message.content)
        except Exception:
            return BrainResult(
                actions=[],
                stop_reason="brain_api_error",
                assumptions=[str(ctx.profile)[:500]],
            )

    def extract_constraints(self, bundle: dict) -> dict | None:
        prompt = f"""Extract CTF byte-level constraints from this decompiled function.
Output ONLY valid JSON with 'length' and 'constraints' fields.

Decompiled:
```c
{bundle.get('decompile_excerpt', '')[:4000]}
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
