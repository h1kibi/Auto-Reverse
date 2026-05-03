"""
LLM Solver Planner

LLM 负责排序和生成约束草案，但不直接给最终 flag
"""

import json
from dataclasses import dataclass

from ..llm import BaseLLMClient, ChatMessage
from .models import ChallengeProfile


VALID_SOLVERS = {
    "static_flag",
    "encoding",
    "z3_constraints",
    "angr_path",
    "brute_force",
    "dynamic_trace",
}


@dataclass
class PlanStep:
    """计划步骤"""
    solver: str
    reason: str
    params: dict


class SolverPlanner:
    """求解器规划器"""

    def __init__(self, llm: BaseLLMClient):
        self.llm = llm

    def plan(self, profile: ChallengeProfile) -> list[PlanStep]:
        """根据挑战画像生成求解计划"""
        prompt = f"""你是 CTF Reverse 解题 Planner。只能输出 JSON，不要输出解释。

目标：选择求解策略，不要猜 flag。
可选 solver：
- static_flag: strings 中直接有 flag
- encoding: base64/hex/rot 编码
- z3_constraints: 约束求解
- angr_path: 符号执行
- brute_force: 小空间爆破
- dynamic_trace: 动态跟踪

样本信息：
file_type={profile.file_type}
arch={profile.architecture}
tags={profile.tags}
success_strings={profile.success_strings[:10]}
failure_strings={profile.failure_strings[:10]}
interesting_strings={profile.strings[:50]}
imports={profile.imports[:50]}

输出格式（JSON 数组）：
[
  {{"solver": "static_flag", "reason": "...", "params": {{}}}}
]

只输出 JSON，不要输出其他内容。"""

        try:
            resp = self.llm.chat(
                [ChatMessage(role="user", content=prompt)],
                temperature=0.1,
                max_tokens=1200,
            )

            data = json.loads(resp.content)
        except Exception:
            return []

        steps = []
        for item in data:
            solver = item.get("solver")
            if solver not in VALID_SOLVERS:
                continue
            steps.append(PlanStep(
                solver=solver,
                reason=item.get("reason", ""),
                params=item.get("params", {}),
            ))

        return steps
