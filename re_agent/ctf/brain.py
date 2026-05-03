"""
OpenAI Brain for CTF local tools.

PR-5 目标：
- 简单 planner loop
- 使用 OpenAI function calling 调用本地工具
- 所有工具执行仍走 re_agent.ctf.tools.ToolExecutor
- validate_candidate accepted=true 之前，不允许声明 solved
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from openai import OpenAI

from .tools import ArtifactStore, ToolExecutor, ToolRegistry, build_default_ctf_registry


SYSTEM_PROMPT = """你是 Auto-Reverse 的 CTF Reverse Agent。

你的职责：
- 调用本地工具分析 CTF reverse challenge；
- 尽量减少 token 消耗；
- 优先使用 profile_sample 获取小 JSON 摘要；
- 不要要求读取完整大文件；
- 需要代码时，只调用 decompile_function 获取有限片段；
- 所有候选 flag 必须调用 validate_candidate 验证；
- validate_candidate accepted=true 之前，不能宣称 solved；
- 如果 validate_candidate accepted=true，停止继续尝试，输出最终报告；
- 如果工具返回 missing_decompile_artifacts，可建议用户用 profile_sample(skip_ghidra=false)；
- 如果当前工具不足以继续，明确说明缺少哪个工具，而不是编造结果。

工具选择策略：
- 如果你不确定 artifact store 中有哪些文件，调用 list_artifacts；
- 不要猜 artifact 文件名，优先 list_artifacts，再 read_artifact_range；
- 如果 list_artifacts 显示 constraints JSON，可以调用 run_z3 或 read_artifact_range 检查内容；
- 如果 list_artifacts 显示 decompile excerpt，调用 read_artifact_range 读取必要行段；
- 如果 profile_sample 返回 encoded_like，优先调用 decode_strings；
- 如果 decode_strings 返回 candidates，必须逐个调用 validate_candidate 验证，直到 accepted=true 或候选耗尽；
- 如果 profile_sample 没有 flag_like / encoded_like，但有 success_strings 或 failure_strings，调用 rank_functions；
- 如果 rank_functions 返回 suspicious functions，调用 decompile_function 查看 top function；
- 如果 profile_sample 没有 flag_like / encoded_like，但存在 success_strings 或 failure_strings，并且目标是 CTF reverse 求解，可以调用 run_angr_stdout；
- run_angr_stdout 返回的 candidate 仍然不是最终答案，必须调用 validate_candidate 验证；
- 优先使用较短 lengths，例如 [8, 12, 16, 24, 32]，如果失败再考虑 [40, 48, 64]；
- 如果 decompile_function 返回的 excerpt 明确包含逐字节约束、xor/add/sub/shift/and/or 比较，可以整理 constraints JSON 并调用 run_z3；
- run_z3 返回的 candidate 仍然不是最终答案，必须调用 validate_candidate；
- 不要凭空发明 constraints，只使用 excerpt 中明确支持的约束；
- 如果约束不完整，先说明缺少信息，不要伪造 flag；
- 如果你从 decompile_function 中整理出 constraints JSON，优先调用 write_artifact 保存为 constraints.generated.json，然后调用 run_z3({"constraints_path":"constraints.generated.json"})；
- 如果 artifact 太长，不要要求完整读取，调用 read_artifact_range 读取必要行段；
- write_artifact / read_artifact_range / list_artifacts 只能访问 artifact store 内部路径；
- 不要写入无关大文本，只保存 constraints、notes、solve 草稿等中间产物；
- decode_strings、rank_functions、run_angr_stdout、run_z3 的输出仍然只是证据，不是最终结论。

输出最终报告时包含：
- solved: true/false
- flag: 如果已验证则给出，否则为 null
- validation mode
- evidence
- artifacts
- next steps
"""


class OpenAIBrain:
    def __init__(
        self,
        store: ArtifactStore,
        model: str,
        max_steps: int = 8,
    ):
        self.store = store
        self.model = model
        self.max_steps = max_steps

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set")

        self.client = OpenAI(api_key=api_key)

        self.registry = build_default_ctf_registry(store)
        self.executor = ToolExecutor(self.registry, store)

    def run(self, sample_path: str, goal: str) -> dict[str, Any]:
        sample_path = str(Path(sample_path).resolve())

        input_items: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": (
                    f"Goal: {goal}\n"
                    f"Sample path: {sample_path}\n\n"
                    "Start with profile_sample. Keep tool usage minimal."
                ),
            },
        ]

        tools = _openai_tools(self.registry)

        final_text = ""
        solved = False
        verified_flag: str | None = None

        for step in range(1, self.max_steps + 1):
            self.store.append_jsonl(
                "agent_trace.jsonl",
                {
                    "event": "brain_step_start",
                    "step": step,
                    "model": self.model,
                },
            )

            response = self.client.responses.create(
                model=self.model,
                input=input_items,
                tools=tools,
                parallel_tool_calls=False,
            )

            output_items = list(response.output or [])
            function_calls = [
                item for item in output_items
                if getattr(item, "type", None) == "function_call"
            ]

            # 没有工具调用，说明模型给出了最终文本
            if not function_calls:
                final_text = getattr(response, "output_text", "") or ""
                self.store.write_text("final_answer.md", final_text)

                self.store.append_jsonl(
                    "agent_trace.jsonl",
                    {
                        "event": "brain_final",
                        "step": step,
                        "text": final_text[:2000],
                    },
                )

                return {
                    "status": "solved" if solved else "done",
                    "solved": solved,
                    "flag": verified_flag,
                    "final_answer": final_text,
                    "artifacts": ["final_answer.md", "agent_trace.jsonl"],
                }

            call = function_calls[0]
            tool_name = call.name
            arguments = _parse_tool_arguments(call.arguments)

            # 自动补 sample_path
            sample_path_tools = {
                "profile_sample",
                "validate_candidate",
                "decode_strings",
                "run_angr_stdout",
                "run_z3",
            }
            if tool_name in sample_path_tools:
                arguments.setdefault("sample_path", sample_path)

            # 补默认值
            if tool_name == "profile_sample":
                arguments.setdefault("skip_ghidra", True)
            if tool_name == "validate_candidate":
                arguments.setdefault("timeout", 10)
            if tool_name == "decompile_function":
                arguments.setdefault("max_lines", 80)

            result = self.executor.execute(tool_name, arguments)

            self.store.append_jsonl(
                "agent_trace.jsonl",
                {
                    "event": "brain_tool_call",
                    "step": step,
                    "tool": tool_name,
                    "arguments": arguments,
                    "ok": result.get("ok"),
                    "summary": result.get("summary"),
                },
            )

            # 把模型输出和工具输出加入下一轮上下文
            input_items.extend(_response_items_for_next_turn(output_items))
            input_items.append(
                {
                    "type": "function_call_output",
                    "call_id": call.call_id,
                    "output": json.dumps(
                        _compact_tool_result(result),
                        ensure_ascii=False,
                    ),
                }
            )

            # 验证成功则记录 solved
            if (
                tool_name == "validate_candidate"
                and result.get("ok") is True
                and result.get("data", {}).get("accepted") is True
            ):
                solved = True
                verified_flag = result.get("data", {}).get("candidate")

                input_items.append(
                    {
                        "role": "user",
                        "content": (
                            "validate_candidate returned accepted=true. "
                            "Do not call more tools. Produce the final solve report."
                        ),
                    }
                )

        # 超步数保护
        response = self.client.responses.create(
            model=self.model,
            input=input_items
            + [
                {
                    "role": "user",
                    "content": (
                        "Max tool steps reached. Summarize what was learned, "
                        "whether solved, and the next best engineering step."
                    ),
                }
            ],
            tools=[],
        )

        final_text = getattr(response, "output_text", "") or ""
        self.store.write_text("final_answer.md", final_text)

        self.store.append_jsonl(
            "agent_trace.jsonl",
            {
                "event": "brain_max_steps",
                "max_steps": self.max_steps,
                "solved": solved,
                "flag": verified_flag,
            },
        )

        return {
            "status": "solved" if solved else "max_steps_reached",
            "solved": solved,
            "flag": verified_flag,
            "final_answer": final_text,
            "artifacts": ["final_answer.md", "agent_trace.jsonl"],
        }


def _openai_tools(registry: ToolRegistry) -> list[dict[str, Any]]:
    """把 ToolRegistry 转成 Responses API function tools"""
    tools: list[dict[str, Any]] = []

    for name in registry.names():
        spec = registry.get(name)

        schema = dict(spec.input_schema)
        schema.setdefault("type", "object")
        schema.setdefault("additionalProperties", False)

        tools.append(
            {
                "type": "function",
                "name": spec.name,
                "description": spec.description,
                "parameters": schema,
                "strict": True,
            }
        )

    return tools


def _parse_tool_arguments(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid tool arguments JSON: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("tool arguments must be a JSON object")

    return data


def _compact_tool_result(result: dict[str, Any]) -> dict[str, Any]:
    """压缩工具输出，避免下一轮 prompt 过大"""
    data = result.get("data", {})

    if isinstance(data, dict):
        data = _truncate_dict(data, max_string=3000, max_list=30)

    return {
        "ok": result.get("ok"),
        "tool": result.get("tool"),
        "summary": result.get("summary"),
        "data": data,
        "artifacts": result.get("artifacts", []),
        "error": result.get("error"),
    }


def _truncate_dict(value: Any, max_string: int, max_list: int) -> Any:
    if isinstance(value, str):
        return value[:max_string]

    if isinstance(value, list):
        return [_truncate_dict(x, max_string, max_list) for x in value[:max_list]]

    if isinstance(value, dict):
        return {
            k: _truncate_dict(v, max_string, max_list)
            for k, v in value.items()
        }

    return value


def _response_items_for_next_turn(output_items: list[Any]) -> list[dict[str, Any]]:
    """把 Responses API output item 转成下一轮 input item"""
    converted: list[dict[str, Any]] = []

    for item in output_items:
        if hasattr(item, "model_dump"):
            converted.append(item.model_dump())
        elif isinstance(item, dict):
            converted.append(item)
        else:
            item_type = getattr(item, "type", "unknown")
            converted.append({"type": item_type})

    return converted
