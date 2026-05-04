"""
MockBrain - for CI and benchmark testing without real LLM API.

Memory-driven: uses MemoryTacticCards to decide actions.
Evidence-driven: uses comparison/crypto/encoding hints as fallback.
"""

from re_agent.brain.actions import BrainAction, BrainResult


class MockBrain:
    name = "mock"

    def plan(self, ctx):
        # memory-driven
        memory_cards = getattr(ctx, "memory_cards", None) or ctx.memory_hits or []
        if memory_cards:
            card = memory_cards[0]
            if isinstance(card, dict):
                tool_seq = card.get("tool_sequence") or card.get("tool_recipe", [])
            else:
                tool_seq = getattr(card, "tool_sequence", []) or getattr(card, "tool_recipe", [])
            if tool_seq:
                step = tool_seq[0]
                if isinstance(step, dict):
                    tool = step.get("tool", "static_flag")
                    params = step.get("params", {})
                else:
                    tool = str(step)
                    params = {}
                card_id = card if isinstance(card, str) else getattr(card, "id", str(card))
                return BrainResult(actions=[
                    BrainAction(
                        action_id="mock_memory_step",
                        kind="run_solver", name=tool, params=params,
                        rationale=f"Following {card_id}",
                        memory_refs=[card_id if isinstance(card_id, str) else str(card_id)],
                        risk="executes_sample",
                        created_from="memory",
                    )
                ])

        # evidence-driven fallback
        evidence = getattr(ctx, "evidence_summary", {}) or getattr(ctx, "profile", {}) or {}
        hints = str(evidence).lower()
        if "memcmp" in hints or "strcmp" in hints:
            return BrainResult(actions=[
                BrainAction(
                    action_id="mock_dynamic",
                    kind="run_solver", name="dynamic_trace",
                    params={"channels": ["stdin", "argv"]},
                    rationale="comparison hint found in evidence",
                    risk="executes_sample", created_from="brain",
                )
            ])

        if "xor" in hints or "hex" in hints or "base64" in hints:
            return BrainResult(actions=[
                BrainAction(
                    action_id="mock_encoding",
                    kind="run_solver", name="encoding",
                    params={}, rationale="encoding hint found",
                    created_from="brain",
                )
            ])

        # default: try static_flag
        return BrainResult(actions=[
            BrainAction(
                action_id="mock_static",
                kind="run_solver", name="static_flag",
                params={}, rationale="always try static flag first",
                risk="read_only", requires_validation=False,
                created_from="brain",
            )
        ])
