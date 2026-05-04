"""
Public contract tests - verify key model fields match commit expectations.
"""


def test_brain_action_memory_contract():
    from re_agent.brain.actions import BrainAction
    fields = BrainAction.model_fields
    assert "memory_refs" in fields
    assert "action_id" in fields
    assert "created_from" in fields


def test_brain_context_memory_contract():
    from re_agent.brain.context import BrainContext
    fields = BrainContext.model_fields
    assert "estimated_tokens" in fields


def test_observation_token_contract():
    from re_agent.core.observation import RuntimeObservation
    fields = RuntimeObservation.model_fields
    assert "token_hint" in fields
    obs = RuntimeObservation(tool="test", status="ok", summary="test")
    view = obs.to_brain_view()
    assert "tool" in view
    assert "summary" in view
    assert "candidate_count" in view


def test_memory_tactic_card_contract():
    from re_agent.brain.context import MemoryTacticCard
    card = MemoryTacticCard(
        id="pb_test", title="Test", source_type="user", priority=90,
        why_relevant="test match",
    )
    assert card.priority == 90
    assert card.source_type == "user"


def test_mock_brain_memory_driven():
    from re_agent.ctf.mock_brain import MockBrain
    from re_agent.brain.context import BrainContext, MemoryTacticCard

    brain = MockBrain()
    ctx = BrainContext(
        memory_hits=[{
            "id": "pb_test", "tool_recipe": [
                {"tool": "dynamic_trace", "params": {"channels": ["stdin"]}}
            ],
        }],
    )
    result = brain.plan(ctx)
    assert len(result.actions) >= 1
    action = result.actions[0]
    assert action.name == "dynamic_trace"
    assert "pb_test" in str(action.memory_refs)
