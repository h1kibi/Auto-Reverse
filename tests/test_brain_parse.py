"""Test parse_brain_result with real MiMo-style broken JSON."""
import json
from re_agent.brain.base import parse_brain_result


def test_parse_mimo_broken_json():
    # Simulate: LLM puts valid actions JSON inside assumptions[0] as escaped string
    inner = json.dumps({
        "actions": [
            {"action_id": "s1", "kind": "run_solver", "name": "static_flag",
             "rationale": "scan strings", "risk": "none", "requires_validation": False}
        ]
    })
    raw = json.dumps({
        "actions": [],
        "assumptions": [inner],
        "stop_reason": "bad"
    })
    result = parse_brain_result(raw)
    assert len(result.actions) >= 1, f"Expected actions, got {len(result.actions)}"
    assert result.actions[0].name == "static_flag"
    assert result.actions[0].risk == "read_only"  # "none" normalized to "read_only"


def test_parse_normal_json():
    raw = json.dumps({"actions": [
        {"action_id": "s1", "kind": "run_solver", "name": "encoding",
         "rationale": "test", "risk": "read_only"}
    ]})
    result = parse_brain_result(raw)
    assert len(result.actions) == 1


def test_parse_list_directly():
    # Some models return just the action list
    raw = json.dumps([
        {"action_id": "s1", "kind": "run_solver", "name": "static_flag",
         "rationale": "test", "risk": "read_only"}
    ])
    result = parse_brain_result(raw)
    assert len(result.actions) == 1


def test_parse_invalid_fallback():
    result = parse_brain_result("not json at all")
    assert result.stop_reason == "invalid_brain_json"
    assert len(result.actions) == 0
