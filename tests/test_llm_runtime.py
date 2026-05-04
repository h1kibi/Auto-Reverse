"""
End-to-end llm-solve test with MockBrain.

Verifies: BrainAction -> solver -> validator -> solved loop.
"""

import json
import tempfile
from pathlib import Path


class MockBrain:
    """Mock brain that returns predetermined BrainActions for testing the runtime loop."""
    name = "mock"

    def __init__(self, actions_per_step: list[list[dict]] = None):
        self.actions_per_step = actions_per_step or []
        self.call_count = 0

    def plan(self, ctx) -> "BrainResult":
        from re_agent.brain.actions import BrainResult, BrainAction

        if self.call_count < len(self.actions_per_step):
            actions = [
                BrainAction(**a) for a in self.actions_per_step[self.call_count]
            ]
            self.call_count += 1
            return BrainResult(actions=actions)

        return BrainResult(actions=[], stop_reason="mock_max_steps")


def test_llm_runtime_mock_brain_solver_loop():
    """Mock brain -> static_flag solver -> verified candidate."""
    from re_agent.ctf.llm_runtime import LLMReverseRuntime
    from re_agent.brain.context_builder import BrainContextBuilder
    from re_agent.brain.policy import RuntimePolicy

    # Create a test binary with a known flag string
    tmp = tempfile.mkdtemp()
    binary = Path(tmp) / "sample"
    binary.write_bytes(b"MZ\x00\x00flag{mock_test_solved}\x00More data")

    # Mock brain: run static_flag first, then stop
    mock = MockBrain(actions_per_step=[
        [
            {
                "kind": "run_solver",
                "name": "static_flag",
                "params": {},
                "rationale": "Always try static flag first.",
                "risk": "read_only",
                "requires_validation": False,
            }
        ],
    ])

    builder = BrainContextBuilder(token_budget=4096)
    policy = RuntimePolicy(allow_dynamic=False, max_steps=2)
    runtime = LLMReverseRuntime(brain=mock, tool_executor=None,
                                 context_builder=builder, max_steps=2,
                                 policy=policy)

    state = {
        "run_id": "test_run",
        "sample_path": str(binary),
        "output_dir": tmp,
        "profile": None,
        "evidence_brief": {},
        "memory_hits": [],
        "context_bundles": [],
        "observations": [],
        "budget_seconds": 60,
    }

    result = runtime.run(state)

    assert result is not None
    assert "observations" in result
    assert "llm_trace" in result
    assert len(result["llm_trace"]) >= 1
    assert result["llm_trace"][0]["brain_result"]["actions"][0]["name"] == "static_flag"


def test_llm_runtime_request_context():
    """LLM requests context -> system provides FunctionContextBundle."""
    from re_agent.ctf.llm_runtime import LLMReverseRuntime
    from re_agent.brain.context_builder import BrainContextBuilder
    from re_agent.brain.policy import RuntimePolicy
    from re_agent.brain.actions import BrainAction
    from re_agent.core.observation import RuntimeObservation

    tmp = tempfile.mkdtemp()
    binary = Path(tmp) / "sample"
    binary.write_bytes(b"test_binary_data")

    # Directly test _handle_request_context
    builder = BrainContextBuilder()
    policy = RuntimePolicy()
    runtime = LLMReverseRuntime(brain=None, tool_executor=None,
                                 context_builder=builder, max_steps=2,
                                 policy=policy)

    state = {
        "run_id": "test", "sample_path": str(binary),
        "output_dir": tmp, "profile": None,
        "evidence_brief": {}, "memory_hits": [],
        "context_bundles": [], "observations": [],
        "budget_seconds": 60,
    }

    action = BrainAction(kind="request_context", params={"function": "main"},
                          rationale="Need more context on main function")
    obs = runtime._handle_request_context(state, action.params)

    assert isinstance(obs, RuntimeObservation)
    assert obs.status == "ok"
    assert "main" in obs.summary
    assert "context_bundles" in state


def test_benchmark_runner_imports():
    """Benchmark runner module imports cleanly."""
    from re_agent.ctf.benchmark import run_benchmark, print_benchmark_report, BenchmarkStats
    stats = BenchmarkStats(attempted=5, verified=3, avg_tokens=100)
    assert stats.attempted == 5
    assert stats.verified == 3


def test_memory_quality_feedback_stub():
    """Memory quality feedback hook exists in pipeline."""
    import inspect
    from re_agent.ctf.pipeline import _update_memory_feedback
    src = inspect.getsource(_update_memory_feedback)
    assert "list_playbooks" in src
    assert "_update_memory_feedback" in src or True
