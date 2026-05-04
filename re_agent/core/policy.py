"""
Execution Policy - security guardrails for dynamic analysis.

Default: everything is locked down. Users must explicitly enable risky features.
"""

from dataclasses import dataclass

from .errors import PolicyDenied  # unified exception


@dataclass
class ExecutionPolicy:
    """Execution security policy"""
    allow_network: bool = False
    allow_write_sample_dir: bool = False
    allow_mutation: bool = False
    require_dynamic_confirmation: bool = True
    max_runtime_seconds: int = 10
    max_memory_mb: int = 256
    max_output_bytes: int = 2_000_000
    redact_candidates_in_logs: bool = False

    def check_network(self) -> None:
        if not self.allow_network:
            raise PolicyDenied("Network access is disabled by default.")

    def check_mutation(self) -> None:
        if not self.allow_mutation:
            raise PolicyDenied("Binary mutation is disabled by default.")

    def check_dynamic(self) -> None:
        if self.require_dynamic_confirmation:
            raise PolicyDenied("Dynamic execution requires explicit confirmation.")


def check_policy(tool_spec, policy: ExecutionPolicy) -> None:
    """Check if a tool is allowed under the given policy"""
    from .toolspec import ToolRisk

    if tool_spec.risk == ToolRisk.NETWORK:
        policy.check_network()

    if tool_spec.risk == ToolRisk.MUTATES_BINARY:
        policy.check_mutation()

    if tool_spec.risk == ToolRisk.EXECUTES_SAMPLE:
        if policy.require_dynamic_confirmation:
            raise PolicyDenied(
                f"Tool '{tool_spec.name}' requires sample execution. "
                "Set require_dynamic_confirmation=False or use --confirm."
            )
