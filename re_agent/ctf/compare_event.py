"""
CompareEvent - unified dynamic trace comparison event.

Cross-runner format: LtraceRunner, FridaRunner, GdbRunner all emit CompareEvent.
"""

from dataclasses import dataclass, field


@dataclass
class CompareEvent:
    """Structured comparison event from dynamic tracing"""
    source: str  # "ltrace", "frida", "gdb"
    function: str  # "strcmp", "memcmp", "strncmp"
    arg0_preview: str = ""
    arg1_preview: str = ""
    n: int | None = None
    return_value: int | None = None
    probe_side: str | None = None  # which arg matched our probe
    candidate_side: str | None = None  # the other arg (the secret)
    confidence: float = 0.0
    evidence_artifact: str = ""
    input_channel: str = "unknown"
