"""
Core errors - unified exception hierarchy.
"""

from __future__ import annotations


class ReverseAgentError(Exception):
    """Base error for all auto-reverse exceptions."""
    pass


class ToolError(ReverseAgentError):
    """Tool execution failure."""
    def __init__(self, tool: str, message: str):
        self.tool = tool
        super().__init__(f"[{tool}] {message}")


class ToolNotFoundError(ToolError):
    """Tool not registered."""
    pass


class ToolTimeoutError(ToolError):
    """Tool execution timed out."""
    pass


class SandboxError(ReverseAgentError):
    """Sandbox execution failure."""
    pass


class PolicyDenied(ReverseAgentError):
    """Action rejected by execution policy."""
    pass


class SolverError(ReverseAgentError):
    """Solver execution failure."""
    def __init__(self, solver: str, message: str):
        self.solver = solver
        super().__init__(f"[{solver}] {message}")


class ValidationError(ReverseAgentError):
    """Validation / constraint schema failure."""
    pass


class ConfigError(ReverseAgentError):
    """Configuration error."""
    pass
