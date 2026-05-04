"""
Brain module - LLM adapter layer for Auto-Reverse.
"""

from .actions import BrainAction, BrainResult
from .context import BrainContext
from .base import Brain, parse_brain_result
from .context_builder import BrainContextBuilder, approx_tokens
from .deepseek import DeepSeekBrain, OpenAICompatibleBrain, OpenAIBrain, MiMoBrain
from .prompts import PLANNER_SYSTEM_PROMPT, PROMPT_VERSION
from .policy import PolicyGate, RuntimePolicy

__all__ = [
    "BrainAction",
    "BrainResult",
    "BrainContext",
    "Brain",
    "parse_brain_result",
    "BrainContextBuilder",
    "approx_tokens",
    "DeepSeekBrain",
    "OpenAICompatibleBrain",
    "OpenAIBrain",
    "MiMoBrain",
    "PLANNER_SYSTEM_PROMPT",
    "PROMPT_VERSION",
    "PolicyGate",
    "RuntimePolicy",
]
