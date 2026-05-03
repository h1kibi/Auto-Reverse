"""
LLM 适配器 - 支持多种模型

支持：
- MiMo API (小米)
- OpenAI 兼容 API
- 本地模型
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
import json
import logging
import requests

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """聊天消息"""
    role: str  # system, user, assistant, tool
    content: str
    name: Optional[str] = None
    tool_call_id: Optional[str] = None


@dataclass
class ToolCall:
    """工具调用"""
    id: str
    type: str = "function"
    function: dict = field(default_factory=dict)


@dataclass
class ChatResponse:
    """聊天响应"""
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict = field(default_factory=dict)


class BaseLLMClient(ABC):
    """LLM 客户端基类"""

    @abstractmethod
    def chat(
        self,
        messages: list[ChatMessage],
        tools: list[dict] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> ChatResponse:
        """发送聊天请求"""
        pass


class MiMoClient(BaseLLMClient):
    """小米 MiMo API 客户端"""

    def __init__(
        self,
        api_key: str,
        model: str = "mimo-v2.5-pro",
        base_url: str = "https://api.xiaomimimo.com/v1",
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    def chat(
        self,
        messages: list[ChatMessage],
        tools: list[dict] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> ChatResponse:
        """发送聊天请求"""
        url = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # 构建请求体
        body = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            body["tools"] = tools

        try:
            resp = requests.post(url, headers=headers, json=body, timeout=120)
            resp.raise_for_status()
            data = resp.json()

            # 解析响应
            choice = data["choices"][0]
            message = choice["message"]

            tool_calls = []
            if "tool_calls" in message:
                for tc in message["tool_calls"]:
                    tool_calls.append(ToolCall(
                        id=tc["id"],
                        type=tc.get("type", "function"),
                        function=tc["function"],
                    ))

            return ChatResponse(
                content=message.get("content", ""),
                tool_calls=tool_calls,
                usage=data.get("usage", {}),
            )

        except Exception as e:
            logger.error(f"MiMo API error: {e}")
            raise


class OpenAICompatClient(BaseLLMClient):
    """OpenAI 兼容 API 客户端"""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4",
        base_url: str = "https://api.openai.com/v1",
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    def chat(
        self,
        messages: list[ChatMessage],
        tools: list[dict] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
    ) -> ChatResponse:
        """发送聊天请求"""
        url = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        body = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            body["tools"] = tools

        try:
            resp = requests.post(url, headers=headers, json=body, timeout=120)
            resp.raise_for_status()
            data = resp.json()

            choice = data["choices"][0]
            message = choice["message"]

            tool_calls = []
            if "tool_calls" in message:
                for tc in message["tool_calls"]:
                    tool_calls.append(ToolCall(
                        id=tc["id"],
                        type=tc.get("type", "function"),
                        function=tc["function"],
                    ))

            return ChatResponse(
                content=message.get("content", ""),
                tool_calls=tool_calls,
                usage=data.get("usage", {}),
            )

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise


class LLMFactory:
    """LLM 客户端工厂"""

    @staticmethod
    def create(
        provider: str = "mimo",
        api_key: str = None,
        model: str = None,
        base_url: str = None,
    ) -> BaseLLMClient:
        """创建 LLM 客户端"""
        import os

        if provider == "mimo":
            return MiMoClient(
                api_key=api_key or os.getenv("MIMO_API_KEY", ""),
                model=model or "mimo-v2.5-pro",
                base_url=base_url or "https://api.xiaomimimo.com/v1",
            )
        elif provider == "openai":
            return OpenAICompatClient(
                api_key=api_key or os.getenv("OPENAI_API_KEY", ""),
                model=model or "gpt-4",
                base_url=base_url or "https://api.openai.com/v1",
            )
        else:
            raise ValueError(f"Unknown provider: {provider}")
