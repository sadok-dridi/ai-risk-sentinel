"""Provider abstract base class and shared data structures."""

from __future__ import annotations

import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ── Data Structures ────────────────────────────────────────────────────────

@dataclass
class ModelInfo:
    """Metadata about a discovered model."""
    id: str
    provider: str                        # "opencode", "openai", "ollama"
    owned_by: str = ""                   # "deepseek", "alibaba", "meta"
    context_window: int = 0
    max_output_tokens: int = 0
    supports_chat: bool = True
    supports_vision: bool = False
    supports_tools: bool = False
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    capabilities: list[str] = field(default_factory=list)
    raw_metadata: dict = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        return self.id

    @property
    def provider_display(self) -> str:
        if self.owned_by:
            return self.owned_by
        return self.provider

    def matches_pattern(self, pattern: str) -> bool:
        """Glob-style matching. `*deepseek*` matches deepseek-v4-pro."""
        import fnmatch
        return fnmatch.fnmatch(self.id.lower(), pattern.lower())


@dataclass
class ChatMessage:
    role: str                           # "system", "user", "assistant"
    content: str


@dataclass
class ChatResponse:
    content: str
    model: str
    finish_reason: str = "stop"          # "stop", "length", "content_filter"
    usage: dict = field(default_factory=dict)   # {"prompt_tokens": N, "completion_tokens": N}
    elapsed_ms: float = 0.0
    raw_response: dict = field(default_factory=dict)


# ── Provider ABC ────────────────────────────────────────────────────────────

class Provider(ABC):
    """Abstract base for any LLM provider."""

    name: str
    base_url: str
    api_key: str

    def __init__(self, name: str, base_url: str, api_key: str = "", **kwargs):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._extra = kwargs

    @abstractmethod
    def list_models(self) -> list[ModelInfo]:
        """Query the provider for available models."""
        ...

    @abstractmethod
    def chat(
        self,
        model: str,
        messages: list[ChatMessage],
        temperature: float = 0.0,
        max_tokens: int = 2048,
        **kwargs
    ) -> ChatResponse:
        """Send a chat completion request and return the response."""
        ...

    def check_health(self, timeout: float = 5.0) -> bool:
        """Quick connectivity check. Returns True if provider is reachable."""
        try:
            t0 = time.monotonic()
            models = self.list_models()
            elapsed = time.monotonic() - t0
            if elapsed > timeout:
                logger.warning(f"{self.name}: health check slow ({elapsed:.1f}s)")
            logger.info(f"{self.name}: healthy — {len(models)} models in {elapsed:.1f}s")
            return True
        except Exception as e:
            logger.warning(f"{self.name}: unhealthy — {e}")
            return False

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} base_url={self.base_url!r}>"


# ── Exceptions ──────────────────────────────────────────────────────────────

class ProviderError(Exception):
    """Base exception for provider failures."""

class AuthenticationError(ProviderError):
    """Invalid or missing API key."""

class RateLimitError(ProviderError):
    """Rate limited by the provider."""

class ModelNotFoundError(ProviderError):
    """Requested model not available."""

class ConnectionError(ProviderError):
    """Network or connectivity issue."""
