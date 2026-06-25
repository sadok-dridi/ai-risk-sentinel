"""Providers package — LLM backend abstraction."""

from .base import (
    Provider,
    ModelInfo,
    ChatMessage,
    ChatResponse,
    ProviderError,
    AuthenticationError,
    RateLimitError,
    ModelNotFoundError,
    ConnectionError,
)
from .openai_compat import OpenAICompatProvider
from .ollama import OllamaProvider
from .registry import ModelRegistry, PROVIDER_TYPES

__all__ = [
    "Provider",
    "ModelInfo",
    "ChatMessage",
    "ChatResponse",
    "ProviderError",
    "AuthenticationError",
    "RateLimitError",
    "ModelNotFoundError",
    "ConnectionError",
    "OpenAICompatProvider",
    "OllamaProvider",
    "ModelRegistry",
    "PROVIDER_TYPES",
]
