"""OpenAI-compatible provider. Covers any /v1/chat/completions API.

Works with:
- OpenAI API
- OpenCode API (user's 12 models)
- Mistral API
- Local vLLM / TGI / LiteLLM
- Any OpenAI-compatible proxy
"""

from __future__ import annotations

import time
import json
import logging
import urllib.request
import urllib.error
from typing import Optional

from .base import (
    Provider, ModelInfo, ChatMessage, ChatResponse,
    ProviderError, AuthenticationError, RateLimitError,
    ModelNotFoundError, ConnectionError,
)

logger = logging.getLogger(__name__)


class OpenAICompatProvider(Provider):
    """Provider for any OpenAI-compatible REST API.

    Endpoints used:
      GET  {base_url}/models              → list models
      POST {base_url}/chat/completions    → chat

    Config (config.yaml):
      providers:
        - name: opencode
          type: openai-compatible
          base_url: https://api.opencode.ai/v1    # or wherever
          api_key: ${OPENCODE_API_KEY}
          extra:
            default_model: deepseek-v4-pro
            headers:
              X-Custom-Header: value
    """

    def __init__(self, name: str, base_url: str, api_key: str = "", **kwargs):
        super().__init__(name, base_url, api_key, **kwargs)
        self._default_model = kwargs.get("default_model", "")
        self._extra_headers = kwargs.get("headers", {})

    # ── Model Discovery ─────────────────────────────────────────────────

    def list_models(self) -> list[ModelInfo]:
        """GET /v1/models → parse and return ModelInfo list."""
        data = self._request("GET", "/models")
        models = []

        raw_list = data.get("data", data.get("models", []))
        if not isinstance(raw_list, list):
            raw_list = []

        for entry in raw_list:
            model_id = entry.get("id", "")
            if not model_id:
                continue

            models.append(ModelInfo(
                id=model_id,
                provider=self.name,
                owned_by=entry.get("owned_by", ""),
                context_window=entry.get("context_window", entry.get("max_input_tokens", 0)),
                max_output_tokens=entry.get("max_output_tokens", 0),
                supports_chat=True,
                supports_vision=entry.get("supports_vision", False),
                supports_tools=entry.get("supports_tools", False),
                capabilities=self._infer_capabilities(model_id, entry),
                raw_metadata=entry,
            ))

        logger.info(f"{self.name}: discovered {len(models)} models")
        return models

    def _infer_capabilities(self, model_id: str, entry: dict) -> list[str]:
        """Guess capabilities from model ID and metadata."""
        caps = ["chat"]
        mid = model_id.lower()
        if any(w in mid for w in ["code", "coder"]):
            caps.append("code")
        if any(w in mid for w in ["vision", "vl", "multimodal"]):
            caps.append("vision")
        if any(w in mid for w in ["reason", "think", "deep"]):
            caps.append("reasoning")
        if any(w in mid for w in ["pro", "max", "large"]):
            caps.append("premium")
        if any(w in mid for w in ["flash", "mini", "lite", "tiny", "nano"]):
            caps.append("fast")
        return caps

    # ── Chat Completions ────────────────────────────────────────────────

    def chat(
        self,
        model: str,
        messages: list[ChatMessage],
        temperature: float = 0.0,
        max_tokens: int = 2048,
        **kwargs
    ) -> ChatResponse:
        """POST /v1/chat/completions → ChatResponse."""
        payload = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        payload.update(kwargs)

        t0 = time.monotonic()
        data = self._request("POST", "/chat/completions", body=payload)
        elapsed = (time.monotonic() - t0) * 1000

        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content", "") or ""
        reasoning = message.get("reasoning_content", "") or ""

        if reasoning:
            content = f"<reasoning>\n{reasoning}\n</reasoning>\n\n{content}"

        return ChatResponse(
            content=content,
            model=data.get("model", model),
            finish_reason=choice.get("finish_reason", "stop"),
            usage=data.get("usage", {}),
            elapsed_ms=elapsed,
            raw_response=data,
        )

    # ── HTTP Transport ──────────────────────────────────────────────────

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        """Make an HTTP request to the API. Returns parsed JSON."""
        url = f"{self.base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AI-Risk-Sentinel/2.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self._extra_headers)

        data_bytes = None
        if body is not None:
            data_bytes = json.dumps(body).encode("utf-8")

        try:
            req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            return self._handle_http_error(e)
        except urllib.error.URLError as e:
            raise ConnectionError(f"{self.name}: cannot reach {url} — {e.reason}") from e
        except json.JSONDecodeError as e:
            raise ProviderError(f"{self.name}: invalid JSON response from {url}") from e

    def _handle_http_error(self, error: urllib.error.HTTPError) -> dict:
        """Map HTTP status codes to exceptions."""
        try:
            body = json.loads(error.read().decode("utf-8"))
        except Exception:
            body = {"error": {"message": str(error)}}

        msg = body.get("error", {}).get("message", str(error))

        if error.code == 401:
            raise AuthenticationError(f"{self.name}: invalid API key — {msg}")
        if error.code == 429:
            raise RateLimitError(f"{self.name}: rate limited — {msg}")
        if error.code in (403, 404):
            raise ModelNotFoundError(f"{self.name}: model not found/forbidden — {msg}")
        raise ProviderError(f"{self.name}: HTTP {error.code} — {msg}")
