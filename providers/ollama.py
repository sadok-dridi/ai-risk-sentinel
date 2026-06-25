"""Ollama provider for local LLM models."""

from __future__ import annotations

import time
import json
import logging
import urllib.request
import urllib.error
from typing import Optional

from .base import (
    Provider, ModelInfo, ChatMessage, ChatResponse,
    ProviderError, ConnectionError,
)

logger = logging.getLogger(__name__)


class OllamaProvider(Provider):
    """Provider for local Ollama instances.

    Endpoints used:
      GET  {base_url}/api/tags       → list models
      POST {base_url}/api/chat       → chat
    """

    def __init__(self, name: str = "ollama", base_url: str = "http://localhost:11434",
                 api_key: str = "", **kwargs):
        super().__init__(name, base_url, api_key, **kwargs)

    # ── Model Discovery ─────────────────────────────────────────────────

    def list_models(self) -> list[ModelInfo]:
        """GET /api/tags → list local models."""
        data = self._request("GET", "/api/tags")
        models = []

        for entry in data.get("models", []):
            model_id = entry.get("name", entry.get("model", ""))
            if not model_id:
                continue

            details = entry.get("details", {})
            models.append(ModelInfo(
                id=model_id,
                provider=self.name,
                owned_by=details.get("family", "local"),
                context_window=entry.get("context_length", 0),
                max_output_tokens=0,
                supports_chat=True,
                supports_vision="vision" in model_id.lower(),
                capabilities=self._infer_capabilities(model_id),
                raw_metadata=entry,
            ))

        logger.info(f"{self.name}: discovered {len(models)} local models")
        return models

    def _infer_capabilities(self, model_id: str) -> list[str]:
        caps = ["chat", "local"]
        mid = model_id.lower()
        if "code" in mid:
            caps.append("code")
        if "vision" in mid:
            caps.append("vision")
        return caps

    # ── Chat ────────────────────────────────────────────────────────────

    def chat(
        self,
        model: str,
        messages: list[ChatMessage],
        temperature: float = 0.0,
        max_tokens: int = 2048,
        **kwargs
    ) -> ChatResponse:
        """POST /api/chat → ChatResponse."""
        payload = {
            "model": model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        t0 = time.monotonic()
        data = self._request("POST", "/api/chat", body=payload)
        elapsed = (time.monotonic() - t0) * 1000

        content = data.get("message", {}).get("content", "") or ""

        return ChatResponse(
            content=content,
            model=data.get("model", model),
            finish_reason=data.get("done_reason", "stop"),
            usage={
                "prompt_tokens": data.get("prompt_eval_count", 0),
                "completion_tokens": data.get("eval_count", 0),
            },
            elapsed_ms=elapsed,
            raw_response=data,
        )

    # ── HTTP ────────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}

        data_bytes = None
        if body is not None:
            data_bytes = json.dumps(body).encode("utf-8")

        try:
            req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw)
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"{self.name}: cannot reach {url} — is Ollama running? ({e.reason})"
            ) from e
        except json.JSONDecodeError as e:
            raise ProviderError(f"{self.name}: invalid JSON from {url}") from e
