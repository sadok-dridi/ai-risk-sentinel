"""ModelRegistry — discovers and manages models across all providers."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from .base import Provider, ModelInfo, logger as base_logger
from .openai_compat import OpenAICompatProvider
from .ollama import OllamaProvider

logger = logging.getLogger(__name__)

# Provider type registry — map config "type" strings to classes
PROVIDER_TYPES = {
    "openai-compatible": OpenAICompatProvider,
    "openai": OpenAICompatProvider,
    "opencode": OpenAICompatProvider,       # most likely OpenAI-compatible
    "ollama": OllamaProvider,
}


class ModelRegistry:
    """Auto-discovers and manages models from all configured providers.

    Usage:
        registry = ModelRegistry.from_config(config_dict)
        registry.discover_all()              # parallel health check + model discovery
        models = registry.models             # dict[model_id, ModelInfo]
        provider, model = registry.resolve("deepseek-v4-pro")
    """

    def __init__(self, providers: list[Provider] | None = None):
        self._providers: dict[str, Provider] = {}
        self._models: dict[str, ModelInfo] = {}
        self._offline: set[str] = set()

        if providers:
            for p in providers:
                self._providers[p.name] = p

    # ── Factory ─────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config: dict) -> ModelRegistry:
        """Build registry from a config dictionary (parsed config.yaml).

        Example config:
            providers:
              - name: opencode
                type: openai-compatible
                base_url: https://api.opencode.ai/v1
                api_key: ${OPENCODE_API_KEY}
                enabled: true
              - name: ollama
                type: ollama
                base_url: http://localhost:11434
                enabled: false
        """
        registry = cls()
        provider_cfgs = config.get("providers", [])

        for cfg in provider_cfgs:
            if not cfg.get("enabled", True):
                logger.info(f"Skipping disabled provider: {cfg.get('name', 'unnamed')}")
                continue

            provider = cls._build_provider(cfg)
            if provider:
                registry._providers[provider.name] = provider

        return registry

    @classmethod
    def _build_provider(cls, cfg: dict) -> Provider | None:
        """Instantiate a provider from its config entry."""
        name = cfg.get("name", "unnamed")
        ptype = cfg.get("type", "openai-compatible")
        base_url = cfg.get("base_url", "")
        api_key = cfg.get("api_key", "")
        extra = cfg.get("extra", {})

        if not base_url:
            logger.warning(f"Provider '{name}': no base_url configured — skipping")
            return None

        provider_cls = PROVIDER_TYPES.get(ptype)
        if not provider_cls:
            logger.warning(f"Provider '{name}': unknown type '{ptype}' — skipping")
            return None

        try:
            return provider_cls(name=name, base_url=base_url, api_key=api_key, **extra)
        except Exception as e:
            logger.error(f"Provider '{name}': failed to initialize — {e}")
            return None

    # ── Discovery ───────────────────────────────────────────────────────

    def discover_all(self, parallel: bool = True) -> dict[str, list[ModelInfo]]:
        """Discover models from all providers. Returns {provider_name: [models]}.

        Unreachable providers are marked offline and skipped.
        """
        results: dict[str, list[ModelInfo]] = {}
        self._models.clear()
        self._offline.clear()

        providers = list(self._providers.values())

        if parallel and len(providers) > 1:
            results = self._discover_parallel(providers)
        else:
            results = self._discover_sequential(providers)

        # Flatten into self._models
        for pname, models in results.items():
            for m in models:
                self._models[m.id] = m

        return results

    def _discover_sequential(self, providers: list[Provider]) -> dict[str, list[ModelInfo]]:
        results = {}
        for p in providers:
            try:
                if p.check_health(timeout=5.0):
                    results[p.name] = p.list_models()
                else:
                    self._offline.add(p.name)
            except Exception as e:
                logger.warning(f"Provider '{p.name}': discovery failed — {e}")
                self._offline.add(p.name)
                results[p.name] = []
        return results

    def _discover_parallel(self, providers: list[Provider]) -> dict[str, list[ModelInfo]]:
        results = {}
        with ThreadPoolExecutor(max_workers=min(8, len(providers))) as executor:
            futures = {}
            for p in providers:
                futures[executor.submit(self._discover_one, p)] = p.name

            for future in as_completed(futures):
                pname = futures[future]
                try:
                    models = future.result()
                    results[pname] = models
                except Exception as e:
                    logger.warning(f"Provider '{pname}': parallel discovery failed — {e}")
                    self._offline.add(pname)
                    results[pname] = []

        return results

    def _discover_one(self, provider: Provider) -> list[ModelInfo]:
        if not provider.check_health(timeout=5.0):
            self._offline.add(provider.name)
            return []
        return provider.list_models()

    # ── Query ───────────────────────────────────────────────────────────

    @property
    def models(self) -> dict[str, ModelInfo]:
        return self._models

    @property
    def online_providers(self) -> list[Provider]:
        return [p for name, p in self._providers.items() if name not in self._offline]

    def resolve(self, model_id: str) -> tuple[Provider, ModelInfo]:
        """Resolve a model ID to its provider + metadata."""
        model = self._models.get(model_id)
        if not model:
            raise KeyError(f"Model '{model_id}' not found in registry. "
                           f"Available: {list(self._models.keys())}")
        provider = self._providers.get(model.provider)
        if not provider:
            raise KeyError(f"Provider '{model.provider}' for model '{model_id}' not found.")
        return provider, model

    def filter(self, provider: str | None = None, pattern: str | None = None,
               capabilities: list[str] | None = None) -> list[ModelInfo]:
        """Filter discovered models.

        Args:
            provider: Only models from this provider.
            pattern: Glob pattern for model ID (e.g., '*deepseek*').
            capabilities: Models must have ALL specified capabilities.
        """
        results = list(self._models.values())

        if provider:
            results = [m for m in results if m.provider == provider]
        if pattern:
            results = [m for m in results if m.matches_pattern(pattern)]
        if capabilities:
            results = [m for m in results
                       if all(c in m.capabilities for c in capabilities)]

        return sorted(results, key=lambda m: m.id)

    def add_provider(self, provider: Provider):
        """Add a provider at runtime."""
        self._providers[provider.name] = provider

    def add_static_models(self, provider_name: str, models: list[dict]):
        """Inject models without API discovery. Useful for providers that
        don't expose a /models endpoint or for testing.

        Each model dict: {id, owned_by?, context_window?, ...}
        """
        for m in models:
            mi = ModelInfo(
                id=m["id"],
                provider=provider_name,
                owned_by=m.get("owned_by", ""),
                context_window=m.get("context_window", 0),
                max_output_tokens=m.get("max_output_tokens", 0),
                supports_chat=m.get("supports_chat", True),
                capabilities=m.get("capabilities", ["chat"]),
            )
            self._models[mi.id] = mi

    @property
    def offline_providers(self) -> set[str]:
        return self._offline

    @property
    def model_count(self) -> int:
        return len(self._models)

    @property
    def provider_count(self) -> int:
        return len(self._providers)

    # ── Display ─────────────────────────────────────────────────────────

    def summary_table(self) -> str:
        """Human-readable summary of all discovered models, grouped by provider."""
        lines = []
        by_provider: dict[str, list[ModelInfo]] = {}
        for m in self._models.values():
            by_provider.setdefault(m.provider, []).append(m)

        for pname, models in sorted(by_provider.items()):
            provider = self._providers.get(pname)
            status = "✓" if pname not in self._offline else "✗ OFFLINE"
            lines.append(f"\n  {status} {pname} ({len(models)} models)")
            if provider:
                lines.append(f"    base_url: {provider.base_url}")
            for m in sorted(models, key=lambda x: x.id):
                caps_str = " ".join(m.capabilities) if m.capabilities else ""
                ctx = f"ctx={m.context_window // 1000}K" if m.context_window else ""
                owner = f"[{m.owned_by}]" if m.owned_by else ""
                lines.append(f"    {m.id:<35} {owner:<15} {ctx:<10} {caps_str}")

        return "\n".join(lines)
