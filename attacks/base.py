"""Attack scenario base classes and data structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Verdict ─────────────────────────────────────────────────────────────────

class Verdict(Enum):
    """Classification of an attack result against an AI model."""
    VULNERABLE = "vulnerable"        # Model complied with the attack
    RESISTANT = "resistant"          # Model refused or blocked the attack
    UNCLEAR = "unclear"              # Ambiguous response — needs human review
    ERROR = "error"                  # API error, timeout, model unavailable
    SKIPPED = "skipped"              # Attack not applicable to this model


# ── Attack Definition ───────────────────────────────────────────────────────

@dataclass
class AttackDefinition:
    """Metadata for a single attack scenario, mapped to RSK-IA-XX."""

    attack_id: str                           # "injection", "jailbreak", etc.
    rsk_id: str                              # "RSK-IA-04"
    title: str                               # Human-readable title
    category: str                            # "input_manipulation", "data_exposure", etc.
    severity: str                            # "Faible", "Moyen", "Élevé", "Extrême"
    difficulty: str                          # "Très simple", "Simple", "Moyen", "Complexe"
    description: str                         # What the attack does
    requires_llm: bool = True                # Needs real LLM or simulation works
    mtr_reference: str = ""                  # "MTR-005"
    mtr_description: str = ""                # Mitigation recommendation

    # System prompt used for the AI under test
    system_prompt: str = ""

    # Prompt template (Jinja2) — rendered before sending
    prompt_template: str = ""

    # Patterns to check in the response for verdict classification
    vulnerability_indicators: list[str] = field(default_factory=list)
    resistance_indicators: list[str] = field(default_factory=list)

    # Which model capabilities are relevant (for targeted attacks)
    target_capabilities: list[str] = field(default_factory=list)

    # Glob patterns for models this attack targets (empty = all models)
    target_model_patterns: list[str] = field(default_factory=list)

    # Tags for grouping/filtering
    tags: list[str] = field(default_factory=list)


# ── Attack Result ───────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    """Result of executing one attack against one model."""

    attack_id: str
    rsk_id: str
    model_id: str
    provider: str
    verdict: Verdict = Verdict.UNCLEAR
    prompt: str = ""
    response: str = ""
    finish_reason: str = ""
    elapsed_ms: float = 0.0
    tokens_prompt: int = 0
    tokens_completion: int = 0
    matched_indicators: list[str] = field(default_factory=list)
    error_message: str = ""
    raw_response: dict = field(default_factory=dict)

    @property
    def is_vulnerable(self) -> bool:
        return self.verdict == Verdict.VULNERABLE

    @property
    def is_resistant(self) -> bool:
        return self.verdict == Verdict.RESISTANT

    @property
    def display_verdict(self) -> str:
        symbols = {
            Verdict.VULNERABLE: "VULNERABLE",
            Verdict.RESISTANT: "RESISTANT",
            Verdict.UNCLEAR: "UNCLEAR",
            Verdict.ERROR: "ERROR",
            Verdict.SKIPPED: "SKIPPED",
        }
        return symbols.get(self.verdict, "?")

    def to_dict(self) -> dict:
        return {
            "attack_id": self.attack_id,
            "rsk_id": self.rsk_id,
            "model_id": self.model_id,
            "provider": self.provider,
            "verdict": self.verdict.value,
            "prompt": self.prompt,
            "response": self.response,
            "finish_reason": self.finish_reason,
            "elapsed_ms": self.elapsed_ms,
            "tokens_prompt": self.tokens_prompt,
            "tokens_completion": self.tokens_completion,
            "matched_indicators": self.matched_indicators,
            "error_message": self.error_message,
        }


# ── Attack Registry Entry (from JSON) ───────────────────────────────────────

@dataclass
class AttackRegistryEntry:
    """Deserialized attack definition from JSON."""
    attack_id: str
    rsk_id: str
    title: str
    category: str
    severity: str
    difficulty: str
    description: str
    requires_llm: bool = True
    mtr_reference: str = ""
    mtr_description: str = ""
    system_prompt: str = ""
    prompt_template: str = ""
    vulnerability_indicators: list[str] = field(default_factory=list)
    resistance_indicators: list[str] = field(default_factory=list)
    target_capabilities: list[str] = field(default_factory=list)
    target_model_patterns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_definition(self) -> AttackDefinition:
        return AttackDefinition(**self.__dict__)
