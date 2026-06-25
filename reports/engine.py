"""Report engine — aggregates attack results, computes stats, builds template context."""

from __future__ import annotations

import time
import json
from pathlib import Path
from typing import Optional, Union
from dataclasses import dataclass, field
from collections import defaultdict

from attacks.base import AttackResult, AttackDefinition, Verdict


@dataclass
class ReportStats:
    """Aggregated statistics from a batch of attack results."""
    total_tests: int = 0
    vulnerable: int = 0
    resistant: int = 0
    unclear: int = 0
    error: int = 0
    skipped: int = 0

    @property
    def vulnerability_rate(self) -> float:
        valid = self.vulnerable + self.resistant
        if valid == 0:
            return 0.0
        return round(self.vulnerable / valid * 100, 1)

    @property
    def resistance_rate(self) -> float:
        valid = self.vulnerable + self.resistant
        if valid == 0:
            return 0.0
        return round(self.resistant / valid * 100, 1)


class ReportGenerator:
    """Aggregates attack results into a Jinja2 template context."""

    def __init__(
        self,
        results: list[AttackResult],
        attack_defs: Optional[dict[str, AttackDefinition]] = None,
        client: str = "Neuraluna",
        lang: str = "fr",
    ):
        self.results = results
        self.attack_defs = attack_defs or {}
        self.client = client
        self.lang = lang

    # ── Stats ────────────────────────────────────────────────────────────

    def compute_stats(self) -> ReportStats:
        stats = ReportStats()
        stats.total_tests = len(self.results)

        for r in self.results:
            if r.verdict == Verdict.VULNERABLE:
                stats.vulnerable += 1
            elif r.verdict == Verdict.RESISTANT:
                stats.resistant += 1
            elif r.verdict == Verdict.UNCLEAR:
                stats.unclear += 1
            elif r.verdict == Verdict.ERROR:
                stats.error += 1
            elif r.verdict == Verdict.SKIPPED:
                stats.skipped += 1

        return stats

    # ── Matrix ───────────────────────────────────────────────────────────

    def build_matrix(self) -> dict:
        models = sorted(set(r.model_id for r in self.results))
        attacks = sorted(set(r.attack_id for r in self.results))

        lookup: dict[tuple[str, str], str] = {}
        for r in self.results:
            lookup[(r.model_id, r.attack_id)] = r.verdict.value

        cells = {}
        for model in models:
            for attack in attacks:
                cells[f"{model}|{attack}"] = lookup.get((model, attack), "skipped")

        return {
            "models": models,
            "attacks": attacks,
            "cells": cells,
        }

    # ── Per-Attack Details ───────────────────────────────────────────────

    def per_attack_details(self) -> list[dict]:
        attacks = {}
        for r in self.results:
            aid = r.attack_id
            if aid not in attacks:
                attacks[aid] = []
            attacks[aid].append(r)

        details = []
        for aid in sorted(attacks):
            group = attacks[aid]
            definition = self.attack_defs.get(aid)

            vuln = [r for r in group if r.verdict == Verdict.VULNERABLE]
            resist = [r for r in group if r.verdict == Verdict.RESISTANT]

            details.append({
                "attack_id": aid,
                "rsk_id": definition.rsk_id if definition else "",
                "title": definition.title if definition else aid,
                "category": definition.category if definition else "",
                "severity": definition.severity if definition else "",
                "description": definition.description if definition else "",
                "mtr_reference": definition.mtr_reference if definition else "",
                "mtr_description": definition.mtr_description if definition else "",
                "prompt": definition.prompt_template[:300] if definition else "",
                "results": [
                    {
                        "model_id": r.model_id,
                        "verdict": r.verdict.value,
                        "verdict_label": _verdict_label(r.verdict, self.lang),
                        "response": r.response[:500] if r.response else "",
                        "matched_indicators": r.matched_indicators,
                        "error_message": r.error_message,
                    }
                    for r in sorted(group, key=lambda x: x.model_id)
                ],
                "vulnerable_count": len(vuln),
                "resistant_count": len(resist),
                "total_tested": len(group),
            })

        return details

    # ── Per-Model Summary ────────────────────────────────────────────────

    def per_model_summary(self) -> list[dict]:
        models = {}
        for r in self.results:
            mid = r.model_id
            if mid not in models:
                models[mid] = {"provider": r.provider, "verdicts": defaultdict(int)}
            models[mid]["verdicts"][r.verdict.value] += 1

        summary = []
        for mid in sorted(models):
            info = models[mid]
            vuln = info["verdicts"].get("vulnerable", 0)
            resist = info["verdicts"].get("resistant", 0)
            valid = vuln + resist
            rate = round(vuln / valid * 100, 1) if valid > 0 else 0.0

            summary.append({
                "model_id": mid,
                "provider": info["provider"],
                "vulnerable_count": vuln,
                "resistant_count": resist,
                "unclear_count": info["verdicts"].get("unclear", 0),
                "error_count": info["verdicts"].get("error", 0),
                "total_tested": sum(info["verdicts"].values()),
                "vulnerability_rate": rate,
            })

        return summary

    # ── Recommendations ──────────────────────────────────────────────────

    def recommendations(self) -> list[dict]:
        seen = {}
        for aid, defn in self.attack_defs.items():
            if defn.mtr_reference and defn.mtr_reference not in seen:
                seen[defn.mtr_reference] = {
                    "mtr_ref": defn.mtr_reference,
                    "description": defn.mtr_description,
                    "severity": defn.severity,
                    "related_attacks": [aid],
                }
            elif defn.mtr_reference:
                seen[defn.mtr_reference]["related_attacks"].append(aid)

        severity_order = {"Extrême": 0, "Élevé": 1, "Moyen": 2, "Faible": 3}
        return sorted(seen.values(), key=lambda x: severity_order.get(x["severity"], 99))

    # ── Full Context ─────────────────────────────────────────────────────

    def build_context(self) -> dict:
        stats = self.compute_stats()
        matrix = self.build_matrix()
        attacks = self.per_attack_details()
        models = self.per_model_summary()
        recs = self.recommendations()

        return {
            "client": self.client,
            "date": time.strftime("%d/%m/%Y"),
            "lang": self.lang,
            "total_models": len(matrix["models"]),
            "total_attacks": len(matrix["attacks"]),
            "total_tests": stats.total_tests,

            "stats": {
                "vulnerable": stats.vulnerable,
                "resistant": stats.resistant,
                "unclear": stats.unclear,
                "error": stats.error,
                "skipped": stats.skipped,
                "vulnerability_rate": stats.vulnerability_rate,
                "resistance_rate": stats.resistance_rate,
            },

            "matrix": matrix,
            "per_attack": attacks,
            "per_model": models,
            "recommendations": recs,
        }

    # ── Helpers ──────────────────────────────────────────────────────────

    @classmethod
    def from_json(cls, path: str, attack_defs: Optional[dict[str, AttackDefinition]] = None,
                  client: str = "Neuraluna", lang: str = "fr") -> "ReportGenerator":
        full_path = Path(path)
        if not full_path.exists():
            raise FileNotFoundError(f"Results file not found: {path}")

        with open(full_path, "r") as f:
            data = json.load(f)

        results = []
        for entry in data.get("results", []):
            results.append(AttackResult(
                attack_id=entry.get("attack_id", ""),
                rsk_id=entry.get("rsk_id", ""),
                model_id=entry.get("model_id", ""),
                provider=entry.get("provider", ""),
                verdict=Verdict(entry.get("verdict", "unclear")),
                prompt=entry.get("prompt", ""),
                response=entry.get("response", ""),
                finish_reason=entry.get("finish_reason", ""),
                elapsed_ms=entry.get("elapsed_ms", 0),
                tokens_prompt=entry.get("tokens_prompt", 0),
                tokens_completion=entry.get("tokens_completion", 0),
                matched_indicators=entry.get("matched_indicators", []),
                error_message=entry.get("error_message", ""),
            ))

        return cls(results=results, attack_defs=attack_defs, client=client, lang=lang)


# ── Translation helpers ───────────────────────────────────────────────

def _verdict_label(verdict: Verdict, lang: str = "fr") -> str:
    if lang == "fr":
        return {
            Verdict.VULNERABLE: "VULNÉRABLE",
            Verdict.RESISTANT: "RÉSISTANT",
            Verdict.UNCLEAR: "INCERTAIN",
            Verdict.ERROR: "ERREUR",
            Verdict.SKIPPED: "IGNORÉ",
        }.get(verdict, "?")
    return {
        Verdict.VULNERABLE: "VULNERABLE",
        Verdict.RESISTANT: "RESISTANT",
        Verdict.UNCLEAR: "UNCLEAR",
        Verdict.ERROR: "ERROR",
        Verdict.SKIPPED: "SKIPPED",
    }.get(verdict, "?")
