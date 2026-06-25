"""Policy document generator — auto-fills governance documents from tool data."""

from __future__ import annotations

import time
from typing import Optional
from collections import defaultdict

from attacks.base import AttackResult, AttackDefinition, Verdict
from .engine import ReportGenerator, ReportStats


class PolicyGenerator:
    """Builds Jinja2 template context for governance documents.

    Each document type draws from the same data sources (attack results,
    attack definitions, model registry) to auto-fill policy sections.
    """

    def __init__(
        self,
        results: Optional[list[AttackResult]] = None,
        attack_defs: Optional[dict[str, AttackDefinition]] = None,
        client: str = "Neuraluna",
        lang: str = "fr",
    ):
        self.results = results or []
        self.attack_defs = attack_defs or {}
        self.client = client
        self.lang = lang
        self.stats = ReportGenerator(
            results=self.results, attack_defs=self.attack_defs, client=client, lang=lang
        ).compute_stats()

    # ── Shared helpers ──────────────────────────────────────────────────

    @property
    def date(self) -> str:
        return time.strftime("%d/%m/%Y")

    def _attacks_by_category(self) -> dict[str, list[AttackDefinition]]:
        grouped = defaultdict(list)
        for defn in self.attack_defs.values():
            grouped[defn.category].append(defn)
        return dict(grouped)

    def _vulnerable_attacks(self) -> list[str]:
        if not self.results:
            return []
        attacked = set()
        for r in self.results:
            if r.verdict == Verdict.VULNERABLE:
                attacked.add(r.attack_id)
        return sorted(attacked)

    def _worst_severity(self) -> str:
        order = {"Extrême": 4, "Élevé": 3, "Moyen": 2, "Faible": 1}
        worst = "Faible"
        worst_val = 0
        for defn in self.attack_defs.values():
            val = order.get(defn.severity, 0)
            if val > worst_val:
                worst_val = val
                worst = defn.severity
        return worst

    # ── Context builders ────────────────────────────────────────────────

    def build_usage_policy_context(self) -> dict:
        """Context for Politique d'Usage de l'IA."""
        # Extract prohibited uses from attack definitions
        prohibited = []
        for defn in self.attack_defs.values():
            prohibited.append({
                "action": self._prohibited_label(defn.attack_id),
                "risk": defn.rsk_id,
                "description": defn.description,
                "severity": defn.severity,
            })

        # Sort by severity
        severity_order = {"Extrême": 0, "Élevé": 1, "Moyen": 2, "Faible": 3}
        prohibited.sort(key=lambda x: severity_order.get(x["severity"], 99))

        # Build approved tools from results — list distinct models tested
        models_used = sorted(set(r.model_id for r in self.results)) if self.results else []

        return {
            "client": self.client,
            "date": self.date,
            "lang": self.lang,
            "worst_severity": self._worst_severity(),
            "vulnerability_rate": self.stats.vulnerability_rate,
            "resistance_rate": self.stats.resistance_rate,
            "prohibited_uses": prohibited,
            "models_tested": models_used,
            "total_attacks_tested": len(self.attack_defs),
            "total_models_tested": len(models_used),
        }

    def build_incident_policy_context(self) -> dict:
        """Context for Procédure de Réponse aux Incidents IA."""
        # Build incident types from attack categories
        incident_types = []
        category_labels = {
            "input_manipulation": "Injection / Contournement",
            "data_exposure": "Fuite de Données",
            "output_integrity": "Contenu Toxique / Hallucination",
            "misuse": "Usage Frauduleux",
        }

        for category, defs in self._attacks_by_category().items():
            rsk_ids = [d.rsk_id for d in defs]
            incident_types.append({
                "category": category,
                "label": category_labels.get(category, category.replace("_", " ").title()),
                "risks": rsk_ids,
                "count": len(rsk_ids),
                "description": defs[0].description if defs else "",
            })

        # Check if personal data scenarios exist
        has_personal_data = any(
            d.rsk_id in ("RSK-IA-02", "RSK-IA-19", "RSK-IA-18")
            for d in self.attack_defs.values()
        )

        return {
            "client": self.client,
            "date": self.date,
            "lang": self.lang,
            "incident_types": incident_types,
            "has_personal_data": has_personal_data,
            "cnil_72h": has_personal_data,  # CNIL notification under 72h if personal data
            "vulnerability_rate": self.stats.vulnerability_rate,
            "contacts": {
                "dsi": "DSI (Directeur des Systèmes d'Information)",
                "rssi": "RSSI (Responsable Sécurité SI)",
                "dpo": "DPO (Délégué à la Protection des Données)" if has_personal_data else "",
            },
        }

    def build_supplier_policy_context(self) -> dict:
        """Context for Grille d'Évaluation Fournisseurs IA."""
        # Build criteria from what we know about the models tested
        providers = set()
        for r in self.results:
            providers.add((r.model_id, r.provider))

        models_list = sorted(
            [{"model_id": mid, "provider": prov} for mid, prov in providers],
            key=lambda x: x["model_id"],
        )

        criteria = [
            {"id": "sovereignty", "label": "Souveraineté des données", "weight": 25,
             "description": "Localisation des données, loi applicable, transferts hors UE"},
            {"id": "rgpd", "label": "Conformité RGPD", "weight": 25,
             "description": "DPA signé, sous-traitants déclarés, DPIA disponible, droit d'audit"},
            {"id": "security", "label": "Sécurité", "weight": 20,
             "description": "ISO 27001, SOC 2, chiffrement des données, pentests réguliers"},
            {"id": "transparency", "label": "Transparence", "weight": 15,
             "description": "Modèle documenté, données d'entraînement, auditabilité"},
            {"id": "sla", "label": "SLA et Support", "weight": 15,
             "description": "Disponibilité garantie, support, réversibilité des données"},
        ]

        return {
            "client": self.client,
            "date": self.date,
            "lang": self.lang,
            "criteria": criteria,
            "max_total": 100,
            "acceptance_threshold": 70,
            "models_evaluated": models_list,
            "total_models": len(models_list),
            "vulnerability_rate": self.stats.vulnerability_rate,
        }

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _prohibited_label(attack_id: str) -> str:
        labels = {
            "injection": "Injecter des instructions dans les prompts externes",
            "jailbreak": "Contourner les restrictions de sécurité du modèle",
            "secrets": "Saisir des secrets, mots de passe ou clés API dans les prompts",
            "dataleak": "Saisir des données personnelles non anonymisées (IBAN, CB, etc.)",
            "hallucination": "Utiliser les sorties IA sans validation humaine pour des décisions critiques",
            "phishing": "Générer du contenu frauduleux ou des emails de phishing",
            "toxic": "Générer du contenu discriminatoire, offensant ou toxique",
        }
        return labels.get(attack_id, f"Usage non autorisé ({attack_id})")
