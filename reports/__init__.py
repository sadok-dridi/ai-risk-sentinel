"""Report generation — public API.

Usage:
    from reports import generate_html_report, generate_report_from_json
    from reports import generate_policy_document

    # From live results
    html_path = generate_html_report(results, attack_defs, client="Neuraluna")

    # From saved JSON
    html_path = generate_report_from_json("results/run.json", attack_defs, client="Neuraluna")

    # Policy documents
    html_path = generate_policy_document("usage", results, attack_defs, client="Neuraluna")
    html_path = generate_policy_document("incident", results, attack_defs, client="Neuraluna")
    html_path = generate_policy_document("supplier", results, attack_defs, client="Neuraluna")
    html_path = generate_policy_document("all", results, attack_defs, client="Neuraluna")
"""

from __future__ import annotations

import os
import time
import logging
from pathlib import Path
from typing import Optional, Literal

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .engine import ReportGenerator
from .policies import PolicyGenerator
from attacks.base import AttackResult, AttackDefinition

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_DEFAULT_OUTPUT = Path(__file__).parent.parent / "output" / "reports"

PolicyType = Literal["usage", "incident", "supplier", "all"]


def _get_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def generate_html_report(
    results: list[AttackResult],
    attack_defs: Optional[dict[str, AttackDefinition]] = None,
    client: str = "Neuraluna",
    lang: str = "fr",
    output_dir: Optional[str] = None,
) -> str:
    """Generate an HTML report from attack results.

    Args:
        results: List of AttackResult objects from a run.
        attack_defs: Attack definitions dict (attack_id -> AttackDefinition).
        client: Client name for the report header.
        lang: Report language ('fr' or 'en').
        output_dir: Directory to save the HTML file. Defaults to output/reports/.

    Returns:
        Absolute path to the generated HTML file.
    """
    generator = ReportGenerator(
        results=results,
        attack_defs=attack_defs or {},
        client=client,
        lang=lang,
    )

    context = generator.build_context()
    env = _get_env()

    template_name = f"report.{lang}.html"
    if not (_TEMPLATE_DIR / template_name).exists():
        logger.warning(f"Template '{template_name}' not found, falling back to report.fr.html")
        template_name = "report.fr.html"

    template = env.get_template(template_name)
    html = template.render(**context)

    out = Path(output_dir) if output_dir else _DEFAULT_OUTPUT
    out.mkdir(parents=True, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")
    filename = f"report_{client.lower().replace(' ', '_')}_{ts}.html"
    filepath = out / filename

    filepath.write_text(html, encoding="utf-8")
    logger.info(f"Report generated: {filepath}")

    return str(filepath.absolute())


def generate_report_from_json(
    json_path: str,
    attack_defs: Optional[dict[str, AttackDefinition]] = None,
    client: str = "Neuraluna",
    lang: str = "fr",
    output_dir: Optional[str] = None,
) -> str:
    """Generate an HTML report from a saved results JSON file.

    Args:
        json_path: Path to the results JSON file (e.g., 'results/run.json').
        attack_defs: Attack definitions dict.
        client: Client name.
        lang: Report language.
        output_dir: Output directory.

    Returns:
        Absolute path to the generated HTML file.
    """
    generator = ReportGenerator.from_json(
        json_path,
        attack_defs=attack_defs,
        client=client,
        lang=lang,
    )

    return generate_html_report(
        results=generator.results,
        attack_defs=attack_defs or {},
        client=client,
        lang=lang,
        output_dir=output_dir,
    )


def generate_policy_document(
    policy_type: PolicyType,
    results: Optional[list[AttackResult]] = None,
    attack_defs: Optional[dict[str, AttackDefinition]] = None,
    client: str = "Neuraluna",
    lang: str = "fr",
    output_dir: Optional[str] = None,
) -> list[str]:
    """Generate one or more governance policy documents.

    Args:
        policy_type: One of 'usage', 'incident', 'supplier', or 'all'.
        results: Attack results (can be empty list for template-only generation).
        attack_defs: Attack definitions dict.
        client: Client name.
        lang: Report language.
        output_dir: Output directory.

    Returns:
        List of absolute paths to generated HTML files.
    """
    generator = PolicyGenerator(
        results=results or [],
        attack_defs=attack_defs or {},
        client=client,
        lang=lang,
    )

    policy_configs = {
        "usage": ("policy_usage", generator.build_usage_policy_context()),
        "incident": ("policy_incident", generator.build_incident_policy_context()),
        "supplier": ("policy_supplier", generator.build_supplier_policy_context()),
    }

    if policy_type == "all":
        to_generate = list(policy_configs.values())
    elif policy_type in policy_configs:
        to_generate = [policy_configs[policy_type]]
    else:
        raise ValueError(f"Unknown policy type: '{policy_type}'. Use one of: usage, incident, supplier, all")

    env = _get_env()
    out = Path(output_dir) if output_dir else _DEFAULT_OUTPUT
    out.mkdir(parents=True, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")
    client_slug = client.lower().replace(" ", "_")
    paths = []

    for template_base, context in to_generate:
        template_name = f"{template_base}.{lang}.html"
        if not (_TEMPLATE_DIR / template_name).exists():
            logger.warning(f"Template '{template_name}' not found, skipping")
            continue

        template = env.get_template(template_name)
        html = template.render(**context)

        filename = f"{template_base}_{client_slug}_{ts}.html"
        filepath = out / filename
        filepath.write_text(html, encoding="utf-8")
        logger.info(f"Policy document generated: {filepath}")
        paths.append(str(filepath.absolute()))

    return paths
