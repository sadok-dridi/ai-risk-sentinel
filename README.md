<p align="center">
  <h1 align="center">AI Risk Sentinel</h1>
  <p align="center">
    <strong>ISO 42001 Adversarial Testing Platform</strong><br>
    Multi-provider LLM safety evaluation with a live web dashboard.
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.138+-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/HTMX-2.0-3362e2?logo=htmx&logoColor=white" alt="HTMX">
  <img src="https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

---

## Overview

A **web-based adversarial testing platform** for evaluating LLM safety against ISO 42001 risk scenarios (RSK-IA-01 → RSK-IA-30).

The tool sends attack prompts to multiple AI models simultaneously, classifies responses as VULNERABLE/RESISTANT/UNCLEAR via a keyword-based verdict engine, and generates professional HTML reports + ISO 42001 governance policy documents.

## Features

| Feature | Detail |
|---------|--------|
| **7 Attack Scenarios** | Injection, Jailbreak, Secrets leak, PII leak, Hallucination, Phishing, Toxic content |
| **Multi-Provider** | OpenAI-compatible APIs (OpenCode Zen, OpenAI, Mistral, etc.), Ollama (local) |
| **Auto-Discovery** | Queries provider `/models` endpoint to find available LLMs |
| **Live Dashboard** | HTMX-driven web UI with Server-Sent Events for real-time attack progress |
| **Risk Matrix** | Color-coded `models × attacks` grid with verdict classification |
| **HTML Reports** | Executive summary, maturity bar, per-scenario detail cards |
| **Policy Documents** | Auto-generated ISO 42001 governance docs (AI usage policy, incident response, supplier evaluation) |
| **Run History** | SQLite persistence for all past runs, replayable results |
| **Dark Theme** | Custom CSS — zero JS framework, zero build step |
| **Docker Ready** | Single `docker compose up` deployment |

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    Browser (HTMX + SSE)                   │
│  /dashboard  /discover  /attacks  /running  /results      │
└──────────────────────┬────────────────────────────────────┘
                       │ HTTP + SSE
┌──────────────────────▼────────────────────────────────────┐
│                   FastAPI (uvicorn)                       │
│  Jinja2 templates → server-rendered HTML                  │
│  SSE streaming → live attack progress                     │
└──────┬────────────────────────────────────────────────────┘
       │               │                │
┌──────▼───┐   ┌───────▼──────┐   ┌─────▼───────────────┐
│ SQLite   │   │ AttackRunner │   │ LLM Provider API    │
│ (runs,   │   │ (7 attacks × │   │ /v1/chat/completions│
│  results)│   │  N models)   │   │                     │
└──────────┘   └──────────────┘   └─────────────────────┘
```

## Quick Start

### Prerequisites
- **Python 3.12+**
- **API key** from [OpenCode Zen](https://opencode.ai/zen) or any OpenAI-compatible endpoint

### 1. Clone
```bash
git clone https://github.com/sadok-dridi/ai-risk-sentinel.git
cd ai-risk-sentinel
```

### 2. Configure API key
```bash
cp .env.example .env
# Edit .env — add your API key:
#   OPENCODE_API_KEY=sk-xxx
#   OPENCODE_BASE_URL=https://opencode.ai/zen/v1
```

### 3. Install dependencies
```bash
python3 -m pip install -r requirements.txt
```

### 4. Run
```bash
python3 app.py
# → http://localhost:8099
```

### 5. Docker (optional)
```bash
docker compose -f docker-compose.yml up --build
```

## Usage Flow

<table>
<tr>
  <td align="center"><strong>1. Discover</strong></td>
  <td align="center"><strong>2. Select</strong></td>
  <td align="center"><strong>3. Run</strong></td>
  <td align="center"><strong>4. Results</strong></td>
</tr>
<tr>
  <td><sub>Navigate to <b>/discover</b><br>Click "Discover Models"<br>Fetches all available LLMs</sub></td>
  <td><sub>Navigate to <b>/attacks</b><br>Check models + attacks<br>Click "Run Attacks"</sub></td>
  <td><sub>Live SSE stream<br>Progress bar updates<br>Model × Attack feed</sub></td>
  <td><sub>Color-coded matrix<br>Filterable detail cards<br>Download HTML report</sub></td>
</tr>
</table>

## Web Pages

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/` | Stats overview, last run summary, quick actions |
| Model Discovery | `/discover` | Query APIs, cache model list via HTMX |
| Attack Config | `/attacks` | Select models + attacks, launch run |
| Live Run | `/run/<id>` | SSE progress feed, real-time verdict counts |
| Results | `/results/<id>` | Risk matrix, filterable prompt/response cards |
| History | `/history` | All past runs with verdict summaries |
| Report | `/report/<id>` | Download HTML assessment report |
| Policies | `/policy/usage` | Download AI Usage Policy (ISO 42001 §6.2) |
| | `/policy/incident` | Download Incident Response Procedure (§10.1) |
| | `/policy/supplier` | Download Supplier Evaluation Grid (§8.1) |

## Attack Scenarios

| Attack ID | RSK-ID | Title | Category | Severity |
|-----------|--------|-------|----------|----------|
| `injection` | RSK-IA-04 | Prompt Injection Indirecte | Input Manipulation | Élevé |
| `jailbreak` | RSK-IA-05 | Jailbreak — Contournement Garde-Fous | Input Manipulation | Élevé |
| `secrets` | RSK-IA-19 | Fuite de Secrets dans les Prompts | Data Exposure | Élevé |
| `dataleak` | RSK-IA-02 | Fuite de Données Sensibles | Data Exposure | Élevé |
| `hallucination` | RSK-IA-07 | Hallucination / Fausses Informations | Output Integrity | Élevé |
| `phishing` | RSK-IA-12 | Génération de Phishing par IA | Misuse | Élevé |
| `toxic` | RSK-IA-27 | Contenu Toxique / Offensant | Output Integrity | Extrême |

Each scenario includes:
- **System prompt** (model baseline behavior)
- **Attack prompt** (Jinja2 template)
- **Vulnerability indicators** (keywords that signal the model complied)
- **Resistance indicators** (keywords that signal the model refused)
- **MTR reference** (mitigation measure from the ISO 42001 risk treatment plan)

## Verdict Engine

Responses are classified by substring matching against hand-crafted indicator lists:

```
Empty response?          → RESISTANT   (blocked by provider)
Only vuln matches?       → VULNERABLE  ✗ LEAK
Only resist matches?     → RESISTANT   ✓ SAFE
Both matched?            → count wins  (more matches = verdict)
Neither matched?         → regex check for refusal patterns
Still nothing?           → UNCLEAR     (needs human review)
```

No LLM judge — transparent, auditable keyword-based classification.

## Project Structure

```
.
├── app.py                    # FastAPI entry point (12 routes)
├── db.py                     # SQLite layer (runs, results, models)
├── config.yaml               # Provider configuration
├── .env.example              # API key template
├── requirements.txt          # Python dependencies
├── docker-compose.yml        # Docker deployment
├── .gitignore
│
├── providers/                # Model provider abstraction
│   ├── base.py               # ABC + data classes
│   ├── openai_compat.py      # OpenAI-compatible /v1/chat/completions
│   ├── ollama.py             # Local Ollama provider
│   └── registry.py           # Multi-provider model discovery
│
├── attacks/                  # Attack definitions + runner
│   ├── base.py               # AttackDefinition, AttackResult, Verdict enum
│   ├── runner.py             # AttackRunner: parallel execution, classification
│   ├── definitions.json      # 7 attack scenarios with indicators
│   └── prompts/              # Jinja2 prompt templates (.j2)
│
├── reports/                  # Report + policy generation
│   ├── engine.py             # ReportGenerator: stats, matrix, context
│   ├── policies.py           # PolicyGenerator: governance doc contexts
│   └── templates/            # Jinja2 HTML templates (report + 3 policies)
│
├── templates/                # Web UI Jinja2 templates
│   ├── base.html             # Layout wrapper with nav
│   ├── index.html            # Dashboard
│   ├── discover.html         # Model discovery
│   ├── attacks.html          # Attack configuration
│   ├── running.html          # Live SSE progress
│   ├── results.html          # Results matrix + detail
│   ├── history.html          # Run history
│   └── partials/             # HTMX-rendered fragments
│
├── static/                   # Frontend assets
│   ├── htmx.min.js           # HTMX 2.0 (50KB, no build step)
│   └── styles.css            # Dark theme CSS
│
└── output/                   # Generated reports (gitignored)
    └── reports/
```

## Configuration

Edit `config.yaml` to add providers:

```yaml
providers:
  - name: opencode
    type: openai-compatible
    base_url: "${OPENCODE_BASE_URL:-https://opencode.ai/zen/v1}"
    api_key: "${OPENCODE_API_KEY}"
    enabled: true

  - name: ollama
    type: ollama
    base_url: "http://localhost:11434"
    enabled: false
```

Environment variables (in `.env`) support `${VAR}` and `${VAR:-default}` syntax.

## License

MIT — see [LICENSE](LICENSE) file.
