# Project: AI Risk Sentinel — Agent Handoff

## Overview

AI Risk Sentinel is an ISO 42001 adversarial testing platform for LLMs. It runs attack scenarios against multiple AI model providers and evaluates whether the models are vulnerable (comply with harmful prompts) or resistant (refuse).

**Stack:** Python 3.11+ · FastAPI · Jinja2 · HTMX · Tailwind CSS v4  
**Target user:** ISO 42001 compliance consultants (TeamWill Groupe) testing client AI deployments.

## How it Works

1. User configures API providers (OpenAI, Anthropic, Ollama, etc.) in Settings
2. App discovers available models from each provider
3. User selects models + attack scenarios from the wizard
4. Attack runner fires prompts at each model × attack combination
5. Responses are evaluated via keyword matching or LLM judge → verdicts (vulnerable/resistant/error)
6. Results displayed as a matrix and detailed feed; HTML reports can be downloaded

## Key Files

| File | Purpose |
|------|---------|
| `app.py` | FastAPI routes (12 pages) + inline HTML for HTMX provider list |
| `db.py` | SQLite persistence (providers, models, runs, results, settings) |
| `providers/` | Model registry — discovers models from various API providers |
| `attacks/` | Attack definitions JSON + `AttackRunner` (parallel executor via ThreadPoolExecutor) |
| `reports/` | HTML report generator + AI governance policy document generator |
| `templates/` | 8 Jinja2 templates + 3 partials (all Tailwind) |
| `static/input.css` | Tailwind v4 source with custom Hermes-inspired theme |
| `static/styles.css` | Built output (generated via `npm run build`) |
| `static/htmx.min.js` | HTMX library for AJAX/SSE interactions |

## Design System (Hermes-inspired)

Defined in `static/input.css` `@theme`:

- **Base:** `#0a0f14` (dark carbon)
- **Accent:** `#5eead4` (cyan/teal)
- **Surfaces:** `color-mix(in srgb, <accent> <X>%, <base>)` where X = 4%, 6%, 8%, 12%
- **Border:** `color-mix(in srgb, <accent> 15%, transparent)`
- **Radius:** `0.5rem` (8px) base, subtracted 2px per nesting layer
- **Bevel shadow:** `inset -1px -1px 0 0 rgba(0,0,0,0.5), inset 1px 1px 0 0 rgba(255,255,255,0.07)`
- **Font:** Inter (sans), JetBrains Mono (code)
- **Arc border:** Class `.arc-border` adds animated gradient border (from Hermes)

Color tokens are CSS variables (`--color-midground`, `--color-card`, etc.) — used via inline `style=` in templates since Tailwind v4 doesn't natively support `color-mix()` as a utility.

## Running

```bash
cd demo2
pip install -r requirements.txt
npm run build     # rebuild Tailwind CSS
python app.py     # starts on http://0.0.0.0:8099
```

## Most Recent Work (this session)

- **Complete UI overhaul** — all templates rewritten from raw CSS to Tailwind v4 utility classes
- **Hermes-inspired theme** — `color-mix()` color system, 8px radius, bevel shadows, Inter font
- **Added build pipeline** — `npm run build` compiles `static/input.css` → `static/styles.css`
- **`app.py:_render_provider_list()`** — inline HTML updated to use new Tailwind-based classes
- **All 8 templates + 3 partials** converted: base, dashboard, discover, attacks, settings, history, results, running + model_list, progress, provider_form

## Templates Quick Reference

| Template | Route | Notes |
|----------|-------|-------|
| `base.html` | (layout) | Sticky header with nav, footer, `page-wrap` main container |
| `index.html` | `/` | Stat grid, provider mini-cards, last run card, recent runs table |
| `discover.html` | `/discover` | Discover button (HTMX POST), includes `model_list.html` partial |
| `attacks.html` | `/attacks` | 3-step wizard (models → attacks → review) with inline JS |
| `settings.html` | `/settings` | Preset provider grid, saved provider list, verdict engine toggle |
| `history.html` | `/history` | Full run history table |
| `results.html` | `/results/{id}` | Run stats, risk matrix table, detailed result cards with filter |
| `running.html` | `/run/{id}` | Live SSE feed, progress bar, live stats updates via JS |

## HTMX Patterns Used

- **Content swaps** — `hx-get`/`hx-post` with `hx-target`/`hx-swap` for dynamic partial rendering
- **Indicators** — `hx-indicator` shows spinners during requests
- **Redirects** — `/run` endpoint returns `HX-Redirect` header on form submit
- **SSE** — `/run/{run_id}/stream` provides `text/event-stream` for live run updates (consumed by vanilla JS `EventSource`, not HTMX)

## Common Issues / Gotchas

- **CSS variable reference in Tailwind:** Need `style="background: var(--color-card);"` because Tailwind v4 can't resolve `bg-[var(--color-card)]` when the CSS variable is defined as a `color-mix()`
- **`_render_provider_list()`** is inline HTML in `app.py` (not a template) — must be kept in sync with `settings.html`
- **Status dot CSS classes** use pattern `status-dot status-dot-{state}` (e.g. `status-dot-done`, `status-dot-error`)
- **Badge classes** use pattern `badge badge-{type}` (e.g. `badge-vulnerable`, `badge-resistant`)
- **Wizard steps** use inline `<style>` in `attacks.html` (kept small, could be moved to `input.css`)

## Style Convention

All templates use the same button/card pattern (copy-paste friendly):

```html
<button class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium
               transition-all duration-200 cursor-pointer"
        style="border: 1px solid var(--color-border); color: var(--color-foreground);
               background: var(--color-card); box-shadow: var(--shadow-bevel);">
  Text
</button>
```

Primary buttons swap to gradient:
```html
style="border: 1px solid transparent; color: #fff; 
       background: linear-gradient(135deg, var(--color-midground), color-mix(in srgb, ...));"
```

## Next Things to Build

- **Real-time audit log** — SSE stream of all actions (add provider, discover models, run attacks)
- **Compare view** — side-by-side model comparisons across attack categories
- **Export to Excel/PDF** — ISO 42001-compliant risk register export
- **Multi-client support** — switch between Neuraluna and other clients
- **Dark/light theme toggle** — second `@theme` in `input.css` with warm amber palette (already prepared)
- **Report template improvements** — the generated HTML reports could use the same Tailwind design
