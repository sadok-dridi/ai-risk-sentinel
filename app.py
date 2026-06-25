#!/usr/bin/env python3
"""AI Risk Sentinel — Web Dashboard (FastAPI + HTMX)

Usage:
    cd demo2 && python3 app.py
    Open http://localhost:8099
"""

from __future__ import annotations

import sys
import os
import re
import json
import time
import queue
import asyncio
import threading
from pathlib import Path
from typing import Optional

# Local directory for resolving paths
_APP_DIR = Path(__file__).parent

from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from providers import ModelRegistry
from attacks import AttackRunner, AttackRunConfig, AttackDefinition, Verdict

import db

# ── App setup ────────────────────────────────────────────────────────────

app = FastAPI(title="AI Risk Sentinel", version="3.0")

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)

def render(request: Request, template: str, **ctx) -> HTMLResponse:
    tpl = env.get_template(template)
    ctx.setdefault("request", request)
    return HTMLResponse(tpl.render(**ctx))

# ── Config loading (reused from demo) ────────────────────────────────────

def _load_config() -> dict:
    config_path = _APP_DIR / "config.yaml"
    if not config_path.exists():
        return {"providers": [], "attacks": {"core": [], "targeted": {}}, "output": {}}

    import yaml
    with open(config_path) as f:
        raw = yaml.safe_load(f)

    def _resolve(val):
        if not isinstance(val, str):
            return val
        def _replacer(m):
            expr = m.group(1)
            if ":-" in expr:
                var, default = expr.split(":-", 1)
                return os.environ.get(var.strip(), default.strip())
            return os.environ.get(expr, "")
        return re.sub(r'\$\{([^}]+)\}', _replacer, val)

    def _walk(obj):
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_walk(i) for i in obj]
        return _resolve(obj)

    return _walk(raw)


_config = _load_config()

# ── Global registry + runner (lazy init) ─────────────────────────────────

_registry: Optional[ModelRegistry] = None
_runner: Optional[AttackRunner] = None
_attack_defs: dict[str, AttackDefinition] = {}

# Active run state (keyed by run_id)
_active_runs: dict[str, queue.Queue] = {}

def _get_registry() -> ModelRegistry:
    global _registry
    if _registry is None:
        _registry = ModelRegistry.from_config(_config)
    return _registry

def _get_runner() -> AttackRunner:
    global _runner, _attack_defs
    if _runner is None:
        _runner = AttackRunner(_get_registry())
        defs_path = _APP_DIR / "attacks" / "definitions.json"
        if defs_path.exists():
            _runner.load_definitions(str(defs_path))
        _attack_defs = _runner.definitions
    return _runner

# ── Routes: Pages ────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    runs = db.list_runs(limit=10)
    last_run = runs[0] if runs else None
    return render(request, "index.html", last_run=last_run, runs=runs, len=len)


@app.get("/discover", response_class=HTMLResponse)
def discover_page(request: Request):
    cached = db.get_cached_models()
    return render(request, "discover.html", models=cached, model_count=len(cached))


@app.post("/discover", response_class=HTMLResponse)
def discover_action(request: Request):
    registry = _get_registry()
    try:
        registry.discover_all(parallel=True)
    except Exception as e:
        models_raw = []
        error_msg = str(e)
    else:
        models_raw = [{"id": m.id, "provider": m.provider, "owned_by": m.owned_by,
                       "context_window": m.context_window, "capabilities": m.capabilities}
                      for m in sorted(registry.models.values(), key=lambda x: x.id)]
        error_msg = ""
        db.save_models(models_raw)

    return render(request, "partials/model_list.html", models=models_raw, error=error_msg)


@app.get("/attacks", response_class=HTMLResponse)
def attacks_page(request: Request):
    runner = _get_runner()
    cached = db.get_cached_models()
    attacks = sorted(_attack_defs.values(), key=lambda a: a.attack_id)
    return render(request, "attacks.html", models=cached, attacks=attacks,
                  model_count=len(cached), attack_count=len(attacks))


@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request):
    runs = db.list_runs(limit=50)
    return render(request, "history.html", runs=runs, len=len)


@app.get("/run/{run_id}", response_class=HTMLResponse)
def run_page(run_id: str, request: Request):
    r = db.get_run(run_id)
    if not r:
        return HTMLResponse("<p class='error'>Run not found.</p>", status_code=404)
    return render(request, "running.html", run=r)


@app.get("/results/{run_id}", response_class=HTMLResponse)
def results_page(run_id: str, request: Request):
    r = db.get_run(run_id)
    if not r:
        return HTMLResponse("<p class='error'>Run not found.</p>", status_code=404)
    results_raw = db.get_run_results(run_id)

    # Build matrix
    models = sorted(set(rr["model_id"] for rr in results_raw))
    attacks = sorted(set(rr["attack_id"] for rr in results_raw))
    lookup = {(rr["model_id"], rr["attack_id"]): rr["verdict"] for rr in results_raw}

    return render(request, "results.html", run=r, results=results_raw, models=models,
                  attacks=attacks, lookup=lookup, len=len)


# ── Routes: Actions ──────────────────────────────────────────────────────

@app.post("/run", response_class=HTMLResponse)
def start_run(
    client: str = Form("Neuraluna"),
    models_json: str = Form("[]"),
    attacks_json: str = Form("[]"),
):
    import json as _json
    model_ids = _json.loads(models_json)
    attack_ids = _json.loads(attacks_json)

    if not model_ids or not attack_ids:
        return HTMLResponse("<p class='error'>Select at least one model and one attack.</p>")

    runner = _get_runner()
    run_id = db.create_run(client)

    config = AttackRunConfig(
        models=model_ids,
        attacks=attack_ids if "all" not in attack_ids else ["all"],
        parallel=True,
        max_workers=4,
        timeout_per_attack=30,
        save_responses=False,
    )
    db.update_run(run_id, status="running", config_json=_json.dumps({
        "models": model_ids, "attacks": attack_ids, "client": client,
    }))

    total = len(attack_ids) * len(model_ids) if "all" not in attack_ids else len(runner.definitions) * len(model_ids)
    db.update_run(run_id, total_tests=total)

    # Create SSE queue for this run
    q: queue.Queue = queue.Queue()
    _active_runs[run_id] = q

    # Fire background thread
    def _run():
        try:
            results = runner.run(config)
            for r in results:
                d = r.to_dict()
                db.save_result(run_id, d)
                q.put({"event": "result", "data": d})
            # Compute stats
            res_list = db.get_run_results(run_id)
            vuln = sum(1 for rr in res_list if rr["verdict"] == "vulnerable")
            resist = sum(1 for rr in res_list if rr["verdict"] == "resistant")
            err = sum(1 for rr in res_list if rr["verdict"] == "error")
            db.update_run(run_id, status="done", completed_tests=len(res_list),
                         vulnerable_count=vuln, resistant_count=resist, error_count=err)
        except Exception as e:
            db.update_run(run_id, status="error")
            q.put({"event": "error", "data": {"message": str(e)}})
        finally:
            q.put({"event": "done", "data": {"run_id": run_id}})

    threading.Thread(target=_run, daemon=True).start()

    # HTMX redirect to running page
    return HTMLResponse(
        f'<script>window.location.href="/run/{run_id}";</script>',
        headers={"HX-Redirect": f"/run/{run_id}"},
    )


@app.get("/run/{run_id}/stream")
async def run_stream(run_id: str):
    q = _active_runs.get(run_id)
    if not q:
        # Run already done, return final state
        return StreamingResponse(
            _send_final(run_id),
            media_type="text/event-stream",
        )

    async def _stream():
        yield f"data: {json.dumps({'event': 'start', 'data': {'run_id': run_id}})}\n\n"
        loop = asyncio.get_event_loop()
        while True:
            try:
                msg = await loop.run_in_executor(None, lambda: q.get(timeout=10))
                yield f"event: {msg['event']}\ndata: {json.dumps(msg['data'])}\n\n"
                if msg["event"] == "done":
                    break
                if msg["event"] == "error":
                    break
            except queue.Empty:
                yield ": keepalive\n\n"

    return StreamingResponse(_stream(), media_type="text/event-stream")


async def _send_final(run_id: str):
    """When the run is already done (no active queue)."""
    r = db.get_run(run_id)
    if not r:
        yield f"data: {json.dumps({'event': 'error', 'data': {'message': 'Run not found'}})}\n\n"
        return
    results = db.get_run_results(run_id)
    for rr in results:
        yield f"event: result\ndata: {json.dumps(rr)}\n\n"
    yield f"event: done\ndata: {json.dumps({'run_id': run_id})}\n\n"


@app.get("/run/{run_id}/matrix", response_class=HTMLResponse)
def run_matrix(run_id: str, request: Request):
    """HTMX partial: returns the results matrix for a completed run."""
    return results_page(run_id, request)


@app.get("/report/{run_id}")
def download_report(run_id: str):
    from reports import generate_html_report
    results = db.get_run_results_as_result_objects(run_id)
    r = db.get_run(run_id)
    client = r["client"] if r else "Neuraluna"
    try:
        path = generate_html_report(results, _attack_defs, client=client)
        return FileResponse(path, filename=Path(path).name, media_type="text/html")
    except Exception as e:
        return PlainTextResponse(f"Report generation failed: {e}", status_code=500)


@app.get("/policy/{policy_type}")
def download_policy(policy_type: str):
    from reports import generate_policy_document
    try:
        if policy_type == "all":
            paths = generate_policy_document("all", attack_defs=_attack_defs)
            from fastapi.responses import JSONResponse
            return JSONResponse({"documents": [{"name": Path(p).stem, "url": f"/policy/download/{Path(p).name}"} for p in paths]})
        paths = generate_policy_document(policy_type, attack_defs=_attack_defs)
        if not paths:
            return PlainTextResponse("No templates found.", status_code=404)
        return FileResponse(paths[0], filename=Path(paths[0]).name, media_type="text/html")
    except Exception as e:
        return PlainTextResponse(f"Policy generation failed: {e}", status_code=500)


@app.get("/policy/download/{filename}")
def download_policy_file(filename: str):
    """Serve a generated policy file by name from output/reports/."""
    path = Path(__file__).parent / "output" / "reports" / filename
    if not path.exists():
        return PlainTextResponse("File not found.", status_code=404)
    return FileResponse(str(path), filename=filename, media_type="text/html")


@app.get("/progress/{run_id}", response_class=HTMLResponse)
def progress_partial(run_id: str, request: Request):
    """HTMX partial: returns current progress bar for a running/completed run."""
    r = db.get_run(run_id)
    if not r:
        return HTMLResponse("<p>Run not found.</p>")
    return render(request, "partials/progress.html", run=r)


# ── Entry ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print(f"\n  AI Risk Sentinel v3.0")
    print(f"  http://localhost:8099\n")
    uvicorn.run(app, host="0.0.0.0", port=8099, log_level="info")
