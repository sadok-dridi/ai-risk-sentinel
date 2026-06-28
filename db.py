"""Database layer — SQLite schema, queries, persistence."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "demo2.db"


@contextmanager
def _conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


SCHEMA_VERSION = 2


def init_db():
    with _conn() as c:
        c.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                client TEXT NOT NULL DEFAULT 'Neuraluna',
                status TEXT NOT NULL DEFAULT 'pending',
                config_json TEXT NOT NULL DEFAULT '{}',
                total_tests INTEGER NOT NULL DEFAULT 0,
                completed_tests INTEGER NOT NULL DEFAULT 0,
                vulnerable_count INTEGER NOT NULL DEFAULT 0,
                resistant_count INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS run_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                attack_id TEXT NOT NULL,
                rsk_id TEXT NOT NULL DEFAULT '',
                model_id TEXT NOT NULL,
                provider TEXT NOT NULL DEFAULT '',
                verdict TEXT NOT NULL DEFAULT 'error',
                judge_verdict TEXT NOT NULL DEFAULT '',
                judge_reason TEXT NOT NULL DEFAULT '',
                prompt TEXT NOT NULL DEFAULT '',
                response TEXT NOT NULL DEFAULT '',
                matched_indicators TEXT NOT NULL DEFAULT '[]',
                error_message TEXT NOT NULL DEFAULT '',
                elapsed_ms REAL NOT NULL DEFAULT 0,
                tokens_prompt INTEGER NOT NULL DEFAULT 0,
                tokens_completion INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_results_run ON run_results(run_id);
            CREATE INDEX IF NOT EXISTS idx_results_verdict ON run_results(verdict);

            CREATE TABLE IF NOT EXISTS discovered_models (
                id TEXT NOT NULL,
                provider_id INTEGER NOT NULL DEFAULT 0,
                provider TEXT NOT NULL DEFAULT '',
                owned_by TEXT NOT NULL DEFAULT '',
                context_window INTEGER NOT NULL DEFAULT 0,
                capabilities TEXT NOT NULL DEFAULT '[]',
                discovered_at TEXT NOT NULL,
                PRIMARY KEY (provider_id, id)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS provider_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                api_key TEXT NOT NULL DEFAULT '',
                provider_type TEXT NOT NULL DEFAULT 'openai-compatible',
                enabled INTEGER NOT NULL DEFAULT 1,
                model_count INTEGER NOT NULL DEFAULT 0,
                tested_at TEXT NOT NULL DEFAULT '',
                test_status TEXT NOT NULL DEFAULT ''
            );
        """)

        # Migration: add model_count if missing
        try:
            c.execute("ALTER TABLE provider_keys ADD COLUMN model_count INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # already exists

        # Migration: recreate discovered_models with provider_id PK
        ver = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if not ver or int(ver["value"]) < 2:
            # Drop old table if it exists without provider_id PK
            try:
                c.execute("SELECT provider_id FROM discovered_models LIMIT 1")
            except sqlite3.OperationalError:
                # Old table, migrate
                c.executescript("""
                    ALTER TABLE discovered_models RENAME TO discovered_models_old;
                    CREATE TABLE discovered_models (
                        id TEXT NOT NULL,
                        provider_id INTEGER NOT NULL DEFAULT 0,
                        provider TEXT NOT NULL DEFAULT '',
                        owned_by TEXT NOT NULL DEFAULT '',
                        context_window INTEGER NOT NULL DEFAULT 0,
                        capabilities TEXT NOT NULL DEFAULT '[]',
                        discovered_at TEXT NOT NULL,
                        PRIMARY KEY (provider_id, id)
                    );
                    INSERT OR IGNORE INTO discovered_models (id, provider_id, provider, owned_by, context_window, capabilities, discovered_at)
                        SELECT id, 0, provider, owned_by, context_window, capabilities, discovered_at FROM discovered_models_old;
                    DROP TABLE discovered_models_old;
                """)
            c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', '2')")


# ── Runs ────────────────────────────────────────────────────────────────

def create_run(client: str = "Neuraluna", config: dict | None = None) -> str:
    run_id = str(uuid.uuid4())[:8]
    with _conn() as c:
        c.execute(
            "INSERT INTO runs (id, client, config_json, created_at) VALUES (?, ?, ?, ?)",
            (run_id, client, json.dumps(config or {}), time.strftime("%Y-%m-%dT%H:%M:%S")),
        )
    return run_id


def update_run(run_id: str, **kwargs):
    if not kwargs:
        return
    sets = ", ".join(f"{k} = ?" for k in kwargs)
    vals = list(kwargs.values()) + [run_id]
    with _conn() as c:
        c.execute(f"UPDATE runs SET {sets} WHERE id = ?", vals)


def get_run(run_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    return dict(row) if row else None


def list_runs(limit: int = 20) -> list[dict]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# ── Results ──────────────────────────────────────────────────────────────

def save_result(run_id: str, result: dict):
    with _conn() as c:
        c.execute(
            """INSERT INTO run_results
               (run_id, attack_id, rsk_id, model_id, provider, verdict,
                judge_verdict, judge_reason,
                prompt, response, matched_indicators, error_message,
                elapsed_ms, tokens_prompt, tokens_completion)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                result.get("attack_id", ""),
                result.get("rsk_id", ""),
                result.get("model_id", ""),
                result.get("provider", ""),
                result.get("verdict", "error"),
                result.get("judge_verdict", ""),
                result.get("judge_reason", ""),
                result.get("prompt", ""),
                result.get("response", ""),
                json.dumps(result.get("matched_indicators", [])),
                result.get("error_message", ""),
                result.get("elapsed_ms", 0),
                result.get("tokens_prompt", 0),
                result.get("tokens_completion", 0),
            ),
        )


def get_run_results(run_id: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM run_results WHERE run_id = ? ORDER BY attack_id, model_id",
            (run_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_run_results_as_result_objects(run_id: str) -> list:
    """Return results as AttackResult objects for report generation."""
    from attacks.base import AttackResult, Verdict

    results = []
    for r in get_run_results(run_id):
        try:
            verdict = Verdict(r["verdict"])
        except ValueError:
            verdict = Verdict.ERROR
        results.append(AttackResult(
            attack_id=r["attack_id"],
            rsk_id=r["rsk_id"],
            model_id=r["model_id"],
            provider=r["provider"],
            verdict=verdict,
            judge_verdict=r.get("judge_verdict", ""),
            judge_reason=r.get("judge_reason", ""),
            prompt=r["prompt"],
            response=r["response"],
            elapsed_ms=r["elapsed_ms"],
            tokens_prompt=r["tokens_prompt"],
            tokens_completion=r["tokens_completion"],
            matched_indicators=json.loads(r["matched_indicators"]),
            error_message=r["error_message"],
        ))
    return results


# ── Models cache ─────────────────────────────────────────────────────────

def save_models(models: list[dict], provider_id: int = 0):
    """Save discovered models. When provider_id > 0, only replaces that provider's cache."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with _conn() as c:
        if provider_id > 0:
            c.execute("DELETE FROM discovered_models WHERE provider_id = ?", (provider_id,))
        else:
            c.execute("DELETE FROM discovered_models")
        for m in models:
            c.execute(
                "INSERT OR REPLACE INTO discovered_models (id, provider_id, provider, owned_by, context_window, capabilities, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (m["id"], provider_id, m.get("provider", ""), m.get("owned_by", ""),
                 m.get("context_window", 0), json.dumps(m.get("capabilities", [])), now),
            )


def get_cached_models(provider_id: int = 0) -> list[dict]:
    """Get cached models. provider_id=0 returns all models."""
    with _conn() as c:
        if provider_id > 0:
            rows = c.execute("SELECT * FROM discovered_models WHERE provider_id = ? ORDER BY id", (provider_id,)).fetchall()
        else:
            rows = c.execute("SELECT * FROM discovered_models ORDER BY provider_id, id").fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d.get("capabilities", "[]"))
        result.append(d)
    return result


def get_models_grouped_by_provider() -> list[dict]:
    """Return models grouped by provider_id for the wizard display."""
    with _conn() as c:
        rows = c.execute("""SELECT dm.*, pk.name as provider_name
            FROM discovered_models dm
            LEFT JOIN provider_keys pk ON dm.provider_id = pk.id
            ORDER BY dm.provider_id, dm.id""").fetchall()
    groups: dict[int, dict] = {}
    for r in rows:
        d = dict(r)
        d["capabilities"] = json.loads(d.get("capabilities", "[]"))
        pid = d["provider_id"]
        if pid not in groups:
            groups[pid] = {
                "provider_id": pid,
                "provider_name": d.get("provider_name") or d.get("provider", "unknown"),
                "models": [],
            }
        groups[pid]["models"].append(d)
    return list(groups.values())


def get_model_count() -> int:
    with _conn() as c:
        row = c.execute("SELECT COUNT(*) as cnt FROM discovered_models").fetchone()
    return row["cnt"] if row else 0


def clear_model_cache(provider_id: int = 0):
    with _conn() as c:
        if provider_id > 0:
            c.execute("DELETE FROM discovered_models WHERE provider_id = ?", (provider_id,))
        else:
            c.execute("DELETE FROM discovered_models")


def get_cache_timestamp() -> str:
    with _conn() as c:
        row = c.execute("SELECT MAX(discovered_at) as ts FROM discovered_models").fetchone()
    return row["ts"] if row and row["ts"] else ""


# ── Settings ─────────────────────────────────────────────────────────────

def get_setting(key: str, default: str = "") -> str:
    with _conn() as c:
        row = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str):
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))


# ── Provider Keys ────────────────────────────────────────────────────────

def get_provider_keys() -> list[dict]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM provider_keys ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def get_provider_key(provider_id: int) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM provider_keys WHERE id = ?", (provider_id,)).fetchone()
    return dict(row) if row else None


def save_provider_key(data: dict) -> int:
    with _conn() as c:
        if data.get("id"):
            c.execute(
                "UPDATE provider_keys SET name=?, base_url=?, api_key=?, provider_type=?, enabled=? WHERE id=?",
                (data["name"], data["base_url"], data.get("api_key", ""),
                 data.get("provider_type", "openai-compatible"), data.get("enabled", 1), data["id"]),
            )
            return data["id"]
        else:
            cur = c.execute(
                "INSERT INTO provider_keys (name, base_url, api_key, provider_type, enabled) VALUES (?, ?, ?, ?, ?)",
                (data["name"], data["base_url"], data.get("api_key", ""),
                 data.get("provider_type", "openai-compatible"), data.get("enabled", 1)),
            )
            return cur.lastrowid


def delete_provider_key(provider_id: int):
    with _conn() as c:
        c.execute("DELETE FROM provider_keys WHERE id = ?", (provider_id,))
        c.execute("DELETE FROM discovered_models WHERE provider_id = ?", (provider_id,))


def update_provider_test(provider_id: int, status: str, model_count: int = 0):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with _conn() as c:
        c.execute(
            "UPDATE provider_keys SET tested_at = ?, test_status = ?, model_count = ? WHERE id = ?",
            (now, f"{status}:{model_count} models" if status == "ok" else status, model_count, provider_id),
        )


def get_provider_models_grouped() -> list:
    """Return models grouped by provider for the wizard."""
    providers = get_provider_keys()
    result = []
    for p in providers:
        models = get_cached_models(provider_id=p["id"])
        if models:
            result.append({
                "provider": p,
                "models": models,
            })
    return result


# ── Init on import ───────────────────────────────────────────────────────

init_db()
