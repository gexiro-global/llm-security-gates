#!/usr/bin/env python3
"""LLM Guard runtime firewall -- an OpenAI-compatible reverse proxy.

Sits in front of any OpenAI-compatible chat backend (e.g. a local gateway on
``:4000``). It scans the user prompt before forwarding upstream and the model
reply before returning it, blocking either side on policy.

Environment:
    BACKEND_URL       upstream base (default http://127.0.0.1:4000/v1)
    BACKEND_API_KEY   bearer for upstream (optional)
    INPUT_SCANNERS    csv (default prompt_injection,secrets,invisible_text,ban_code)
    OUTPUT_SCANNERS   csv (default sensitive,malicious_urls)
    GUARD_BLOCK_MODE  refuse | reject  (default refuse -> 200 OpenAI-style refusal)

Run:  uvicorn llm_security_gates.llmguard_proxy:app --host 127.0.0.1 --port 18091

Scanner construction (which pulls in the heavy ``llm-guard`` dependency) happens
in ``load_scanners`` at startup, so importing this module for testing does not
require the ML stack; tests inject fakes via ``set_scanners``.
"""
import os
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .llmguard_scan import (
    build_input_scanners, build_output_scanners, parse_scanner_names,
    scan_input, scan_output_text,
)

BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:4000/v1").rstrip("/")
BACKEND_API_KEY = os.environ.get("BACKEND_API_KEY", "")
INPUT_SCANNERS = parse_scanner_names(os.environ.get(
    "INPUT_SCANNERS", "prompt_injection,secrets,invisible_text,ban_code"))
OUTPUT_SCANNERS = parse_scanner_names(os.environ.get(
    "OUTPUT_SCANNERS", "sensitive,malicious_urls"))
BLOCK_MODE = os.environ.get("GUARD_BLOCK_MODE", "refuse")
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "120"))

_STATE = {"in": None, "out": None}


def set_scanners(input_scanners, output_scanners):
    """Inject scanner instances directly (used by tests to avoid the ML load)."""
    _STATE["in"] = input_scanners
    _STATE["out"] = output_scanners


def load_scanners():
    """Build the configured scanner sets (pulls in llm-guard). Idempotent."""
    if _STATE["in"] is not None and _STATE["out"] is not None:
        return
    in_scanners, vault = build_input_scanners(INPUT_SCANNERS)
    _STATE["in"] = in_scanners
    _STATE["out"] = build_output_scanners(OUTPUT_SCANNERS, vault)


@asynccontextmanager
async def lifespan(_app):
    load_scanners()
    yield


app = FastAPI(title="llm-security-gates: llm-guard proxy", lifespan=lifespan)


def _refusal(reason, detail):
    body = {
        "id": "guard-block", "object": "chat.completion",
        "choices": [{"index": 0, "finish_reason": "content_filter",
                     "message": {"role": "assistant",
                                 "content": "[llm-security-gates] request blocked: " + reason}}],
        "guard": detail,
    }
    status = 200 if BLOCK_MODE == "refuse" else 403
    return JSONResponse(body, status_code=status)


def _last_user(messages):
    """Return the content of the last user message, or '' (pure)."""
    for m in reversed(messages or []):
        if m.get("role") == "user":
            return m.get("content", "") or ""
    return ""


@app.post("/v1/chat/completions")
async def chat(request: Request):
    payload = await request.json()
    prompt = _last_user(payload.get("messages"))

    gin = scan_input(prompt, _STATE["in"])
    if gin["blocked"]:
        return _refusal("input policy", gin)

    headers = {"Content-Type": "application/json"}
    if BACKEND_API_KEY:
        headers["Authorization"] = "Bearer " + BACKEND_API_KEY
    t0 = time.perf_counter()
    async with httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT) as client:
        r = await client.post(BACKEND_URL + "/chat/completions", json=payload, headers=headers)
    upstream_ms = round((time.perf_counter() - t0) * 1000, 1)
    if r.status_code != 200:
        return JSONResponse({"error": "upstream", "status": r.status_code, "body": r.text[:500]},
                            status_code=502)
    data = r.json()
    reply = (data.get("choices", [{}])[0].get("message", {}) or {}).get("content", "") or ""

    gout = scan_output_text(prompt, reply, _STATE["out"])
    if gout["blocked"]:
        return _refusal("output policy", gout)

    data["guard"] = {"input": gin, "output": gout, "upstream_ms": upstream_ms}
    return JSONResponse(data)


@app.get("/healthz")
def health():
    return {"ok": True, "input_scanners": INPUT_SCANNERS, "output_scanners": OUTPUT_SCANNERS,
            "backend": BACKEND_URL, "block_mode": BLOCK_MODE,
            "loaded": _STATE["in"] is not None}
