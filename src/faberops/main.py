"""FastAPI app and webhook entrypoint — Handoff §2's `main.py`.

Idea.md §6 rules out PagerDuty as a hard dependency: ingest is a generic webhook accepting
Alertmanager, CloudWatch or PagerDuty payload shapes. Shape detection and normalization
live in `ingest/alerts.py`; this module is transport only.

Tier 0 runs here: read-only, no approval, complete before a human opens their laptop.
**Nothing reachable from this module can mutate anything** — the automation layer is
entered only through an approval callback in `slack/handlers.py` (plan §3.5).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .ingest.alerts import UnrecognisedPayload, normalize_alert
from .pipeline import investigate
from .render.text import render_brief

app = FastAPI(title="FaberOps", version="0.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook")
async def webhook(request: Request) -> JSONResponse:
    payload: dict[str, Any] = await request.json()

    try:
        alert = normalize_alert(payload)
    except UnrecognisedPayload as exc:
        # A 400 beats guessing. An unrecognised shape parsed permissively yields the wrong
        # service, and the brief then investigates the wrong blast radius confidently.
        return JSONResponse({"error": str(exc)}, status_code=400)

    brief = await investigate(alert)

    return JSONResponse(
        {
            "incident_id": brief.incident_id,
            "service": brief.alert.service,
            "payload_shape": brief.alert.payload_shape,
            "candidate_count": len(brief.candidates),
            "ci_merge_count": brief.ci_status.merge_count,
            "degraded": brief.degraded,
            "brief": render_brief(brief),
        }
    )


@app.post("/webhook/text", response_class=PlainTextResponse)
async def webhook_text(request: Request) -> PlainTextResponse:
    """Same investigation, rendered for a terminal."""
    payload: dict[str, Any] = await request.json()
    try:
        alert = normalize_alert(payload)
    except UnrecognisedPayload as exc:
        return PlainTextResponse(str(exc), status_code=400)

    return PlainTextResponse(render_brief(await investigate(alert)))
