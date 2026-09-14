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
from .ingest.dedupe import AlertDeduper
from .models import incident_id_for
from .pipeline import investigate
from .render.text import render_brief

app = FastAPI(title="FazerOps", version="0.1.0")

# A re-delivered firing is answered with the first delivery's result (`ingest/dedupe.py`).
app.state.dedupe = AlertDeduper()


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

    dedupe: AlertDeduper = request.app.state.dedupe
    key = incident_id_for(alert)
    seen = dedupe.claim(key)
    if seen is not None:
        if seen.response is None:
            return JSONResponse({"incident_id": key, "deduplicated": True, "in_progress": True}, status_code=202)
        return JSONResponse({**seen.response, "deduplicated": True})

    try:
        brief = await investigate(alert)
    except BaseException:
        dedupe.abandon(key)
        raise

    body = {
        "incident_id": brief.incident_id,
        "service": brief.alert.service,
        "payload_shape": brief.alert.payload_shape,
        "candidate_count": len(brief.candidates),
        "ci_merge_count": brief.ci_status.merge_count,
        "degraded": brief.degraded,
        "brief": render_brief(brief),
    }
    dedupe.finish(key, body)
    return JSONResponse({**body, "deduplicated": False})


@app.post("/webhook/text", response_class=PlainTextResponse)
async def webhook_text(request: Request) -> PlainTextResponse:
    """Same investigation, rendered for a terminal."""
    payload: dict[str, Any] = await request.json()
    try:
        alert = normalize_alert(payload)
    except UnrecognisedPayload as exc:
        return PlainTextResponse(str(exc), status_code=400)

    # Its own key space: `/webhook` caches a JSON body, and one endpoint must never answer with the
    # other's shape.
    dedupe: AlertDeduper = request.app.state.dedupe
    incident_id = incident_id_for(alert)
    key = f"text:{incident_id}"
    seen = dedupe.claim(key)
    if seen is not None:
        if seen.response is None:
            return PlainTextResponse(f"{incident_id} is still being investigated.", status_code=202)
        return PlainTextResponse(seen.response["text"])

    try:
        text = render_brief(await investigate(alert))
    except BaseException:
        dedupe.abandon(key)
        raise
    dedupe.finish(key, {"text": text})
    return PlainTextResponse(text)
