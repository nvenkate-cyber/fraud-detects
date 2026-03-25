import json
import os
from typing import Any, Dict, Optional

import httpx
import stripe
from fastapi import FastAPI, Header, HTTPException, Request


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name, default)
    if value is not None:
        value = value.strip()
    return value


STRIPE_WEBHOOK_SECRET = _env("STRIPE_WEBHOOK_SECRET")
OPENCLAW_GATEWAY_URL = _env("OPENCLAW_GATEWAY_URL", "http://127.0.0.1:18789")
OPENCLAW_GATEWAY_TOKEN = _env("OPENCLAW_GATEWAY_TOKEN")
OPENCLAW_SESSION_KEY = _env("OPENCLAW_SESSION_KEY", "fraud-monitor")
SLACK_CHANNEL = _env("SLACK_CHANNEL", "#fraud-alerts")
STRIPE_EVENT_ALLOWLIST = set(
    e.strip()
    for e in (_env(
        "STRIPE_EVENT_ALLOWLIST",
        "radar.early_fraud_warning.created,charge.dispute.created,review.closed",
    ) or "").split(",")
    if e.strip()
)

app = FastAPI(title="OpenClaw Stripe Fraud Webhook")


def _extract_risk_fields(obj: Dict[str, Any]) -> Dict[str, Any]:
    outcome = obj.get("outcome") or {}
    return {
        "risk_level": obj.get("risk_level") or outcome.get("risk_level"),
        "risk_score": obj.get("risk_score") or outcome.get("risk_score"),
        "seller_message": outcome.get("seller_message"),
        "network_status": outcome.get("network_status"),
        "reason": outcome.get("reason"),
    }


def _summarize_event(event: Dict[str, Any]) -> str:
    data_obj = (event.get("data") or {}).get("object") or {}
    risk = _extract_risk_fields(data_obj)
    summary = {
        "event_id": event.get("id"),
        "type": event.get("type"),
        "created": event.get("created"),
        "livemode": event.get("livemode"),
        "object": data_obj.get("object"),
        "charge": data_obj.get("charge") or data_obj.get("id"),
        "payment_intent": data_obj.get("payment_intent"),
        "customer": data_obj.get("customer"),
        "amount": data_obj.get("amount"),
        "currency": data_obj.get("currency"),
        "risk": {k: v for k, v in risk.items() if v is not None},
    }
    return json.dumps(summary, ensure_ascii=True)


async def _openclaw_request(path: str, payload: Dict[str, Any]) -> None:
    if not OPENCLAW_GATEWAY_TOKEN:
        return
    url = f"{OPENCLAW_GATEWAY_URL.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {OPENCLAW_GATEWAY_TOKEN}"}
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()


async def _store_memory(text: str) -> None:
    payload = {
        "tool": "memory_store",
        "args": {"text": text, "category": "fact"},
    }
    await _openclaw_request("/tools/invoke", payload)


async def _notify_slack(text: str) -> None:
    prompt = (
        "You are a fraud monitoring agent. "
        f"Post the following alert to Slack channel {SLACK_CHANNEL} using Civic Nexus tools. "
        "Do not ask clarifying questions.\n\n"
        f"{text}"
    )
    payload = {
        "model": "openclaw",
        "input": prompt,
        "user": OPENCLAW_SESSION_KEY,
    }
    await _openclaw_request("/v1/responses", payload)


@app.post("/webhook/stripe")
async def stripe_webhook(
    request: Request, stripe_signature: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET missing")
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=stripe_signature,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if STRIPE_EVENT_ALLOWLIST and event["type"] not in STRIPE_EVENT_ALLOWLIST:
        return {"status": "ignored", "event": event["type"]}

    summary = _summarize_event(event)

    if OPENCLAW_GATEWAY_TOKEN:
        await _store_memory(summary)
        await _notify_slack(summary)

    return {"status": "processed", "event": event["type"]}


@app.post("/webhook/test")
async def test_webhook(payload: Dict[str, Any]) -> Dict[str, Any]:
    event_type = payload.get("type", "test.fraud_signal")
    event = {
        "id": payload.get("id", "evt_test"),
        "type": event_type,
        "created": payload.get("created", 0),
        "livemode": False,
        "data": {"object": payload.get("data", {})},
    }
    summary = _summarize_event(event)

    if OPENCLAW_GATEWAY_TOKEN:
        await _store_memory(summary)
        await _notify_slack(summary)

    return {"status": "processed", "event": event_type}
