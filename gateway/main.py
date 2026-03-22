"""
DLP Gateway — FastAPI Application
Central API for scanning prompts, auditing events, and serving admin data.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from db.session import get_session, engine
from db.models import Base, DLPEvent, UserRiskProfile, Alert
from detection.engine import dlp_engine
from policy.engine import policy_engine
from cache.redis_client import get_cached, set_cached
from alerting.alert_manager import alert_manager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dlp.gateway")

app = FastAPI(title="LLM DLP Gateway", version="1.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount admin UI static files
UI_DIR = os.path.join(os.path.dirname(__file__), "ui")
if os.path.isdir(UI_DIR):
    app.mount("/ui", StaticFiles(directory=UI_DIR, html=True), name="ui")


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("DLP Gateway started — tables created")


# ── Request / Response schemas ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    user_id:           str = Field(..., example="emp-00123")
    department:        str = Field("default", example="finance")
    role:              str = Field("employee", example="analyst")
    prompt:            str = Field(..., min_length=1)
    destination_model: str = Field("unknown", example="chatgpt")

class AnalyzeResponse(BaseModel):
    event_id:          str
    decision:          str           # PASS | BLOCK | WARN
    risk_score:        float
    risk_tier:         str
    block_reason:      str
    detected_types:    List[str]
    findings:          List[dict]
    layer_scores:      dict
    processing_ms:     float
    policy_notes:      dict
    from_cache:        bool
    timestamp:         str


# ── Helper: get last chain hash ───────────────────────────────────────────────

async def _get_prev_hash(session: AsyncSession) -> str:
    row = await session.scalar(
        select(DLPEvent.chain_hash)
        .order_by(DLPEvent.id.desc())
        .limit(1)
    )
    return row or "GENESIS"


# ── Helper: upsert user profile ───────────────────────────────────────────────

async def _update_user_profile(
    session: AsyncSession,
    user_id: str, department: str, role: str,
    decision: str, risk_score: float,
) -> None:
    profile = await session.scalar(
        select(UserRiskProfile).where(UserRiskProfile.user_id == user_id)
    )
    if not profile:
        profile = UserRiskProfile(
            user_id=user_id, department=department, role=role,
            total_prompts=0, total_blocked=0, total_warned=0, avg_risk_score=0.0
        )
        session.add(profile)

    profile.total_prompts += 1
    profile.last_seen      = datetime.utcnow()
    if decision == "BLOCK":
        profile.total_blocked += 1
    elif decision == "WARN":
        profile.total_warned  += 1

    # Rolling average
    n = profile.total_prompts
    profile.avg_risk_score = (profile.avg_risk_score * (n - 1) + risk_score) / n


# ── Main DLP endpoint ─────────────────────────────────────────────────────────

@app.post("/gateway/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest, session: AsyncSession = Depends(get_session)):
    event_id  = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()

    # 1. Redis cache lookup (only for PASS candidates)
    cached = await get_cached(req.prompt)
    if cached:
        cached["event_id"]   = event_id
        cached["from_cache"] = True
        cached["timestamp"]  = timestamp
        return AnalyzeResponse(**cached)

    # 2. Run detection engine
    scan = await dlp_engine.scan(req.prompt, department=req.department)

    # 3. Run policy engine
    policy = policy_engine.evaluate(
        department=req.department,
        role=req.role,
        detected_types=scan.detected_types,
        risk_score=scan.risk_score,
    )

    # Policy can upgrade scanner PASS → BLOCK
    final_decision = (
        "BLOCK" if policy["decision"] == "BLOCK" or scan.decision == "BLOCK"
        else "WARN"  if policy["decision"] == "WARN"  or scan.decision == "WARN"
        else "PASS"
    )

    # 4. Persist to DB with hash chain
    prev_hash  = await _get_prev_hash(session)
    chain_hash = DLPEvent.compute_chain_hash(prev_hash, event_id, timestamp, final_decision)

    db_event = DLPEvent(
        event_id          = event_id,
        user_id           = req.user_id,
        department        = req.department,
        role              = req.role,
        destination_model = req.destination_model,
        prompt_hash       = hashlib.sha256(req.prompt.encode()).hexdigest(),
        prompt_snippet    = req.prompt[:200],
        decision          = final_decision,
        risk_score        = scan.risk_score,
        risk_tier         = scan.risk_tier,
        detected_types    = scan.detected_types,
        block_reason      = scan.block_reason,
        layer_scores      = scan.layer_scores,
        findings_count    = len(scan.findings),
        processing_ms     = scan.processing_ms,
        from_cache        = False,
        chain_hash        = chain_hash,
    )
    session.add(db_event)
    await _update_user_profile(session, req.user_id, req.department, req.role,
                               final_decision, scan.risk_score)
    await session.commit()

    # 5. Alerting
    await alert_manager.evaluate(
        event_id=event_id,
        user_id=req.user_id,
        decision=final_decision,
        risk_score=scan.risk_score,
        detected_types=scan.detected_types,
    )

    # 6. Cache if PASS
    result_dict = dict(
        event_id=event_id,
        decision=final_decision,
        risk_score=scan.risk_score,
        risk_tier=scan.risk_tier,
        block_reason=scan.block_reason,
        detected_types=scan.detected_types,
        findings=scan.findings,
        layer_scores=scan.layer_scores,
        processing_ms=scan.processing_ms,
        policy_notes=policy,
        from_cache=False,
        timestamp=timestamp,
    )
    await set_cached(req.prompt, result_dict)

    return AnalyzeResponse(**result_dict)


# ── Admin endpoints ───────────────────────────────────────────────────────────

@app.get("/admin/events")
async def list_events(
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    decision: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
):
    q = select(DLPEvent).order_by(DLPEvent.id.desc()).offset(offset).limit(limit)
    if decision:
        q = q.where(DLPEvent.decision == decision.upper())
    rows = (await session.scalars(q)).all()
    return [
        {
            "event_id":       r.event_id,
            "user_id":        r.user_id,
            "department":     r.department,
            "destination":    r.destination_model,
            "decision":       r.decision,
            "risk_score":     r.risk_score,
            "risk_tier":      r.risk_tier,
            "detected_types": r.detected_types,
            "block_reason":   r.block_reason,
            "processing_ms":  r.processing_ms,
            "from_cache":     r.from_cache,
            "chain_hash":     r.chain_hash,
            "timestamp":      r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in rows
    ]


@app.get("/admin/alerts")
async def list_alerts(
    limit: int = Query(50, le=200),
    dismissed: bool = False,
    session: AsyncSession = Depends(get_session),
):
    q = (
        select(Alert)
        .where(Alert.dismissed == dismissed)
        .order_by(Alert.id.desc())
        .limit(limit)
    )
    rows = (await session.scalars(q)).all()
    return [
        {
            "alert_id":   r.alert_id,
            "event_id":   r.event_id,
            "user_id":    r.user_id,
            "alert_type": r.alert_type,
            "risk_score": r.risk_score,
            "message":    r.message,
            "dismissed":  r.dismissed,
            "timestamp":  r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in rows
    ]


@app.post("/admin/alerts/{alert_id}/dismiss")
async def dismiss_alert(alert_id: str, session: AsyncSession = Depends(get_session)):
    alert = await session.scalar(select(Alert).where(Alert.alert_id == alert_id))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.dismissed = True
    await session.commit()
    return {"status": "dismissed"}


@app.get("/admin/users")
async def list_users(
    limit: int = Query(50, le=200),
    session: AsyncSession = Depends(get_session),
):
    rows = (await session.scalars(
        select(UserRiskProfile)
        .order_by(UserRiskProfile.total_blocked.desc())
        .limit(limit)
    )).all()
    return [
        {
            "user_id":       r.user_id,
            "department":    r.department,
            "role":          r.role,
            "total_prompts": r.total_prompts,
            "total_blocked": r.total_blocked,
            "total_warned":  r.total_warned,
            "avg_risk_score": round(r.avg_risk_score, 1),
            "last_seen":     r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows
    ]


@app.get("/admin/users/{user_id}")
async def get_user(user_id: str, session: AsyncSession = Depends(get_session)):
    profile = await session.scalar(
        select(UserRiskProfile).where(UserRiskProfile.user_id == user_id)
    )
    if not profile:
        raise HTTPException(status_code=404, detail="User not found")

    recent_events = (await session.scalars(
        select(DLPEvent)
        .where(DLPEvent.user_id == user_id)
        .order_by(DLPEvent.id.desc())
        .limit(20)
    )).all()

    return {
        "profile": {
            "user_id":        profile.user_id,
            "department":     profile.department,
            "role":           profile.role,
            "total_prompts":  profile.total_prompts,
            "total_blocked":  profile.total_blocked,
            "total_warned":   profile.total_warned,
            "avg_risk_score": round(profile.avg_risk_score, 1),
            "last_seen":      profile.last_seen.isoformat() if profile.last_seen else None,
        },
        "recent_events": [
            {
                "event_id":   e.event_id,
                "decision":   e.decision,
                "risk_score": e.risk_score,
                "detected_types": e.detected_types,
                "timestamp":  e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in recent_events
        ],
    }


@app.get("/admin/stats")
async def stats(session: AsyncSession = Depends(get_session)):
    total    = await session.scalar(select(func.count(DLPEvent.id)))
    blocked  = await session.scalar(select(func.count(DLPEvent.id)).where(DLPEvent.decision == "BLOCK"))
    warned   = await session.scalar(select(func.count(DLPEvent.id)).where(DLPEvent.decision == "WARN"))
    passed   = await session.scalar(select(func.count(DLPEvent.id)).where(DLPEvent.decision == "PASS"))
    alerts_n = await session.scalar(select(func.count(Alert.id)).where(Alert.dismissed == False))
    return {
        "total_prompts":   total or 0,
        "total_blocked":   blocked or 0,
        "total_warned":    warned or 0,
        "total_passed":    passed or 0,
        "active_alerts":   alerts_n or 0,
        "block_rate_pct":  round((blocked or 0) / max(total or 1, 1) * 100, 1),
    }


# ── WebSocket: real-time admin live feed ──────────────────────────────────────

@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    q = alert_manager.subscribe()
    try:
        while True:
            payload = await q.get()
            await ws.send_json(payload)
    except (WebSocketDisconnect, Exception):
        alert_manager.unsubscribe(q)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "DLP Gateway"}
