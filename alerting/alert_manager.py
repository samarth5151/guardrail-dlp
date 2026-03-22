"""
DLP Gateway — Alert Manager
Triggers alerts for high-risk events and repeat violators.
Broadcasts to admin WebSocket connections in real time.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Deque, Set, List

logger = logging.getLogger("dlp.alerting")

REPEAT_VIOLATION_WINDOW   = 600   # seconds = 10 minutes
REPEAT_VIOLATION_THRESHOLD = 3    # violations before repeat-violator alert
HIGH_RISK_THRESHOLD        = 80.0 # risk_score threshold


class AlertManager:
    def __init__(self):
        # user_id → deque of violation timestamps within the window
        self._violation_times: Dict[str, Deque[datetime]] = defaultdict(deque)
        # WebSocket subscriber queues (admin dashboard connections)
        self._subscribers: Set[asyncio.Queue] = set()

    # ── WebSocket fan-out subscription ────────────────────────────────────────

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def _broadcast(self, payload: dict) -> None:
        dead = set()
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.add(q)
        self._subscribers -= dead

    # ── Alert evaluation ──────────────────────────────────────────────────────

    async def evaluate(
        self,
        event_id: str,
        user_id:  str,
        decision: str,
        risk_score: float,
        detected_types: List[str],
    ) -> List[dict]:
        alerts = []
        now = datetime.utcnow()

        # 1. High-risk event alert
        if risk_score >= HIGH_RISK_THRESHOLD:
            alert = {
                "alert_id":   str(uuid.uuid4()),
                "event_id":   event_id,
                "user_id":    user_id,
                "alert_type": "HIGH_RISK",
                "risk_score": risk_score,
                "message":    (
                    f"High-risk DLP event from {user_id} "
                    f"(score={risk_score:.1f}). "
                    f"Detected: {', '.join(detected_types[:3])}."
                ),
                "timestamp":  now.isoformat(),
            }
            alerts.append(alert)
            self._broadcast({"type": "alert", "data": alert})
            logger.warning("[ALERT] HIGH_RISK  user=%s  score=%.1f", user_id, risk_score)

        # 2. Repeat violator alert
        if decision in ("BLOCK", "WARN"):
            window = self._violation_times[user_id]
            window.append(now)
            cutoff = now - timedelta(seconds=REPEAT_VIOLATION_WINDOW)
            # Prune old entries outside window
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= REPEAT_VIOLATION_THRESHOLD:
                alert = {
                    "alert_id":   str(uuid.uuid4()),
                    "event_id":   event_id,
                    "user_id":    user_id,
                    "alert_type": "REPEAT_VIOLATOR",
                    "risk_score": risk_score,
                    "message":    (
                        f"User {user_id} has triggered {len(window)} "
                        f"violations in the past 10 minutes."
                    ),
                    "timestamp":  now.isoformat(),
                }
                alerts.append(alert)
                self._broadcast({"type": "alert", "data": alert})
                logger.warning("[ALERT] REPEAT_VIOLATOR  user=%s  count=%d", user_id, len(window))

        # Always broadcast the event to the live feed
        self._broadcast({
            "type":    "event",
            "data": {
                "event_id":      event_id,
                "user_id":       user_id,
                "decision":      decision,
                "risk_score":    risk_score,
                "detected_types": detected_types,
                "timestamp":     now.isoformat(),
            }
        })

        return alerts


alert_manager = AlertManager()
