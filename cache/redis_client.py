"""
DLP Gateway — Redis cache for safe prompt results.
Cache key = SHA-256(prompt). TTL = 10 minutes.
Only PASS decisions are cached (never BLOCK/WARN).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Optional

logger = logging.getLogger("dlp.cache")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
CACHE_TTL  = 600   # seconds

try:
    import redis.asyncio as aioredis
    _redis: Optional[aioredis.Redis] = None

    async def get_redis() -> aioredis.Redis:
        global _redis
        if _redis is None:
            _redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
        return _redis

    async def get_cached(prompt: str) -> Optional[dict]:
        key = "dlp:" + hashlib.sha256(prompt.encode()).hexdigest()
        try:
            r = await get_redis()
            val = await r.get(key)
            if val:
                return json.loads(val)
        except Exception as e:
            logger.warning("Redis GET error: %s", e)
        return None

    async def set_cached(prompt: str, result: dict) -> None:
        if result.get("decision") != "PASS":
            return   # Only cache safe prompts
        key = "dlp:" + hashlib.sha256(prompt.encode()).hexdigest()
        try:
            r = await get_redis()
            await r.setex(key, CACHE_TTL, json.dumps(result))
        except Exception as e:
            logger.warning("Redis SET error: %s", e)

    REDIS_AVAILABLE = True

except ImportError:
    logger.warning("redis package not installed — caching disabled")
    REDIS_AVAILABLE = False

    async def get_cached(prompt: str) -> Optional[dict]:
        return None

    async def set_cached(prompt: str, result: dict) -> None:
        pass
