"""
DLP Gateway — Async SQLAlchemy session factory
"""
from __future__ import annotations

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

DATABASE_URL = os.getenv(
    "POSTGRES_URL",
    "postgresql+asyncpg://dlp:dlp@localhost:5432/dlp"
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
