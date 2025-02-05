from datetime import datetime
from typing import Dict, Any, List, Optional

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Boolean,
    JSON,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy import update

from ..storage.base import SessionStore

Base = declarative_base()


class DBSession(Base):
    """Database model for session storage"""

    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), unique=True, nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    last_activity = Column(DateTime(timezone=True), nullable=False)
    session_metadata = Column(JSON, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)


class DatabaseSessionStore(SessionStore):
    """Session storage using SQL database through SQLAlchemy"""

    def __init__(self, async_session_factory):
        """
        Initialize database session store

        Args:
            async_session_factory: Async session factory from SQLAlchemy
        """
        self.async_session_factory = async_session_factory

    async def _get_session(self) -> AsyncSession:
        """Get database session"""
        return self.async_session_factory()

    async def create_session(
        self,
        user_id: int,
        session_id: str,
        expires_at: datetime,
        metadata: Dict[str, Any],
    ) -> bool:
        """Create a new session in the database"""
        now = datetime.now()
        session = DBSession(
            session_id=session_id,
            user_id=user_id,
            expires_at=expires_at,
            created_at=now,
            last_activity=now,
            session_metadata=metadata,
            is_active=True,
        )

        try:
            async with await self._get_session() as db:
                db.add(session)
                await db.commit()
            return True
        except Exception:
            return False

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data from database"""
        async with await self._get_session() as db:
            query = select(DBSession).where(
                DBSession.session_id == session_id, DBSession.is_active is True
            )
            result = await db.execute(query)
            session = result.scalar_one_or_none()

            if not session:
                return None

            return {
                "user_id": session.user_id,
                "session_id": session.session_id,
                "expires_at": session.expires_at,
                "created_at": session.created_at,
                "last_activity": session.last_activity,
                "metadata": session.metadata,
            }

    async def update_session(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """Update session metadata and last activity"""
        try:
            async with await self._get_session() as db:
                stmt = (
                    update(DBSession)
                    .where(DBSession.session_id == session_id)
                    .values(metadata=metadata, last_activity=datetime.now())
                )
                await db.execute(stmt)
                await db.commit()
            return True
        except Exception:
            return False

    async def delete_session(self, session_id: str) -> bool:
        """Soft delete a session by marking it inactive"""
        try:
            async with await self._get_session() as db:
                stmt = (
                    update(DBSession)
                    .where(DBSession.session_id == session_id)
                    .values(is_active=False)
                )
                await db.execute(stmt)
                await db.commit()
            return True
        except Exception:
            return False

    async def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all active sessions for a user"""
        async with await self._get_session() as db:
            query = select(DBSession).where(
                DBSession.user_id == user_id, DBSession.is_active is True
            )
            result = await db.execute(query)
            sessions = result.scalars().all()

            return [
                {
                    "user_id": session.user_id,
                    "session_id": session.session_id,
                    "expires_at": session.expires_at,
                    "created_at": session.created_at,
                    "last_activity": session.last_activity,
                    "metadata": session.metadata,
                }
                for session in sessions
            ]

    async def cleanup_expired_sessions(self) -> None:
        """Remove expired sessions"""
        now = datetime.now()
        async with await self._get_session() as db:
            stmt = (
                update(DBSession)
                .where(DBSession.expires_at <= now, DBSession.is_active is True)
                .values(is_active=False)
            )
            await db.execute(stmt)
            await db.commit()

    async def create_tables(self) -> None:
        """Create database tables"""
        async with await self._get_session() as db:
            engine = db.get_bind()
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
