from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, select, and_
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import update


class Base(DeclarativeBase):
    pass


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


class DatabaseSessionStore:
    """Session storage using SQL database through SQLAlchemy"""

    def __init__(self, async_session_factory):
        """Initialize database session store"""
        self.async_session_factory = async_session_factory

    def _ensure_timezone(self, dt: datetime) -> datetime:
        """Ensure datetime has UTC timezone"""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    async def create_session(
        self,
        user_id: int,
        session_id: str,
        expires_at: datetime,
        metadata: Dict[str, Any],
    ) -> bool:
        """Create a new session in the database"""
        try:
            now = self._ensure_timezone(datetime.now())
            expires_at = self._ensure_timezone(expires_at)

            session = DBSession(
                session_id=session_id,
                user_id=user_id,
                expires_at=expires_at,
                created_at=now,
                last_activity=now,
                session_metadata=metadata,
                is_active=True,
            )

            async with self.async_session_factory() as db:
                db.add(session)
                await db.commit()
                await db.refresh(session)
                return True
        except Exception:
            if "db" in locals():
                await db.rollback()
            return False

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data from database"""
        try:
            now = self._ensure_timezone(datetime.now())

            async with self.async_session_factory() as db:
                result = await db.execute(
                    select(DBSession).where(
                        and_(
                            DBSession.session_id == session_id,
                            DBSession.is_active.is_(True),
                            DBSession.expires_at > now,
                        )
                    )
                )
                session = result.scalar_one_or_none()

                if not session:
                    return None

                return {
                    "user_id": session.user_id,
                    "session_id": session.session_id,
                    "expires_at": session.expires_at,
                    "created_at": session.created_at,
                    "last_activity": session.last_activity,
                    "metadata": session.session_metadata,
                }
        except Exception:
            return None

    async def update_session(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """Update session metadata and last activity"""
        try:
            now = self._ensure_timezone(datetime.now())
            async with self.async_session_factory() as db:
                result = await db.execute(
                    select(DBSession).where(
                        and_(
                            DBSession.session_id == session_id,
                            DBSession.is_active.is_(True),
                            DBSession.expires_at > now,
                        )
                    )
                )
                session = result.scalar_one_or_none()

                if not session:
                    return False

                stmt = (
                    update(DBSession)
                    .where(DBSession.session_id == session_id)
                    .values(session_metadata=metadata, last_activity=now)
                )
                await db.execute(stmt)
                await db.commit()
                return True
        except Exception:
            if "db" in locals():
                await db.rollback()
            return False

    async def delete_session(self, session_id: str) -> bool:
        """Soft delete a session by marking it inactive"""
        try:
            async with self.async_session_factory() as db:
                stmt = (
                    update(DBSession)
                    .where(
                        and_(
                            DBSession.session_id == session_id,
                            DBSession.is_active.is_(True),
                        )
                    )
                    .values(is_active=False)
                )
                result = await db.execute(stmt)
                await db.commit()
                is_not_empty: bool = result.rowcount > 0
                return is_not_empty
        except Exception:
            if "db" in locals():
                await db.rollback()
            return False

    async def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all active and non-expired sessions for a user"""
        try:
            now = self._ensure_timezone(datetime.now())
            async with self.async_session_factory() as db:
                result = await db.execute(
                    select(DBSession).where(
                        and_(
                            DBSession.user_id == user_id,
                            DBSession.is_active.is_(True),
                            DBSession.expires_at > now,
                        )
                    )
                )
                sessions = result.scalars().all()

                return [
                    {
                        "user_id": session.user_id,
                        "session_id": session.session_id,
                        "expires_at": session.expires_at,
                        "created_at": session.created_at,
                        "last_activity": session.last_activity,
                        "metadata": session.session_metadata,
                    }
                    for session in sessions
                ]
        except Exception:
            return []

    async def cleanup_expired_sessions(self) -> None:
        """Clean up expired sessions by marking them inactive"""
        try:
            now = self._ensure_timezone(datetime.now())

            async with self.async_session_factory() as db:
                stmt = (
                    update(DBSession)
                    .where(
                        and_(DBSession.expires_at <= now, DBSession.is_active.is_(True))
                    )
                    .values(is_active=False)
                )
                await db.execute(stmt)
                await db.commit()

        except Exception:
            if "db" in locals():
                await db.rollback()

    async def create_tables(self) -> None:
        """Create database tables"""
        async with self.async_session_factory() as db:
            try:
                engine = db.get_bind()
                async with engine.begin() as conn:
                    await conn.run_sync(Base.metadata.create_all)
            except Exception:
                if "db" in locals():
                    await db.rollback()
                raise
