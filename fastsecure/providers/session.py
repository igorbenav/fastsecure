from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Set, Optional
from uuid import uuid4

from .base import AuthenticationProvider
from .storage import SessionStore, MemorySessionStore
from ..core.types import AuthenticationResult


def now_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    """Ensure a datetime is UTC aware"""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class SessionAuthenticationProvider(AuthenticationProvider):
    """Session-based authentication provider"""

    def __init__(
        self,
        session_store: Optional[SessionStore] = None,
        session_timeout_minutes: int = 30,
        max_sessions_per_user: int = 5,
        cleanup_expired: bool = True,
    ):
        self.store = session_store or MemorySessionStore()
        self.session_timeout = timedelta(minutes=max(0, session_timeout_minutes))
        self.max_sessions = max_sessions_per_user
        self.cleanup_expired = cleanup_expired

    def get_required_credentials(self) -> Set[str]:
        """Get required credentials for session authentication"""
        return {"user_id"}

    async def _cleanup_user_sessions(self, user_id: int) -> None:
        """Remove expired sessions and enforce max sessions limit"""
        sessions = await self.store.get_user_sessions(user_id)
        current_time = now_utc()

        if self.cleanup_expired:
            for session in sessions:
                expires_at = ensure_utc(session["expires_at"])
                if expires_at <= current_time:
                    await self.store.delete_session(session["session_id"])

        active_sessions = await self.store.get_user_sessions(user_id)

        if len(active_sessions) >= self.max_sessions:
            sorted_sessions = sorted(
                active_sessions,
                key=lambda x: ensure_utc(x.get("created_at", now_utc())),
            )
            to_remove = sorted_sessions[: -(self.max_sessions - 1)]

            for session in to_remove:
                await self.store.delete_session(session["session_id"])

    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """Create a new session"""
        if not self.validate_credentials(credentials):
            return AuthenticationResult(
                success=False,
                provider=self.provider_name,
                metadata={"error": "Missing required credentials"},
            )

        user_id = credentials["user_id"]

        await self._cleanup_user_sessions(user_id)

        session_id = str(uuid4())
        current_time = now_utc()
        expires_at = current_time + self.session_timeout

        metadata = {
            "created_ip": credentials.get("ip_address"),
            "user_agent": credentials.get("user_agent"),
            "created_at": current_time.isoformat(),
            "last_activity": current_time.isoformat(),
            "scopes": list(credentials.get("scopes", [])),
            "ip_address": credentials.get("ip_address"),
            **(credentials.get("metadata", {})),
        }

        success = await self.store.create_session(
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
            metadata=metadata,
        )

        if not success:
            return AuthenticationResult(
                success=False,
                provider=self.provider_name,
                metadata={"error": "Failed to create session"},
            )

        return AuthenticationResult(
            success=True,
            user_id=user_id,
            session_id=session_id,
            expires_at=expires_at,
            provider=self.provider_name,
            metadata=metadata,
        )

    async def validate_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """Validate if session exists and is not expired"""
        session_id = auth_data.get("session_id")
        if not session_id:
            return False

        session = await self.store.get_session(session_id)
        if not session:
            return False

        current_time = now_utc()
        expires_at = ensure_utc(session["expires_at"])

        if expires_at <= current_time:
            if self.cleanup_expired:
                await self.store.delete_session(session_id)
            return False

        metadata = session["metadata"].copy()
        metadata["last_activity"] = current_time.isoformat()
        success = await self.store.update_session(
            session_id=session_id, metadata=metadata, session_data=session
        )

        return success

    async def revoke_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """End the session"""
        session_id = auth_data.get("session_id")
        if not session_id:
            return False

        return await self.store.delete_session(session_id)

    @property
    def supports_revocation(self) -> bool:
        return True
