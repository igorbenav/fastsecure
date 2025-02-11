from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Set, Optional
from uuid import uuid4

from .base import AuthenticationProvider
from .storage import SessionStore, MemorySessionStore
from ..core.types import AuthenticationResult


def now_utc() -> datetime:
    """
    Get the current UTC datetime.

    Returns:
        datetime: Current time in UTC timezone
    """
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    """
    Ensure a datetime object is UTC-aware.

    Args:
        dt: The datetime object to check

    Returns:
        datetime: The same datetime with UTC timezone if not already set
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class SessionAuthenticationProvider(AuthenticationProvider):
    """
    Authentication provider implementing session-based authentication.

    This provider manages user sessions with features like session timeout,
    maximum concurrent sessions per user, and automatic cleanup of expired
    sessions. It supports different session storage backends including
    memory, Redis, and database storage.

    Attributes:
        store: The session storage backend
        session_timeout: How long sessions remain valid
        max_sessions: Maximum number of concurrent sessions per user
        cleanup_expired: Whether to automatically remove expired sessions
        supports_revocation: Always True as sessions can be revoked

    Example:
        Basic initialization with memory storage:
        ```python
        provider = SessionAuthenticationProvider(
            session_timeout_minutes=60,
            max_sessions_per_user=3
        )
        ```

        Using Redis storage:
        ```python
        provider = SessionAuthenticationProvider(
            session_store=RedisSessionStore("redis://localhost"),
            session_timeout_minutes=60
        )
        ```

        Using database storage:
        ```python
        provider = SessionAuthenticationProvider(
            session_store=DatabaseSessionStore(async_session_factory),
            cleanup_expired=True
        )
        ```
    """

    def __init__(
        self,
        session_store: Optional[SessionStore] = None,
        session_timeout_minutes: int = 30,
        max_sessions_per_user: int = 5,
        cleanup_expired: bool = True,
    ):
        """
        Initialize the session authentication provider.

        Args:
            session_store: Storage backend for sessions (default: MemorySessionStore)
            session_timeout_minutes: Session lifetime in minutes (default: 30)
            max_sessions_per_user: Max concurrent sessions per user (default: 5)
            cleanup_expired: Whether to remove expired sessions (default: True)
        """
        self.store = session_store or MemorySessionStore()
        self.session_timeout = timedelta(minutes=max(0, session_timeout_minutes))
        self.max_sessions = max_sessions_per_user
        self.cleanup_expired = cleanup_expired

    def get_required_credentials(self) -> Set[str]:
        """
        Get required credentials for session authentication.

        Returns:
            Set[str]: Set containing only "user_id" as required credential
        """
        return {"user_id"}

    async def _cleanup_user_sessions(self, user_id: int) -> None:
        """
        Clean up a user's sessions by removing expired ones and enforcing
        the maximum sessions limit.

        If the user has more active sessions than allowed, the oldest
        sessions are removed to stay within the limit.

        Args:
            user_id: The ID of the user whose sessions to clean up
        """
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
        """
        Create a new session for the user.

        Creates a session with a unique ID and stores user information
        including IP address, user agent, and custom metadata. Also performs
        session cleanup before creating new sessions.

        Args:
            credentials: Dictionary containing:
                - user_id: Required user identifier
                - ip_address: Optional client IP
                - user_agent: Optional client user agent
                - scopes: Optional permission scopes
                - metadata: Optional additional session metadata

        Returns:
            AuthenticationResult: Result containing:
                - session_id: Unique session identifier
                - expires_at: Session expiration time
                - metadata: Session metadata including creation info

        Example:
            ```python
            result = await provider.authenticate({
                "user_id": 123,
                "ip_address": "127.0.0.1",
                "user_agent": "Mozilla/5.0...",
                "scopes": ["read", "write"]
            })
            ```
        """
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
            "scopes": set(credentials.get("scopes", [])),
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
        """
        Validate if a session exists and is not expired.

        Checks if the session ID exists, hasn't expired, and updates
        the last activity timestamp if valid.

        Args:
            auth_data: Dictionary containing:
                - session_id: The session identifier to validate

        Returns:
            bool: True if session is valid and updated, False otherwise
        """
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

        metadata = session.get("metadata", {}).copy()
        metadata["last_activity"] = current_time.isoformat()

        success = await self.store.update_session(
            session_id=session_id, metadata=metadata
        )

        return success

    async def revoke_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """
        End a session by deleting it from storage.

        Args:
            auth_data: Dictionary containing:
                - session_id: The session identifier to revoke

        Returns:
            bool: True if session was successfully deleted, False otherwise
        """
        session_id = auth_data.get("session_id")
        if not session_id:
            return False

        return await self.store.delete_session(session_id)

    @property
    def supports_revocation(self) -> bool:
        """
        Whether this provider supports session revocation.

        Returns:
            bool: Always True as sessions can be explicitly ended
        """
        return True
