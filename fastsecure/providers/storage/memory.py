from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class MemorySessionStore:
    """In-memory session storage for development/testing"""

    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.user_sessions: Dict[int, List[str]] = {}

    async def create_session(
        self,
        user_id: int,
        session_id: str,
        expires_at: datetime,
        metadata: Dict[str, Any],
    ) -> bool:
        """Create a new session"""
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        session_data = {
            "user_id": user_id,
            "session_id": session_id,
            "expires_at": expires_at,
            "created_at": datetime.now(timezone.utc),
            "last_activity": datetime.now(timezone.utc),
            "metadata": metadata,
            "is_active": True,
        }

        self.sessions[session_id] = session_data
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = []
        self.user_sessions[user_id].append(session_id)

        return True

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        session = self.sessions.get(session_id)
        if not session or not session.get("is_active", False):
            return None

        expires_at = session["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) > expires_at:
            session["is_active"] = False
            return None

        return session.copy()

    async def update_session(
        self,
        session_id: str,
        metadata: Dict[str, Any],
        session_data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update session metadata and optionally other session data"""
        session = self.sessions.get(session_id)
        if not session or not session.get("is_active", False):
            return False

        if session_data:
            session.update(session_data)
            session["metadata"].update(metadata)
        else:
            session["metadata"].update(metadata)

        session["last_activity"] = datetime.now(timezone.utc)
        return True

    async def delete_session(self, session_id: str) -> bool:
        """Soft delete session"""
        if session_id in self.sessions:
            self.sessions[session_id]["is_active"] = False
            return True
        return False

    async def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all active sessions for a user"""
        session_ids = self.user_sessions.get(user_id, [])
        current_time = datetime.now(timezone.utc)

        active_sessions = []
        for session_id in session_ids:
            session = self.sessions.get(session_id)
            if not session or not session.get("is_active", False):
                continue

            expires_at = session["expires_at"]
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if current_time <= expires_at:
                active_sessions.append(session.copy())

        return active_sessions
