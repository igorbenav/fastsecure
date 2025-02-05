from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, List, Optional


class SessionStore(ABC):
    """Base class for session storage"""

    @abstractmethod
    async def create_session(
        self,
        user_id: int,
        session_id: str,
        expires_at: datetime,
        metadata: Dict[str, Any],
    ) -> bool:
        """Create a new session"""
        pass

    @abstractmethod
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        pass

    @abstractmethod
    async def update_session(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """Update session metadata and last activity"""
        pass

    @abstractmethod
    async def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        pass

    @abstractmethod
    async def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all sessions for a user"""
        pass
