from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, List, Optional, TypeVar, Generic

T = TypeVar("T")


class SessionStore(ABC, Generic[T]):
    """Base class for session storage with flexible user identification"""

    def __init__(self, identifier_field: str = "id"):
        self.identifier_field = identifier_field

    @abstractmethod
    async def create_session(
        self,
        user_id: T,
        session_id: str,
        expires_at: datetime,
        metadata: Dict[str, Any],
    ) -> bool:
        pass

    @abstractmethod
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def update_session(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    async def delete_session(self, session_id: str) -> bool:
        pass

    @abstractmethod
    async def get_user_sessions(self, user_identifier: T) -> List[Dict[str, Any]]:
        pass
