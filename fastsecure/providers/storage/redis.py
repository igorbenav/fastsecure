import json
from datetime import datetime
from typing import Dict, Any, List, Optional

import redis.asyncio as redis

from ..storage.base import SessionStore


class RedisSessionStore(SessionStore):
    """Session storage using Redis"""

    def __init__(
        self,
        redis_url: str,
        prefix: str = "fastsecure:session:",
        user_prefix: str = "fastsecure:user:",
    ):
        self.redis = redis.from_url(redis_url)
        self.prefix = prefix
        self.user_prefix = user_prefix

    def _session_key(self, session_id: str) -> str:
        """Get Redis key for session"""
        return f"{self.prefix}{session_id}"

    def _user_key(self, user_id: int) -> str:
        """Get Redis key for user's sessions"""
        return f"{self.user_prefix}{user_id}"

    def _serialize_datetime(self, dt: datetime) -> str:
        """Serialize datetime to string"""
        return dt.isoformat()

    def _deserialize_datetime(self, dt_str: str) -> datetime:
        """Deserialize datetime from string"""
        return datetime.fromisoformat(dt_str)

    async def create_session(
        self,
        user_id: int,
        session_id: str,
        expires_at: datetime,
        metadata: Dict[str, Any],
    ) -> bool:
        """Create a new session in Redis"""
        session_data = {
            "user_id": user_id,
            "session_id": session_id,
            "expires_at": self._serialize_datetime(expires_at),
            "created_at": self._serialize_datetime(datetime.now()),
            "last_activity": self._serialize_datetime(datetime.now()),
            "metadata": metadata,
        }

        try:
            session_key = self._session_key(session_id)
            await self.redis.set(
                session_key,
                json.dumps(session_data),
                px=int((expires_at - datetime.now()).total_seconds() * 1000),
            )

            user_key = self._user_key(user_id)
            await self.redis.sadd(user_key, session_id)

            return True
        except Exception:
            return False

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data from Redis"""
        session_key = self._session_key(session_id)
        data = await self.redis.get(session_key)

        if not data:
            return None

        session_data = json.loads(data)
        session_data["expires_at"] = self._deserialize_datetime(
            session_data["expires_at"]
        )
        session_data["created_at"] = self._deserialize_datetime(
            session_data["created_at"]
        )
        session_data["last_activity"] = self._deserialize_datetime(
            session_data["last_activity"]
        )

        return session_data

    async def update_session(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """Update session metadata and last activity"""
        try:
            session_data = await self.get_session(session_id)
            if not session_data:
                return False

            session_data["metadata"].update(metadata)
            session_data["last_activity"] = self._serialize_datetime(datetime.now())

            expires_at = session_data["expires_at"]
            ttl = int((expires_at - datetime.now()).total_seconds() * 1000)
            if ttl <= 0:
                return False

            session_key = self._session_key(session_id)
            await self.redis.set(session_key, json.dumps(session_data), px=ttl)

            return True
        except Exception:
            return False

    async def delete_session(self, session_id: str) -> bool:
        """Delete session from Redis"""
        try:
            session_data = await self.get_session(session_id)
            if not session_data:
                return False

            user_key = self._user_key(session_data["user_id"])
            await self.redis.srem(user_key, session_id)

            session_key = self._session_key(session_id)
            await self.redis.delete(session_key)

            return True
        except Exception:
            return False

    async def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all sessions for a user"""
        user_key = self._user_key(user_id)
        session_ids = await self.redis.smembers(user_key)

        sessions = []
        for session_id in session_ids:
            session_data = await self.get_session(session_id.decode())
            if session_data:
                sessions.append(session_data)
            else:
                await self.redis.srem(user_key, session_id)

        return sessions
