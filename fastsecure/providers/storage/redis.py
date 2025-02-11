from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import json
import redis.asyncio as redis

from .base import SessionStore


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
        return f"{self.prefix}{session_id}"

    def _user_key(self, user_id: int) -> str:
        return f"{self.user_prefix}{user_id}"

    def _serialize_datetime(self, dt: datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    def _deserialize_datetime(self, dt_str: str) -> datetime:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _serialize_session(self, session_data: Dict[str, Any]) -> str:
        serialized = {
            "user_id": session_data["user_id"],
            "session_id": session_data["session_id"],
            "expires_at": self._serialize_datetime(session_data["expires_at"]),
            "created_at": self._serialize_datetime(
                session_data.get("created_at", datetime.now(timezone.utc))
            ),
            "last_activity": self._serialize_datetime(
                session_data.get("last_activity", datetime.now(timezone.utc))
            ),
            "metadata": session_data.get("metadata", {}),
        }
        return json.dumps(serialized)

    def _deserialize_session(self, session_str: str) -> Dict[str, Any]:
        data = json.loads(session_str)
        return {
            "user_id": data["user_id"],
            "session_id": data["session_id"],
            "expires_at": self._deserialize_datetime(data["expires_at"]),
            "created_at": self._deserialize_datetime(data["created_at"]),
            "last_activity": self._deserialize_datetime(data["last_activity"]),
            "metadata": data.get("metadata", {}),
        }

    async def create_session(
        self,
        user_id: int,
        session_id: str,
        expires_at: datetime,
        metadata: Dict[str, Any],
    ) -> bool:
        now = datetime.now(timezone.utc)
        session_data = {
            "user_id": user_id,
            "session_id": session_id,
            "expires_at": expires_at,
            "created_at": now,
            "last_activity": now,
            "metadata": metadata,
        }

        try:
            session_key = self._session_key(session_id)
            serialized = self._serialize_session(session_data)

            expires_in_ms = int((expires_at - now).total_seconds() * 1000)
            if expires_in_ms <= 0:
                return False

            await self.redis.set(session_key, serialized, px=expires_in_ms)

            user_key = self._user_key(user_id)
            await self.redis.sadd(user_key, session_id)

            return True
        except Exception:
            return False

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        try:
            session_key = self._session_key(session_id)
            data = await self.redis.get(session_key)

            if not data:
                return None

            if isinstance(data, bytes):
                data = data.decode("utf-8")

            return self._deserialize_session(data)
        except Exception:
            return None

    async def update_session(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        try:
            session_data = await self.get_session(session_id)
            if not session_data:
                return False

            session_data["metadata"] = metadata
            session_data["last_activity"] = datetime.now(timezone.utc)

            expires_at = session_data["expires_at"]
            now = datetime.now(timezone.utc)
            expires_in_ms = int((expires_at - now).total_seconds() * 1000)

            if expires_in_ms <= 0:
                return False

            session_key = self._session_key(session_id)
            await self.redis.set(
                session_key, self._serialize_session(session_data), px=expires_in_ms
            )

            return True
        except Exception:
            return False

    async def delete_session(self, session_id: str) -> bool:
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
        try:
            user_key = self._user_key(user_id)
            session_ids = await self.redis.smembers(user_key)

            sessions = []
            for session_id in session_ids:
                session_id = (
                    session_id.decode() if isinstance(session_id, bytes) else session_id
                )
                session_data = await self.get_session(session_id)
                if session_data:
                    sessions.append(session_data)
                else:
                    await self.redis.srem(user_key, session_id)

            return sessions
        except Exception:
            return []
