import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from fastsecure.providers.storage import (
    RedisSessionStore,
    DatabaseSessionStore,
    DBSession,
)
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.asyncio


def serialize_datetime(dt):
    """Helper to serialize datetime objects"""
    if isinstance(dt, datetime):
        return dt.isoformat()
    return dt


def deserialize_datetime(dt_str):
    """Helper to deserialize datetime strings"""
    if isinstance(dt_str, str):
        return datetime.fromisoformat(dt_str)
    return dt_str


# Redis Tests
@pytest.fixture
def mock_redis():
    mock = AsyncMock()

    # Store for simulating Redis data
    stored_data = {}
    user_sessions = {}

    async def mock_set(key, value, px=None):
        try:
            key_str = key.decode() if isinstance(key, bytes) else str(key)
            if isinstance(value, bytes):
                value = value.decode()
            stored_data[key_str] = value
            return True
        except Exception:
            return False

    async def mock_get(key):
        key_str = key.decode() if isinstance(key, bytes) else str(key)
        value = stored_data.get(key_str)
        if value is None:
            return None
        if isinstance(value, str):
            return value.encode()
        return value

    async def mock_sadd(key, value):
        key_str = key.decode() if isinstance(key, bytes) else str(key)
        if key_str not in user_sessions:
            user_sessions[key_str] = set()
        value_str = value.decode() if isinstance(value, bytes) else str(value)
        user_sessions[key_str].add(value_str)
        return True

    async def mock_smembers(key):
        key_str = key.decode() if isinstance(key, bytes) else str(key)
        return {s.encode() for s in user_sessions.get(key_str, set())}

    async def mock_delete(*keys):
        for key in keys:
            key_str = key.decode() if isinstance(key, bytes) else str(key)
            if key_str in stored_data:
                del stored_data[key_str]
        return True

    async def mock_srem(key, value):
        key_str = key.decode() if isinstance(key, bytes) else str(key)
        if key_str in user_sessions:
            value_str = value.decode() if isinstance(value, bytes) else str(value)
            user_sessions[key_str].discard(value_str)
        return True

    mock.set = AsyncMock(side_effect=mock_set)
    mock.get = AsyncMock(side_effect=mock_get)
    mock.delete = AsyncMock(side_effect=mock_delete)
    mock.sadd = AsyncMock(side_effect=mock_sadd)
    mock.srem = AsyncMock(side_effect=mock_srem)
    mock.smembers = AsyncMock(side_effect=mock_smembers)

    return mock


@pytest.fixture
def redis_store(mock_redis):
    store = RedisSessionStore("redis://localhost")
    store.redis = mock_redis
    return store


@pytest_asyncio.fixture
async def db_engine():
    """Create async SQLite engine"""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(DBSession.metadata.create_all)

    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def db_store(db_engine):
    """Create database store with async session"""
    async_session = sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    # Return the session factory directly
    store = DatabaseSessionStore(async_session)
    return store


@pytest.fixture
def session_data():
    """Common session data for tests"""
    now = datetime.now(timezone.utc)
    return {
        "user_id": 123,
        "session_id": "test-session",
        "expires_at": now + timedelta(minutes=30),
        "metadata": {"ip": "127.0.0.1"},
    }


# Redis Tests
async def test_redis_create_session(redis_store, session_data):
    """Test Redis session creation"""
    success = await redis_store.create_session(
        user_id=session_data["user_id"],
        session_id=session_data["session_id"],
        expires_at=session_data["expires_at"],
        metadata=session_data["metadata"],
    )

    assert success is True
    # Verify session was stored
    session = await redis_store.get_session(session_data["session_id"])
    assert session is not None
    assert session["user_id"] == session_data["user_id"]
    assert session["metadata"] == session_data["metadata"]


async def test_redis_get_session(redis_store, session_data):
    """Test Redis session retrieval"""
    # First create a session
    await redis_store.create_session(
        user_id=session_data["user_id"],
        session_id=session_data["session_id"],
        expires_at=session_data["expires_at"],
        metadata=session_data["metadata"],
    )

    # Then retrieve it
    session = await redis_store.get_session(session_data["session_id"])
    assert session is not None
    assert session["user_id"] == session_data["user_id"]
    assert session["metadata"] == session_data["metadata"]
    assert isinstance(session["expires_at"], datetime)


async def test_redis_delete_session(redis_store, session_data):
    """Test Redis session deletion"""
    # First create a session
    await redis_store.create_session(
        user_id=session_data["user_id"],
        session_id=session_data["session_id"],
        expires_at=session_data["expires_at"],
        metadata=session_data["metadata"],
    )

    # Then delete it
    success = await redis_store.delete_session(session_data["session_id"])
    assert success is True

    # Verify it's gone
    session = await redis_store.get_session(session_data["session_id"])
    assert session is None


async def test_redis_update_session(redis_store, session_data):
    """Test Redis session update"""
    # Create initial session
    await redis_store.create_session(
        user_id=session_data["user_id"],
        session_id=session_data["session_id"],
        expires_at=session_data["expires_at"],
        metadata=session_data["metadata"],
    )

    # Update metadata
    new_metadata = {"ip": "127.0.0.2", "user_agent": "updated"}
    success = await redis_store.update_session(
        session_id=session_data["session_id"], metadata=new_metadata
    )
    assert success is True

    # Verify update
    session = await redis_store.get_session(session_data["session_id"])
    assert session is not None
    assert session["metadata"] == new_metadata


# Database Tests
async def test_db_create_session(db_store, session_data):
    """Test database session creation"""
    success = await db_store.create_session(
        user_id=session_data["user_id"],
        session_id=session_data["session_id"],
        expires_at=session_data["expires_at"],
        metadata=session_data["metadata"],
    )
    assert success is True

    # Verify session was created
    session = await db_store.get_session(session_data["session_id"])
    assert session is not None
    assert session["user_id"] == session_data["user_id"]
    assert session["metadata"] == session_data["metadata"]


async def test_db_update_session(db_store, session_data):
    """Test database session update"""
    # Create initial session
    await db_store.create_session(
        user_id=session_data["user_id"],
        session_id=session_data["session_id"],
        expires_at=session_data["expires_at"],
        metadata=session_data["metadata"],
    )

    # Update metadata
    new_metadata = {"ip": "127.0.0.2", "user_agent": "updated"}
    success = await db_store.update_session(
        session_id=session_data["session_id"], metadata=new_metadata
    )
    assert success is True

    # Verify update
    session = await db_store.get_session(session_data["session_id"])
    assert session is not None
    assert session["metadata"] == new_metadata


async def test_db_get_user_sessions(db_store, session_data):
    """Test retrieving all user sessions from database"""
    # Create multiple sessions
    for i in range(3):
        await db_store.create_session(
            user_id=session_data["user_id"],
            session_id=f"test-session-{i}",
            expires_at=session_data["expires_at"],
            metadata={"session_number": i},
        )

    sessions = await db_store.get_user_sessions(session_data["user_id"])
    assert len(sessions) == 3
    assert all(s["user_id"] == session_data["user_id"] for s in sessions)


async def test_db_cleanup_expired_sessions(db_store, session_data):
    """Test cleanup of expired database sessions"""

    # Helper to ensure datetime has timezone
    def ensure_timezone(dt):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    now = ensure_timezone(datetime.now())

    # Create expired session (1 minute in the past)
    expired_session_time = now - timedelta(minutes=1)
    await db_store.create_session(
        user_id=session_data["user_id"],
        session_id="expired-session",
        expires_at=expired_session_time,
        metadata={},
    )

    # Create active session (30 minutes in the future)
    active_session_time = now + timedelta(minutes=30)
    await db_store.create_session(
        user_id=session_data["user_id"],
        session_id="active-session",
        expires_at=active_session_time,
        metadata={},
    )

    # Run cleanup
    await db_store.cleanup_expired_sessions()

    # Check results after cleanup
    expired = await db_store.get_session("expired-session")
    active = await db_store.get_session("active-session")

    # The expired session should be marked as inactive and thus not returned
    assert expired is None
    assert active is not None

    # Additional check to verify active session's expiry time
    if active:
        assert ensure_timezone(active["expires_at"]) == active_session_time
