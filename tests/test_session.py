import asyncio
import pytest
from datetime import datetime, timedelta, timezone

from fastsecure import SessionAuthenticationProvider, MemorySessionStore

pytestmark = pytest.mark.asyncio


def now_utc():
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


async def test_session_authentication_success(
    session_provider, user_credentials, mock_request_data
):
    """Test successful session authentication"""
    credentials = {**user_credentials, **mock_request_data}
    result = await session_provider.authenticate(credentials)

    assert result.success
    assert result.provider == "session"
    assert result.session_id is not None
    assert result.user_id == user_credentials["user_id"]
    assert result.expires_at is not None

    # Check stored session
    session = await session_provider.store.get_session(result.session_id)
    assert session is not None
    assert session["user_id"] == user_credentials["user_id"]
    assert session["metadata"]["ip_address"] == mock_request_data["ip_address"]


async def test_session_missing_user_id(session_provider):
    """Test session authentication with missing user_id"""
    result = await session_provider.authenticate({})
    assert not result.success
    assert "Missing required credentials" in str(result.metadata.get("error", ""))


async def test_session_validation_success(session_provider, user_credentials):
    """Test successful session validation"""
    auth_result = await session_provider.authenticate(user_credentials)
    assert auth_result.success

    is_valid = await session_provider.validate_authentication(
        {"session_id": auth_result.session_id}
    )
    assert is_valid


async def test_session_validation_invalid_session(session_provider):
    """Test session validation with invalid session ID"""
    is_valid = await session_provider.validate_authentication(
        {"session_id": "invalid-session-id"}
    )
    assert not is_valid


async def test_session_expiration(user_credentials):
    """Test session expiration"""
    # Create provider with very short timeout
    store = MemorySessionStore()
    provider = SessionAuthenticationProvider(
        session_store=store,
        session_timeout_minutes=0,  # Expire immediately
    )

    result = await provider.authenticate(user_credentials)
    assert result.success

    # Ensure some time passes
    await asyncio.sleep(0.1)

    # Session should be invalid due to expiration
    is_valid = await provider.validate_authentication({"session_id": result.session_id})
    assert not is_valid


async def test_session_max_sessions(session_provider, user_credentials):
    """Test max sessions per user limit"""
    # Create max_sessions + 1 sessions
    sessions = []
    for _ in range(session_provider.max_sessions + 1):
        result = await session_provider.authenticate(user_credentials)
        assert result.success
        sessions.append(result.session_id)

    # First session should be invalidated
    is_valid = await session_provider.validate_authentication(
        {"session_id": sessions[0]}
    )
    assert not is_valid

    # Latest session should be valid
    is_valid = await session_provider.validate_authentication(
        {"session_id": sessions[-1]}
    )
    assert is_valid


async def test_session_revocation(session_provider, user_credentials):
    """Test session revocation"""
    result = await session_provider.authenticate(user_credentials)
    assert result.success

    # Revoke session
    success = await session_provider.revoke_authentication(
        {"session_id": result.session_id}
    )
    assert success

    # Session should be invalid
    is_valid = await session_provider.validate_authentication(
        {"session_id": result.session_id}
    )
    assert not is_valid


async def test_session_cleanup(session_provider, user_credentials):
    """Test expired session cleanup"""
    # Create a session
    result = await session_provider.authenticate(user_credentials)
    assert result.success

    # Manually expire the session
    session = await session_provider.store.get_session(result.session_id)
    session["expires_at"] = now_utc() - timedelta(minutes=1)
    # We need to update the session in the store with the modified expiration
    await session_provider.store.update_session(
        session_id=result.session_id,
        metadata=session["metadata"],
        session_data=session,  # Pass the full session data
    )

    # Try to validate - should trigger cleanup
    is_valid = await session_provider.validate_authentication(
        {"session_id": result.session_id}
    )
    assert not is_valid

    # Session should be cleaned up
    session = await session_provider.store.get_session(result.session_id)
    assert session is None
