import pytest

from fastsecure import (
    AuthenticationManager,
    JWTAuthenticationProvider,
    SessionAuthenticationProvider,
    MemorySessionStore,
)


@pytest.fixture
def jwt_secret():
    return "test-secret-key-for-testing-purposes-only"


@pytest.fixture
def jwt_provider(jwt_secret):
    return JWTAuthenticationProvider(
        secret_key=jwt_secret,
        access_token_expire_minutes=15,
        refresh_token_expire_days=7,
    )


@pytest.fixture
def memory_store():
    return MemorySessionStore()


@pytest.fixture
def session_provider(memory_store):
    return SessionAuthenticationProvider(
        session_store=memory_store, session_timeout_minutes=30, max_sessions_per_user=3
    )


@pytest.fixture
def auth_manager(jwt_provider, session_provider):
    manager = AuthenticationManager()
    manager.register_provider("jwt", jwt_provider)
    manager.register_provider("session", session_provider)
    return manager


@pytest.fixture
def user_credentials():
    return {
        "user_id": 123,
        "username": "testuser",
        "email": "test@example.com",
        "scopes": ["read:profile", "write:profile"],
    }


@pytest.fixture
def valid_jwt_auth_data():
    return {
        "access_token": "dummy-token",  # Will be replaced with real token in tests
        "refresh_token": "dummy-refresh-token",  # Will be replaced with real token in tests
    }


@pytest.fixture
def valid_session_auth_data():
    return {
        "session_id": "dummy-session-id",  # Will be replaced with real session in tests
        "user_id": 123,
    }


@pytest.fixture
def mock_request_data():
    return {
        "ip_address": "127.0.0.1",
        "user_agent": "Mozilla/5.0 (Test Browser) Test/1.0",
        "metadata": {"device": "test_device", "platform": "test_platform"},
    }
