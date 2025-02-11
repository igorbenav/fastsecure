from unittest.mock import patch
import pytest
from datetime import datetime, timezone

from fastsecure import (
    AuthStrategy,
    JWTAuthenticationProvider,
)
from fastsecure.exceptions import (
    ProviderNotFoundError,
)

pytestmark = pytest.mark.asyncio


# Path Pattern Matching Tests
async def test_path_pattern_matching_with_query_params(auth_manager):
    """Test path matching with query parameters"""
    auth_manager.add_requirement("/api/users/*", providers=["jwt"])

    # Should match despite query parameters
    requirement = auth_manager.get_requirement("/api/users/123?filter=active")
    assert requirement is not None
    assert "jwt" in requirement.required_providers


async def test_nested_path_pattern_matching(auth_manager):
    """Test matching nested path patterns"""
    auth_manager.add_requirement("/api/orgs/*/users/*", providers=["jwt"])

    requirement = auth_manager.get_requirement("/api/orgs/456/users/789")
    assert requirement is not None
    assert "jwt" in requirement.required_providers


# Scopes Tests
async def test_authentication_with_multiple_required_scopes(
    auth_manager, user_credentials
):
    """Test authentication with multiple required scopes"""
    auth_manager.add_requirement(
        path="/api/admin/users",
        providers=["jwt"],
        scopes=["admin:access", "users:write"],
    )

    # Add required scopes
    user_credentials["scopes"] = ["admin:access", "users:write", "extra:scope"]

    result = await auth_manager.authenticate(
        path="/api/admin/users", credentials={"jwt": user_credentials}
    )

    assert result.success


# Optional Providers Tests
async def test_authentication_with_only_optional_provider(
    auth_manager, user_credentials
):
    """Test authentication with only optional provider succeeding"""
    auth_manager.add_requirement(
        path="/api/public",
        providers=["jwt"],  # jwt is required
        optional_providers=["session"],  # session is optional
    )

    result = await auth_manager.authenticate(
        path="/api/public",
        credentials={
            "session": {
                **user_credentials,
                "ip_address": "127.0.0.1",
                "user_agent": "test",
            }
        },
    )

    assert not result.success
    errors = result.metadata.get("errors", [])
    assert any(
        "Missing credentials for required provider: jwt" in error for error in errors
    ), f"Actual errors: {errors}"


async def test_authentication_optional_provider_failure(auth_manager, user_credentials):
    """Test authentication succeeds when optional provider fails"""
    auth_manager.add_requirement(
        path="/api/flexible", providers=["jwt"], optional_providers=["session"]
    )

    # Authenticate with required jwt and invalid session
    result = await auth_manager.authenticate(
        path="/api/flexible",
        credentials={"jwt": user_credentials, "session": {"invalid": "credentials"}},
    )

    assert result.success  # Should succeed as jwt is valid


# Error Handling Tests
async def test_provider_not_found_error(auth_manager):
    """Test error when provider is not found"""
    with pytest.raises(ProviderNotFoundError):
        auth_manager.add_requirement(path="/api/test", providers=["nonexistent"])


async def test_authentication_with_expired_credentials(
    auth_manager, jwt_provider, user_credentials
):
    """Test authentication with expired credentials"""
    expired_provider = JWTAuthenticationProvider(
        secret_key=jwt_provider.secret_key,
        access_token_expire_minutes=0,
        refresh_token_expire_days=0,
    )

    auth_manager.register_provider("jwt", expired_provider)
    auth_manager.add_requirement("/api/test", providers=["jwt"])

    auth_result = await expired_provider.authenticate(user_credentials)
    result = await auth_manager.authenticate(
        path="/api/test",
        credentials={"jwt": {"access_token": auth_result.access_token}},
    )

    assert not result.success
    errors = result.metadata.get("errors", [])
    assert any("expired" in error.lower() for error in errors)


# Session Management Tests
async def test_session_concurrent_login_limit(
    auth_manager, user_credentials, mock_request_data
):
    """Test session concurrent login limit"""
    auth_manager.add_requirement("/api/login", providers=["session"])

    # Create maximum allowed sessions
    sessions = []
    for _ in range(3):  # Assuming max_sessions_per_user = 3
        result = await auth_manager.authenticate(
            path="/api/login",
            credentials={"session": {**user_credentials, **mock_request_data}},
        )
        assert result.success
        sessions.append(result.session_id)

    # Try to create one more session
    result = await auth_manager.authenticate(
        path="/api/login",
        credentials={"session": {**user_credentials, **mock_request_data}},
    )

    assert result.success
    # Verify first session was invalidated
    first_session_valid = await auth_manager.validate_authentication(
        path="/api/login", auth_data={"session": {"session_id": sessions[0]}}
    )
    assert not first_session_valid


# Metadata Tests
async def test_session_metadata_preservation(
    auth_manager, user_credentials, mock_request_data
):
    """Test session metadata is preserved"""
    auth_manager.add_requirement("/api/session", providers=["session"])

    custom_metadata = {
        "device_id": "test_device_123",
        "app_version": "1.0.0",
        "platform": "test_platform",
    }

    result = await auth_manager.authenticate(
        path="/api/session",
        credentials={
            "session": {
                **user_credentials,
                **mock_request_data,
                "metadata": custom_metadata,
            }
        },
    )

    assert result.success
    # Session provider includes metadata directly in the result metadata
    for key, value in custom_metadata.items():
        assert result.metadata.get(key) == value


# Multiple Provider Tests
async def test_multiple_providers_partial_success(
    auth_manager, user_credentials, mock_request_data
):
    """Test behavior when some providers succeed and others fail"""
    auth_manager.add_requirement(
        path="/api/multi", providers=["jwt", "session"], strategy=AuthStrategy.ANY
    )

    # JWT succeeds but session fails
    result = await auth_manager.authenticate(
        path="/api/multi",
        credentials={"jwt": user_credentials, "session": {"invalid": "credentials"}},
    )

    assert result.success
    assert result.provider == "jwt"


@patch("fastsecure.providers.session.now_utc")
async def test_provider_specific_metadata(mock_now, auth_manager, user_credentials):
    """Test provider-specific metadata handling"""
    mock_now.side_effect = lambda: datetime.now(timezone.utc)

    auth_manager.add_requirement(
        path="/api/test", providers=["jwt", "session"], strategy=AuthStrategy.ALL
    )

    custom_metadata = {"custom_claim": "test_value"}
    credentials_with_metadata = {**user_credentials, "metadata": custom_metadata}

    result = await auth_manager.authenticate(
        path="/api/test",
        credentials={
            "jwt": credentials_with_metadata,
            "session": {
                **credentials_with_metadata,
                "ip_address": "127.0.0.1",
                "user_agent": "test",
            },
        },
    )

    assert result.success
    assert result.metadata["jwt"].get("custom_claim") == "test_value"
