import pytest

from fastsecure import (
    AuthStrategy,
    AuthenticationRequirement,
)
from fastsecure.core.strategies import AnyAuthStrategy, AllAuthStrategy

pytestmark = pytest.mark.asyncio


@pytest.fixture
def auth_requirement():
    return AuthenticationRequirement(
        providers=["jwt", "session"],
        strategy=AuthStrategy.ANY,
        optional_providers=["google"],
        scopes=["read:profile"],
    )


@pytest.fixture
def any_strategy():
    return AnyAuthStrategy()


@pytest.fixture
def all_strategy():
    return AllAuthStrategy()


async def test_any_strategy_single_success(
    auth_manager, auth_requirement, user_credentials
):
    """Test ANY strategy with single successful provider"""
    strategy = AnyAuthStrategy()

    result = await strategy.authenticate(
        auth_manager, auth_requirement, {"jwt": user_credentials}
    )

    assert result.success
    assert result.provider == "jwt"


async def test_any_strategy_multiple_success(
    auth_manager, auth_requirement, user_credentials
):
    """Test ANY strategy with multiple successful providers"""
    strategy = AnyAuthStrategy()

    credentials = {
        "jwt": user_credentials,
        "session": {**user_credentials, "ip_address": "127.0.0.1"},
    }

    result = await strategy.authenticate(auth_manager, auth_requirement, credentials)

    assert result.success
    assert result.provider == "jwt"  # First successful provider is used


async def test_any_strategy_all_fail(auth_manager, auth_requirement):
    """Test ANY strategy when all providers fail"""
    strategy = AnyAuthStrategy()

    result = await strategy.authenticate(
        auth_manager, auth_requirement, {"jwt": {}, "session": {}}
    )

    assert not result.success
    assert len(result.metadata["errors"]) > 0


async def test_any_strategy_with_scopes(auth_manager, user_credentials):
    """Test ANY strategy with scope requirements"""
    requirement = AuthenticationRequirement(providers=["jwt"], scopes=["admin:access"])
    strategy = AnyAuthStrategy()

    # Without required scope
    result = await strategy.authenticate(
        auth_manager, requirement, {"jwt": user_credentials}
    )
    assert not result.success

    # With required scope
    credentials = {**user_credentials, "scopes": ["admin:access"]}
    result = await strategy.authenticate(
        auth_manager, requirement, {"jwt": credentials}
    )
    assert result.success


async def test_all_strategy_complete_success(
    auth_manager, auth_requirement, user_credentials, mock_request_data
):
    """Test ALL strategy with all providers succeeding"""
    strategy = AllAuthStrategy()

    credentials = {
        "jwt": user_credentials,
        "session": {**user_credentials, **mock_request_data},
    }

    result = await strategy.authenticate(auth_manager, auth_requirement, credentials)

    assert result.success
    assert result.provider == "all"
    assert "jwt" in result.metadata
    assert "session" in result.metadata


async def test_all_strategy_partial_success(
    auth_manager, auth_requirement, user_credentials
):
    """Test ALL strategy with some providers failing"""
    strategy = AllAuthStrategy()

    result = await strategy.authenticate(
        auth_manager,
        auth_requirement,
        {"jwt": user_credentials, "session": {}},
    )

    assert not result.success
    assert "errors" in result.metadata


async def test_all_strategy_optional_provider(auth_manager, user_credentials):
    """Test ALL strategy with optional provider failure"""
    requirement = AuthenticationRequirement(
        providers=["jwt"], optional_providers=["session"]
    )
    strategy = AllAuthStrategy()

    # Should succeed with only required provider
    result = await strategy.authenticate(
        auth_manager, requirement, {"jwt": user_credentials}
    )

    assert result.success


async def test_all_strategy_metadata_merging(auth_manager, user_credentials):
    """Test metadata merging in ALL strategy"""
    requirement = AuthenticationRequirement(providers=["jwt", "session"])
    strategy = AllAuthStrategy()

    jwt_metadata = {"custom_field": "jwt_value"}
    session_metadata = {"custom_field": "session_value"}

    credentials = {
        "jwt": {**user_credentials, "metadata": jwt_metadata},
        "session": {
            **user_credentials,
            "ip_address": "127.0.0.1",
            "metadata": session_metadata,
        },
    }

    result = await strategy.authenticate(auth_manager, requirement, credentials)

    assert result.success
    assert result.metadata["jwt"]["custom_field"] == "jwt_value"
    assert result.metadata["session"]["custom_field"] == "session_value"
