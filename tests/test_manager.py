import pytest

from fastsecure import AuthStrategy
from fastsecure.exceptions import ProviderNotFoundError

pytestmark = pytest.mark.asyncio


async def test_register_provider(auth_manager, jwt_provider):
    """Test registering a new provider"""
    auth_manager.register_provider("custom_jwt", jwt_provider)
    assert "custom_jwt" in auth_manager.get_available_providers()
    assert auth_manager.get_provider("custom_jwt") == jwt_provider


async def test_add_requirement_any_strategy(auth_manager):
    """Test adding requirement with ANY strategy"""
    auth_manager.add_requirement(
        path="/api/flexible", providers=["jwt", "session"], strategy=AuthStrategy.ANY
    )

    requirement = auth_manager.get_requirement("/api/flexible")
    assert requirement is not None
    assert requirement.strategy == AuthStrategy.ANY
    assert requirement.required_providers == {"jwt", "session"}


async def test_add_requirement_all_strategy(auth_manager):
    """Test adding requirement with ALL strategy"""
    auth_manager.add_requirement(
        path="/api/secure", providers=["jwt", "session"], strategy=AuthStrategy.ALL
    )

    requirement = auth_manager.get_requirement("/api/secure")
    assert requirement is not None
    assert requirement.strategy == AuthStrategy.ALL
    assert requirement.required_providers == {"jwt", "session"}


async def test_add_requirement_with_optional_providers(auth_manager):
    """Test adding requirement with optional providers"""
    auth_manager.add_requirement(
        path="/api/mixed",
        providers=["jwt"],
        optional_providers=["session"],
        strategy=AuthStrategy.ANY,
    )

    requirement = auth_manager.get_requirement("/api/mixed")
    assert requirement is not None
    assert requirement.required_providers == {"jwt"}
    assert requirement.optional_providers == {"session"}


async def test_add_requirement_invalid_provider(auth_manager):
    """Test adding requirement with non-existent provider"""
    with pytest.raises(ProviderNotFoundError):
        auth_manager.add_requirement(
            path="/api/invalid", providers=["invalid_provider"]
        )


async def test_authenticate_any_strategy_success(
    auth_manager, user_credentials, mock_request_data
):
    """Test successful authentication with ANY strategy"""
    # Add requirement
    auth_manager.add_requirement(
        path="/api/flexible", providers=["jwt", "session"], strategy=AuthStrategy.ANY
    )

    # Try with JWT
    jwt_result = await auth_manager.authenticate(
        path="/api/flexible", credentials={"jwt": user_credentials}
    )
    assert jwt_result.success
    assert jwt_result.provider == "jwt"

    # Try with Session
    session_result = await auth_manager.authenticate(
        path="/api/flexible",
        credentials={"session": {**user_credentials, **mock_request_data}},
    )
    assert session_result.success
    assert session_result.provider == "session"


async def test_authenticate_all_strategy_success(
    auth_manager, user_credentials, mock_request_data
):
    """Test successful authentication with ALL strategy"""
    # Add requirement
    auth_manager.add_requirement(
        path="/api/secure", providers=["jwt", "session"], strategy=AuthStrategy.ALL
    )

    # Authenticate with both providers
    result = await auth_manager.authenticate(
        path="/api/secure",
        credentials={
            "jwt": user_credentials,
            "session": {**user_credentials, **mock_request_data},
        },
    )

    assert result.success
    assert result.provider == "all"
    assert "jwt" in result.metadata
    assert "session" in result.metadata


async def test_authenticate_all_strategy_partial_failure(
    auth_manager, user_credentials
):
    """Test ALL strategy with one provider failing"""
    # Add requirement
    auth_manager.add_requirement(
        path="/api/secure", providers=["jwt", "session"], strategy=AuthStrategy.ALL
    )

    # Try with only JWT credentials
    result = await auth_manager.authenticate(
        path="/api/secure", credentials={"jwt": user_credentials}
    )

    assert not result.success
    assert (
        "Missing credentials for required provider: session"
        in result.metadata["errors"]
    )


async def test_authenticate_path_not_found(auth_manager, user_credentials):
    """Test authentication for path with no requirement"""
    result = await auth_manager.authenticate(
        path="/api/no-requirement", credentials={"jwt": user_credentials}
    )

    assert not result.success
    assert "No authentication requirement found" in result.metadata["error"]


async def test_path_pattern_matching(auth_manager):
    """Test path pattern matching for requirements"""
    # Add requirement with wildcard
    auth_manager.add_requirement(path="/api/users/*", providers=["jwt"])

    # Should match pattern
    requirement = auth_manager.get_requirement("/api/users/123")
    assert requirement is not None
    assert "jwt" in requirement.required_providers

    # Should not match different path
    requirement = auth_manager.get_requirement("/api/products/123")
    assert requirement is None


async def test_validate_authentication_any_strategy(
    auth_manager, user_credentials, mock_request_data
):
    """Test validation with ANY strategy"""
    # Add requirement
    auth_manager.add_requirement(
        path="/api/flexible", providers=["jwt", "session"], strategy=AuthStrategy.ANY
    )

    # Get valid auth data
    jwt_result = await auth_manager.authenticate(
        path="/api/flexible", credentials={"jwt": user_credentials}
    )

    # Validate authentication
    is_valid = await auth_manager.validate_authentication(
        path="/api/flexible",
        auth_data={"jwt": {"access_token": jwt_result.access_token}},
    )
    assert is_valid


async def test_validate_authentication_all_strategy(
    auth_manager, user_credentials, mock_request_data
):
    """Test validation with ALL strategy"""
    # Add requirement
    auth_manager.add_requirement(
        path="/api/secure", providers=["jwt", "session"], strategy=AuthStrategy.ALL
    )

    # First get a JWT token
    jwt_result = await auth_manager.get_provider("jwt").authenticate(user_credentials)
    assert jwt_result.success

    # Now authenticate with both
    combined_result = await auth_manager.authenticate(
        path="/api/secure",
        credentials={
            "jwt": {
                "access_token": jwt_result.access_token,
                "user_id": user_credentials["user_id"],
            },
            "session": {**user_credentials, **mock_request_data},
        },
    )
    assert combined_result.success

    # Validate using the JWT token and session ID
    is_valid = await auth_manager.validate_authentication(
        path="/api/secure",
        auth_data={
            "jwt": {"access_token": jwt_result.access_token},
            "session": {"session_id": combined_result.session_id},
        },
    )
    assert is_valid
