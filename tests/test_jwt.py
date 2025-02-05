import pytest
import asyncio
from jose import jwt

from fastsecure import JWTAuthenticationProvider

pytestmark = pytest.mark.asyncio


async def test_jwt_authentication_success(jwt_provider, user_credentials):
    """Test successful JWT authentication"""
    result = await jwt_provider.authenticate(user_credentials)

    assert result.success
    assert result.provider == "jwt"
    assert result.access_token is not None
    assert result.refresh_token is not None
    assert result.user_id == user_credentials["user_id"]

    # Verify token contents
    payload = jwt.decode(
        result.access_token,
        jwt_provider.secret_key,
        algorithms=[jwt_provider.algorithm],
    )
    assert payload["sub"] == str(user_credentials["user_id"])
    assert payload["token_type"] == "access"
    assert "exp" in payload


async def test_jwt_missing_user_id(jwt_provider):
    """Test JWT authentication with missing user_id"""
    result = await jwt_provider.authenticate({})
    assert not result.success
    assert "Missing user_id" in str(result.metadata.get("error", ""))


async def test_jwt_validation_success(jwt_provider, user_credentials):
    """Test successful JWT token validation"""
    auth_result = await jwt_provider.authenticate(user_credentials)
    assert auth_result.success

    is_valid = await jwt_provider.validate_authentication(
        {"access_token": auth_result.access_token}
    )
    assert is_valid


async def test_jwt_validation_invalid_token(jwt_provider):
    """Test JWT validation with invalid token"""
    is_valid = await jwt_provider.validate_authentication(
        {"access_token": "invalid-token"}
    )
    assert not is_valid


async def test_jwt_refresh_success(jwt_provider, user_credentials):
    """Test successful JWT token refresh"""
    # First authenticate to get tokens
    auth_result = await jwt_provider.authenticate(user_credentials)
    assert auth_result.success

    # Store original tokens
    original_access = auth_result.access_token
    original_refresh = auth_result.refresh_token

    # Small delay to ensure different token
    await asyncio.sleep(1)

    # Try to refresh
    refresh_result = await jwt_provider.refresh_authentication(
        {"refresh_token": original_refresh}
    )

    assert refresh_result.success
    assert refresh_result.access_token is not None
    assert refresh_result.refresh_token is not None
    assert refresh_result.access_token != original_access
    assert refresh_result.refresh_token != original_refresh


async def test_jwt_refresh_invalid_token(jwt_provider):
    """Test JWT refresh with invalid token"""
    refresh_result = await jwt_provider.refresh_authentication(
        {"refresh_token": "invalid-token"}
    )
    assert not refresh_result.success


async def test_jwt_token_expiration(jwt_provider, user_credentials):
    """Test JWT token expiration"""
    # Create provider with very short expiration
    short_provider = JWTAuthenticationProvider(
        secret_key=jwt_provider.secret_key,
        access_token_expire_minutes=0,  # Expire immediately
    )

    result = await short_provider.authenticate(user_credentials)
    assert result.success

    # Small delay to ensure token expires
    await asyncio.sleep(0.1)

    # Token should be invalid due to expiration
    is_valid = await short_provider.validate_authentication(
        {"access_token": result.access_token}
    )
    assert not is_valid


async def test_jwt_scopes(jwt_provider):
    """Test JWT with scopes"""
    credentials = {"user_id": 123, "scopes": ["read:profile", "write:profile"]}

    result = await jwt_provider.authenticate(credentials)
    assert result.success

    # Verify scopes in token
    payload = jwt.decode(
        result.access_token,
        jwt_provider.secret_key,
        algorithms=[jwt_provider.algorithm],
    )
    assert set(payload.get("scopes", [])) == set(credentials["scopes"])
