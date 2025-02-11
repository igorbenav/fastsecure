import pytest
from unittest.mock import patch, MagicMock

from fastsecure import GoogleAuthProvider, GitHubAuthProvider
from fastsecure.exceptions import AuthenticationError

pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_response():
    response = MagicMock()

    async def async_json():
        return response._json_data

    response.json = async_json
    return response


@pytest.fixture
def google_provider():
    return GoogleAuthProvider(
        client_id="test-client-id",
        client_secret="test-client-secret",
        redirect_uri="http://localhost:8000/auth/google/callback",
    )


@pytest.fixture
def github_provider():
    return GitHubAuthProvider(
        client_id="test-client-id",
        client_secret="test-client-secret",
        redirect_uri="http://localhost:8000/auth/github/callback",
    )


async def test_google_authorization_url(google_provider):
    """Test Google OAuth authorization URL generation"""
    url = google_provider.get_authorization_url(state="test-state")
    assert "accounts.google.com/o/oauth2/v2/auth" in url
    assert "client_id=test-client-id" in url
    assert "state=test-state" in url
    assert "openid" in url


@patch("httpx.AsyncClient.post")
async def test_google_exchange_code(mock_post, google_provider, mock_response):
    """Test Google OAuth code exchange"""
    mock_response.status_code = 200
    mock_response._json_data = {
        "access_token": "test-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    mock_post.return_value = mock_response

    token_data = await google_provider.exchange_code("test-code")

    mock_post.assert_called_once()
    assert token_data["access_token"] == "test-access-token"


@patch("httpx.AsyncClient.get")
async def test_google_user_info(mock_get, google_provider, mock_response):
    """Test Google user info retrieval"""
    mock_response.status_code = 200
    mock_response._json_data = {
        "sub": "12345",
        "email": "test@example.com",
        "email_verified": True,
        "name": "Test User",
    }
    mock_get.return_value = mock_response

    user_info = await google_provider.get_user_info("test-access-token")
    processed = await google_provider.process_user_info(user_info)

    mock_get.assert_called_once()
    assert processed["id"] == "12345"
    assert processed["email"] == "test@example.com"
    assert processed["email_verified"] is True


@patch("httpx.AsyncClient.post")
async def test_github_exchange_code(mock_post, github_provider, mock_response):
    """Test GitHub OAuth code exchange"""
    mock_response.status_code = 200
    mock_response._json_data = {
        "access_token": "test-access-token",
        "token_type": "Bearer",
        "scope": "read:user,user:email",
    }
    mock_post.return_value = mock_response

    token_data = await github_provider.exchange_code("test-code")

    mock_post.assert_called_once()
    assert token_data["access_token"] == "test-access-token"


@patch("httpx.AsyncClient.get")
async def test_github_user_info(mock_get, github_provider, mock_response):
    """Test GitHub user info retrieval with email"""
    profile_response = MagicMock()

    async def profile_json():
        return {"id": 12345, "login": "testuser", "name": "Test User", "email": None}

    profile_response.json = profile_json
    profile_response.status_code = 200

    email_response = MagicMock()

    async def email_json():
        return [{"email": "test@example.com", "primary": True, "verified": True}]

    email_response.json = email_json
    email_response.status_code = 200

    mock_get.side_effect = [profile_response, email_response]

    user_info = await github_provider.get_user_info("test-access-token")
    processed = await github_provider.process_user_info(user_info)

    assert mock_get.call_count == 2
    assert processed["id"] == "12345"
    assert processed["email"] == "test@example.com"
    assert processed["email_verified"] is True
    assert processed["login"] == "testuser"


@patch("httpx.AsyncClient.post")
@patch("httpx.AsyncClient.get")
async def test_github_authentication_flow(mock_get, mock_post, github_provider):
    """Test complete GitHub authentication flow"""
    # Mock token exchange
    token_response = MagicMock()

    async def token_json():
        return {"access_token": "test-access-token", "token_type": "Bearer"}

    token_response.json = token_json
    token_response.status_code = 200
    mock_post.return_value = token_response

    # Mock profile and email responses
    profile_response = MagicMock()

    async def profile_json():
        return {"id": 12345, "login": "testuser", "name": "Test User"}

    profile_response.json = profile_json
    profile_response.status_code = 200

    email_response = MagicMock()

    async def email_json():
        return [{"email": "test@example.com", "primary": True, "verified": True}]

    email_response.json = email_json
    email_response.status_code = 200

    mock_get.side_effect = [profile_response, email_response]

    # Test the full authentication flow
    result = await github_provider.authenticate({"code": "test-code"})

    assert result.success
    assert result.access_token == "test-access-token"
    assert result.metadata["user_info"]["id"] == "12345"
    assert result.metadata["user_info"]["email"] == "test@example.com"
    assert result.provider == "github"

    # Verify mock calls
    mock_post.assert_called_once()
    assert mock_get.call_count == 2


@patch("httpx.AsyncClient.get")
async def test_oauth_error_handling(mock_get, google_provider, mock_response):
    """Test OAuth error handling"""
    mock_response.status_code = 401
    mock_get.return_value = mock_response

    with pytest.raises(AuthenticationError) as exc:
        await google_provider.get_user_info("invalid-token")
    assert "Failed to get user info" in str(exc.value)


@patch("httpx.AsyncClient.get")
async def test_oauth_validation(mock_get, google_provider, mock_response):
    """Test OAuth token validation"""
    # Test validation with missing token
    is_valid = await google_provider.validate_authentication({})
    assert not is_valid

    # Test validation with wrong key
    is_valid = await google_provider.validate_authentication({"wrong_key": "value"})
    assert not is_valid

    # Test validation with invalid token
    mock_response.status_code = 401
    mock_get.return_value = mock_response
    is_valid = await google_provider.validate_authentication(
        {"access_token": "invalid"}
    )
    assert not is_valid

    # Test validation with valid token
    mock_response.status_code = 200
    mock_response._json_data = {"sub": "12345"}
    mock_get.return_value = mock_response
    is_valid = await google_provider.validate_authentication(
        {"access_token": "valid-token"}
    )
    assert is_valid


@patch("httpx.AsyncClient.post")
@patch("httpx.AsyncClient.get")
async def test_google_authentication_flow(mock_get, mock_post, google_provider):
    """Test complete Google authentication flow"""
    # Mock token exchange
    token_response = MagicMock()

    async def token_json():
        return {
            "access_token": "test-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

    token_response.json = token_json
    token_response.status_code = 200
    mock_post.return_value = token_response

    # Mock user info response
    user_response = MagicMock()

    async def user_json():
        return {
            "sub": "12345",
            "email": "test@example.com",
            "email_verified": True,
            "name": "Test User",
        }

    user_response.json = user_json
    user_response.status_code = 200
    mock_get.return_value = user_response

    # Test the full authentication flow
    result = await google_provider.authenticate({"code": "test-code"})

    assert result.success
    assert result.access_token == "test-access-token"
    assert result.metadata["user_info"]["id"] == "12345"
    assert result.metadata["user_info"]["email"] == "test@example.com"
    assert result.provider == "google"

    # Verify mock calls
    mock_post.assert_called_once()
    mock_get.assert_called_once()


@patch("httpx.AsyncClient.post")
async def test_oauth_token_exchange_error(mock_post, github_provider, mock_response):
    """Test error handling during token exchange"""
    mock_response.status_code = 400
    mock_post.return_value = mock_response

    with pytest.raises(AuthenticationError) as exc:
        await github_provider.exchange_code("invalid-code")
    assert "Failed to exchange authorization code" in str(exc.value)


async def test_oauth_provider_names():
    """Test provider name consistency"""
    google = GoogleAuthProvider(
        client_id="test", client_secret="test", redirect_uri="test"
    )
    github = GitHubAuthProvider(
        client_id="test", client_secret="test", redirect_uri="test"
    )

    assert google.provider_name == "google"
    assert github.provider_name == "github"
