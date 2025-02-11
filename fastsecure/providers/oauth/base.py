from abc import abstractmethod
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode
import httpx

from ..base import AuthenticationProvider
from ...core.types import AuthenticationResult
from ...exceptions import AuthenticationError


class OAuthProvider(AuthenticationProvider):
    """
    Base class for implementing OAuth 2.0 authentication providers.

    This class provides a foundation for OAuth 2.0 authentication flows,
    handling the standard OAuth operations like authorization URL generation,
    code exchange, token management, and user info retrieval.

    Attributes:
        client_id: OAuth client ID from the provider
        client_secret: OAuth client secret from the provider
        redirect_uri: OAuth callback URL
        scopes: List of OAuth scopes to request
        authorize_endpoint: Provider's authorization endpoint URL
        token_endpoint: Provider's token exchange endpoint URL
        userinfo_endpoint: Provider's user info endpoint URL
        provider_name: Name of the OAuth provider

    Example:
        Implementing a custom OAuth provider:
        ```python
        class CustomOAuthProvider(OAuthProvider):
            def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
                super().__init__(
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uri=redirect_uri,
                    scopes=["profile", "email"],
                    authorize_endpoint="https://custom.com/oauth/authorize",
                    token_endpoint="https://custom.com/oauth/token",
                    userinfo_endpoint="https://custom.com/oauth/userinfo",
                    provider_name="custom"
                )
        ```
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: List[str],
        authorize_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str,
        provider_name: str,
    ):
        """
        Initialize the OAuth provider with required endpoints and credentials.

        Args:
            client_id: OAuth application client ID
            client_secret: OAuth application client secret
            redirect_uri: Callback URL for OAuth flow
            scopes: List of OAuth scopes to request
            authorize_endpoint: Authorization URL
            token_endpoint: Token exchange URL
            userinfo_endpoint: User info URL
            provider_name: Provider identifier
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.authorize_endpoint = authorize_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self._provider_name = provider_name

    @property
    def provider_name(self) -> str:
        """
        Get the name of this OAuth provider.

        Returns:
            str: The provider's name as specified during initialization
        """
        return self._provider_name

    def get_authorization_url(self, state: Optional[str] = None) -> str:
        """
        Generate the OAuth authorization URL for user redirection.

        Builds the URL that users should be redirected to in order to
        begin the OAuth authentication flow.

        Args:
            state: Optional state parameter for CSRF protection

        Returns:
            str: The fully constructed authorization URL

        Example:
            ```python
            url = provider.get_authorization_url(state="random-state-token")
            # Redirect user to this URL
            ```
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "response_type": "code",
        }

        if state:
            params["state"] = state

        return f"{self.authorize_endpoint}?{urlencode(params)}"

    async def exchange_code(
        self, code: str, headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Exchange an authorization code for OAuth tokens.

        Makes a request to the token endpoint to exchange the authorization
        code for access tokens and related data.

        Args:
            code: The authorization code received from the callback
            headers: Optional additional headers for the token request

        Returns:
            Dict[str, Any]: The token response containing:
                - access_token: The OAuth access token
                - token_type: Usually "Bearer"
                - expires_in: Token lifetime in seconds
                - refresh_token: Optional refresh token
                - scope: Granted scopes

        Raises:
            AuthenticationError: If the code exchange fails
        """
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }

        request_headers = headers or {}
        if "Accept" not in request_headers:
            request_headers["Accept"] = "application/json"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_endpoint, data=data, headers=request_headers
            )

            if response.status_code != 200:
                raise AuthenticationError(
                    message="Failed to exchange authorization code",
                    provider=self.provider_name,
                    details={"status_code": response.status_code},
                )

            token_data: dict = await response.json()
            return token_data

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Retrieve user information using the access token.

        Makes a request to the userinfo endpoint to get the authenticated
        user's profile information.

        Args:
            access_token: Valid OAuth access token

        Returns:
            Dict[str, Any]: Raw user info from the provider

        Raises:
            AuthenticationError: If unable to retrieve user info
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(self.userinfo_endpoint, headers=headers)

            if response.status_code != 200:
                raise AuthenticationError(
                    message="Failed to get user info",
                    provider=self.provider_name,
                    details={"status_code": response.status_code},
                )

            user_data: dict = await response.json()
            return user_data

    @abstractmethod
    async def process_user_info(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process provider-specific user info into a standardized format.

        This method should be implemented by each OAuth provider to transform
        the raw user info from their API into a consistent format used across
        the application.

        Args:
            user_info: Raw user info from the provider's API

        Returns:
            Dict[str, Any]: Standardized user info containing at minimum:
                - id: User's unique identifier as string
                - email: User's email address (if available)
        """
        pass

    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """
        Handle the OAuth authentication flow.

        Processes either an authorization code or access token to authenticate
        the user. If a code is provided, it will be exchanged for an access token.
        The access token is then used to retrieve and process user information.

        Args:
            credentials: Dictionary containing either:
                - code: OAuth authorization code from callback
                - access_token: Existing OAuth access token

        Returns:
            AuthenticationResult: Result containing:
                - access_token: The OAuth access token
                - metadata: Processed and raw user info
        """
        try:
            code = credentials.get("code")
            access_token = credentials.get("access_token")

            if code and not access_token:
                token_data = await self.exchange_code(code)
                access_token = token_data.get("access_token")

            if not access_token:
                return AuthenticationResult(
                    success=False,
                    provider=self.provider_name,
                    metadata={"error": "No access token available"},
                )

            user_info = await self.get_user_info(access_token)
            processed_info = await self.process_user_info(user_info)

            return AuthenticationResult(
                success=True,
                provider=self.provider_name,
                access_token=access_token,
                metadata={"user_info": processed_info, "raw_user_info": user_info},
            )

        except Exception as e:
            return AuthenticationResult(
                success=False, provider=self.provider_name, metadata={"error": str(e)}
            )

    async def validate_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """
        Validate an existing OAuth authentication.

        Checks if the access token is still valid by attempting to
        retrieve user information.

        Args:
            auth_data: Dictionary containing:
                - access_token: The OAuth access token to validate

        Returns:
            bool: True if the token is valid and user info was retrieved
        """
        access_token = auth_data.get("access_token")
        if not access_token:
            return False

        try:
            user_info = await self.get_user_info(access_token)
            return bool(user_info)
        except Exception:
            return False
