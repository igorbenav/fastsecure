from abc import abstractmethod
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode

import httpx

from ..base import AuthenticationProvider
from ...core.types import AuthenticationResult
from ...exceptions import AuthenticationError


class OAuthProvider(AuthenticationProvider):
    """Base class for OAuth providers"""

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
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.authorize_endpoint = authorize_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.provider_name = provider_name

    def get_authorization_url(self, state: Optional[str] = None) -> str:
        """Get the authorization URL for redirecting users"""
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "response_type": "code",
        }

        if state:
            params["state"] = state

        return f"{self.authorize_endpoint}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> Dict[str, Any]:
        """Exchange authorization code for tokens"""
        async with httpx.AsyncClient() as client:
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code",
            }

            response = await client.post(self.token_endpoint, data=data)
            if response.status_code != 200:
                raise AuthenticationError(
                    message="Failed to exchange authorization code",
                    provider=self.provider_name,
                    details={"status_code": response.status_code},
                )

            return response.json()

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from provider"""
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = await client.get(self.userinfo_endpoint, headers=headers)

            if response.status_code != 200:
                raise AuthenticationError(
                    message="Failed to get user info",
                    provider=self.provider_name,
                    details={"status_code": response.status_code},
                )

            return response.json()

    @abstractmethod
    async def process_user_info(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process provider-specific user info into standardized format"""
        pass

    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """Handle OAuth authentication flow"""
        code = credentials.get("code")
        access_token = credentials.get("access_token")

        try:
            if code:
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
        """Validate OAuth authentication"""
        access_token = auth_data.get("access_token")
        if not access_token:
            return False

        try:
            user_info = await self.get_user_info(access_token)
            return bool(user_info)
        except Exception:
            return False
