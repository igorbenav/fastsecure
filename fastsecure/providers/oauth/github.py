from typing import Dict, Any, List, Optional
import httpx

from .base import OAuthProvider


class GitHubAuthProvider(OAuthProvider):
    """GitHub OAuth authentication provider"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
    ):
        default_scopes = ["read:user", "user:email"]

        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes or default_scopes,
            authorize_endpoint="https://github.com/login/oauth/authorize",
            token_endpoint="https://github.com/login/oauth/access_token",
            userinfo_endpoint="https://api.github.com/user",
            provider_name="github",
        )

    async def exchange_code(self, code: str) -> Dict[str, Any]:
        """Override to handle GitHub-specific token response"""
        headers = {"Accept": "application/json"}
        data = await super().exchange_code(code, headers=headers)
        return data

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get both user profile and email"""
        profile = await super().get_user_info(access_token)

        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            }
            response = await client.get(
                "https://api.github.com/user/emails", headers=headers
            )

            if response.status_code == 200:
                profile["emails"] = response.json()

        return profile

    async def process_user_info(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process GitHub user info into standardized format"""
        email = None
        email_verified = False
        if emails := user_info.get("emails"):
            for e in emails:
                if e.get("primary"):
                    email = e.get("email")
                    email_verified = e.get("verified", False)
                    break

        return {
            "id": str(user_info.get("id")),
            "email": email,
            "email_verified": email_verified,
            "name": user_info.get("name"),
            "login": user_info.get("login"),
            "avatar_url": user_info.get("avatar_url"),
            "bio": user_info.get("bio"),
            "company": user_info.get("company"),
            "location": user_info.get("location"),
        }
