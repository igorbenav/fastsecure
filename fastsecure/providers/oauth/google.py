from typing import Dict, Any, List, Optional

from .base import OAuthProvider


class GoogleAuthProvider(OAuthProvider):
    """Google OAuth authentication provider"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
    ):
        default_scopes = [
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ]

        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes or default_scopes,
            authorize_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
            token_endpoint="https://oauth2.googleapis.com/token",
            userinfo_endpoint="https://www.googleapis.com/oauth2/v3/userinfo",
            provider_name="google",
        )

    async def process_user_info(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process Google user info into standardized format"""
        return {
            "id": user_info.get("sub"),
            "email": user_info.get("email"),
            "email_verified": user_info.get("email_verified"),
            "name": user_info.get("name"),
            "given_name": user_info.get("given_name"),
            "family_name": user_info.get("family_name"),
            "picture": user_info.get("picture"),
            "locale": user_info.get("locale"),
        }
