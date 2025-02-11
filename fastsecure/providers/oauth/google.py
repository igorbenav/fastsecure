from typing import Dict, Any, List, Optional

from .base import OAuthProvider


class GoogleAuthProvider(OAuthProvider):
    """
    OAuth authentication provider for Google Sign-In.

    This provider implements Google's OAuth 2.0 authentication flow,
    allowing users to sign in with their Google accounts. It handles
    the OAuth flow and standardizes the user information format.

    Attributes:
        default_scopes: Default OAuth scopes for Google Sign-In:
            - openid: OpenID Connect support
            - userinfo.email: Email address access
            - userinfo.profile: Basic profile information

    Example:
        Basic initialization:
        ```python
        provider = GoogleAuthProvider(
            client_id="your-client-id",
            client_secret="your-client-secret",
            redirect_uri="https://your-app.com/callback"
        )
        ```

        Custom scopes:
        ```python
        provider = GoogleAuthProvider(
            client_id="your-client-id",
            client_secret="your-client-secret",
            redirect_uri="https://your-app.com/callback",
            scopes=["openid", "email", "profile", "calendar.readonly"]
        )
        ```

        Usage with AuthenticationManager:
        ```python
        auth_manager = AuthenticationManager()
        auth_manager.register_provider(
            "google",
            GoogleAuthProvider(
                client_id="your-client-id",
                client_secret="your-client-secret",
                redirect_uri="https://your-app.com/callback"
            )
        )
        ```
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: Optional[List[str]] = None,
    ):
        """
        Initialize the Google OAuth provider.

        Args:
            client_id: Google OAuth client ID from Google Cloud Console
            client_secret: Google OAuth client secret
            redirect_uri: Callback URL for OAuth flow completion
            scopes: Optional list of Google OAuth scopes to request.
                   If not provided, uses default scopes for basic profile
                   and email access.
        """
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
        """
        Process Google user info into a standardized format.

        Transforms the raw user info from Google's userinfo endpoint
        into a consistent format used across the application.

        Args:
            user_info: Raw user info from Google containing fields like
                      sub, email, name, picture, etc.

        Returns:
            Dict[str, Any]: Standardized user info containing:
                - id: User's Google ID (sub claim)
                - email: User's email address
                - email_verified: Whether email is verified
                - name: Full name
                - given_name: First name
                - family_name: Last name
                - picture: Profile picture URL
                - locale: User's locale preference

        Example:
            ```python
            raw_info = await provider.get_user_info(access_token)
            processed = await provider.process_user_info(raw_info)
            # processed = {
            #     "id": "123456789",
            #     "email": "user@example.com",
            #     "name": "John Doe",
            #     ...
            # }
            ```
        """
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
