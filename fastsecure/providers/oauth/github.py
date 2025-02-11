from typing import Dict, Any, List, Optional
import httpx

from .base import OAuthProvider


class GitHubAuthProvider(OAuthProvider):
    """
    OAuth authentication provider for GitHub Sign-In.

    This provider implements GitHub's OAuth 2.0 authentication flow,
    allowing users to sign in with their GitHub accounts. It handles
    the OAuth flow and standardizes the user information format.

    Attributes:
        default_scopes: Default OAuth scopes for GitHub Sign-In:
            - read:user: Read-only access to profile information
            - user:email: Access to user's email addresses

    Example:
        Basic initialization:
        ```python
        provider = GitHubAuthProvider(
            client_id="your-client-id",
            client_secret="your-client-secret",
            redirect_uri="https://your-app.com/callback"
        )
        ```

        Custom scopes:
        ```python
        provider = GitHubAuthProvider(
            client_id="your-client-id",
            client_secret="your-client-secret",
            redirect_uri="https://your-app.com/callback",
            scopes=["read:user", "user:email", "repo"]
        )
        ```

        Usage with AuthenticationManager:
        ```python
        auth_manager = AuthenticationManager()
        auth_manager.register_provider(
            "github",
            GitHubAuthProvider(
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
        Initialize the GitHub OAuth provider.

        Args:
            client_id: GitHub OAuth client ID from GitHub Developer Settings
            client_secret: GitHub OAuth client secret
            redirect_uri: Callback URL for OAuth flow completion
            scopes: Optional list of GitHub OAuth scopes to request.
                   If not provided, uses default scopes for basic profile
                   and email access.
        """
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

    async def exchange_code(
        self, code: str, headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Override to handle GitHub-specific token response.

        GitHub requires the 'Accept: application/json' header to receive
        the response in JSON format instead of the default
        application/x-www-form-urlencoded.

        Args:
            code: The authorization code received from GitHub
            headers: Optional additional headers for the token request

        Returns:
            Dict[str, Any]: The token response containing:
                - access_token: OAuth access token
                - token_type: Token type (usually "bearer")
                - scope: Granted scopes as a comma-separated string
        """
        headers = {"Accept": "application/json"}
        return await super().exchange_code(code, headers=headers)

    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get both user profile and email information from GitHub.

        Makes two API calls:
        1. Fetches the user's profile from the user endpoint
        2. Fetches the user's email addresses from the emails endpoint

        GitHub requires separate API calls to get email information,
        especially for users with private email addresses.

        Args:
            access_token: Valid GitHub OAuth access token

        Returns:
            Dict[str, Any]: Combined user profile and email data containing:
                - Basic profile fields (id, name, login, etc.)
                - emails: List of user's email addresses with verification status

        Example:
            ```python
            user_info = await provider.get_user_info(access_token)
            # user_info = {
            #     "id": 123456,
            #     "login": "username",
            #     "name": "Full Name",
            #     "emails": [
            #         {"email": "user@example.com", "primary": true, "verified": true},
            #         ...
            #     ],
            #     ...
            # }
            ```
        """
        profile = await super().get_user_info(access_token)

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user/emails", headers=headers
            )

            if response.status_code == 200:
                emails_data = await response.json()
                profile["emails"] = emails_data

        return profile

    async def process_user_info(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process GitHub user info into standardized format.

        Transforms the raw user info from GitHub's API into a consistent
        format used across the application. Handles the extraction of
        primary email and its verification status from the emails array.

        Args:
            user_info: Raw user info from GitHub containing fields like
                      id, login, name, emails array, etc.

        Returns:
            Dict[str, Any]: Standardized user info containing:
                - id: User's GitHub ID as string
                - email: Primary email address
                - email_verified: Whether primary email is verified
                - name: Full name
                - login: GitHub username
                - avatar_url: Profile picture URL
                - bio: User biography
                - company: User's company
                - location: User's location

        Example:
            ```python
            raw_info = await provider.get_user_info(access_token)
            processed = await provider.process_user_info(raw_info)
            # processed = {
            #     "id": "123456",
            #     "email": "user@example.com",
            #     "email_verified": true,
            #     "name": "John Doe",
            #     "login": "johndoe",
            #     ...
            # }
            ```
        """
        email = None
        email_verified = False

        if emails := user_info.get("emails", []):
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
