from abc import ABC, abstractmethod
from typing import Dict, Any, Set

from ..core.types import AuthenticationResult


class AuthenticationProvider(ABC):
    """
    Base class for implementing authentication providers in FastSecure.

    This abstract class defines the interface that all authentication providers must implement,
    providing a consistent way to handle different authentication methods such as JWT tokens,
    sessions, OAuth, etc.

    The provider system is designed to be extensible, allowing you to implement custom
    authentication providers by inheriting from this class and implementing the required
    methods.

    Attributes:
        provider_name: Auto-generated name based on the provider class name.
        supports_refresh: Whether the provider supports token/session refresh.
        supports_revocation: Whether the provider supports token/session revocation.

    Example:
        Create a custom authentication provider:
        ```python
        class CustomAuthProvider(AuthenticationProvider):
            async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
                # Implement authentication logic
                return AuthenticationResult(success=True, provider="custom")

            async def validate_authentication(self, auth_data: Dict[str, Any]) -> bool:
                # Implement validation logic
                return True
        ```

        Register provider with authentication manager:
        ```python
        auth_manager = AuthenticationManager()
        auth_manager.register_provider("custom", CustomAuthProvider())
        ```
    """

    @property
    def provider_name(self) -> str:
        """
        Get the normalized name of this provider.

        Returns:
            str: The provider name, derived from the class name with 'authenticationprovider'
                 removed and converted to lowercase.
        """
        return self.__class__.__name__.lower().replace("authenticationprovider", "")

    def get_required_credentials(self) -> Set[str]:
        """
        Get the set of credential fields required by this provider.

        This method should be overridden by providers to specify which credentials
        are mandatory for authentication.

        Returns:
            Set[str]: Set of required credential field names.

        Example:
            ```python
            def get_required_credentials(self) -> Set[str]:
                return {"username", "password"}
            ```
        """
        return set()

    def get_optional_credentials(self) -> Set[str]:
        """
        Get the set of optional credential fields supported by this provider.

        This method should be overridden by providers to specify which additional
        credentials can be provided but are not mandatory.

        Returns:
            Set[str]: Set of optional credential field names.

        Example:
            ```python
            def get_optional_credentials(self) -> Set[str]:
                return {"remember_me", "device_id"}
            ```
        """
        return set()

    def validate_credentials(self, credentials: Dict[str, Any]) -> bool:
        """
        Validate that all required credentials are present.

        Args:
            credentials: Dictionary containing the credentials to validate.

        Returns:
            bool: True if all required credentials are present, False otherwise.
        """
        required = self.get_required_credentials()
        return all(k in credentials for k in required)

    @abstractmethod
    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate a user with the provided credentials.

        This is the main authentication method that must be implemented by all providers.
        It should verify the credentials and return an AuthenticationResult indicating
        success or failure.

        Args:
            credentials: Dictionary containing the authentication credentials.
                        Required fields are specified by get_required_credentials().

        Returns:
            AuthenticationResult: The result of the authentication attempt, including:
                - success: Whether authentication was successful
                - user_id: The authenticated user's ID (if applicable)
                - access_token: JWT or other token (if applicable)
                - session_id: Session identifier (if applicable)
                - expires_at: Token/session expiration time
                - metadata: Additional provider-specific information

        Raises:
            AuthenticationError: If authentication fails due to invalid credentials.
        """
        pass

    @abstractmethod
    async def validate_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """
        Validate if the current authentication is still valid.

        This method should check if a previously successful authentication
        is still valid (e.g., token not expired, session still active).

        Args:
            auth_data: Dictionary containing the authentication data to validate
                      (e.g., tokens, session IDs).

        Returns:
            bool: True if the authentication is still valid, False otherwise.
        """
        pass

    async def revoke_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """
        Revoke or logout the current authentication.

        Implement this method to support explicit revocation of authentication
        (e.g., token blacklisting, session termination).

        Args:
            auth_data: Dictionary containing the authentication data to revoke.

        Returns:
            bool: True if revocation was successful, False otherwise.
        """
        return True

    async def refresh_authentication(
        self, auth_data: Dict[str, Any]
    ) -> AuthenticationResult:
        """
        Refresh authentication tokens or session.

        Implement this method to support token/session refresh operations
        (e.g., using refresh tokens to obtain new access tokens).

        Args:
            auth_data: Dictionary containing the authentication data to refresh.

        Returns:
            AuthenticationResult: The result of the refresh attempt.
        """
        return AuthenticationResult(
            success=False,
            provider=self.provider_name,
            metadata={"error": "Refresh not supported"},
        )

    @property
    def supports_refresh(self) -> bool:
        """
        Whether this provider supports refreshing authentication.

        Override this property to return True if the provider implements
        refresh_authentication().

        Returns:
            bool: True if refresh is supported, False otherwise.
        """
        return False

    @property
    def supports_revocation(self) -> bool:
        """
        Whether this provider supports revoking authentication.

        Override this property to return True if the provider implements
        revoke_authentication() with custom logic.

        Returns:
            bool: True if revocation is supported, False otherwise.
        """
        return False
