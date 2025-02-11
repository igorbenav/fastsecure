from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

from .types import AuthStrategy, AuthenticationResult, AuthenticationRequirement
from .strategies import AuthenticationStrategy, AnyAuthStrategy, AllAuthStrategy
from ..providers.base import AuthenticationProvider
from ..password import PasswordHasher, BCryptPasswordHasher
from ..exceptions import ProviderNotFoundError


class AuthenticationManager:
    """
    Central manager for handling multiple authentication providers and strategies.

    This class provides a flexible system for managing authentication across
    different providers (like OAuth, JWT, etc.) and implementing various
    authentication strategies. It supports path-based authentication
    requirements and handles provider registration, validation, and refresh.

    Attributes:
        providers: Dictionary mapping provider names to AuthenticationProvider instances
        strategies: Dictionary mapping AuthStrategy types to strategy implementations
        _requirements: Dictionary mapping paths to their authentication requirements
        _password_hasher: Password hasher instance for handling password operations

    Example:
        Basic setup with OAuth providers:
        ```python
        auth_manager = AuthenticationManager()

        # Register providers
        auth_manager.register_provider(
            "google",
            GoogleAuthProvider(
                client_id="client-id",
                client_secret="client-secret",
                redirect_uri="https://app.com/callback"
            )
        )

        # Add authentication requirements
        auth_manager.add_requirement(
            path="/api/protected/*",
            providers=["google"],
            strategy=AuthStrategy.ANY
        )

        # Authenticate request
        result = await auth_manager.authenticate(
            path="/api/protected/resource",
            credentials={"google": {"code": "auth_code"}}
        )
        ```

        Multiple provider setup:
        ```python
        # Register multiple providers
        auth_manager.register_provider("github", github_provider)
        auth_manager.register_provider("google", google_provider)

        # Require any one of multiple providers
        auth_manager.add_requirement(
            path="/api/dashboard",
            providers=["github", "google"],
            strategy=AuthStrategy.ANY
        )

        # Require all specified providers
        auth_manager.add_requirement(
            path="/api/admin",
            providers=["github", "google"],
            strategy=AuthStrategy.ALL
        )
        ```

        Password hashing:
        ```python
        # Hash and verify passwords
        hashed = auth_manager.hash_password("mypassword")
        is_valid = auth_manager.verify_password("mypassword", hashed)

        # Use custom password hasher
        custom_hasher = BCryptPasswordHasher(rounds=14)
        auth_manager.set_password_hasher(custom_hasher)
        ```
    """

    def __init__(self, password_hasher: Optional[PasswordHasher] = None) -> None:
        """
        Initialize the authentication manager.

        Sets up empty provider registry, default authentication strategies
        (ANY and ALL), and password hashing functionality.

        Args:
            password_hasher: Optional custom password hasher implementation
                           (defaults to BCryptPasswordHasher)
        """
        self.providers: Dict[str, AuthenticationProvider] = {}
        self.strategies: Dict[AuthStrategy, AuthenticationStrategy] = {
            AuthStrategy.ANY: AnyAuthStrategy(),
            AuthStrategy.ALL: AllAuthStrategy(),
        }
        self._requirements: Dict[str, AuthenticationRequirement] = {}
        self._password_hasher = password_hasher or BCryptPasswordHasher()

    def hash_password(self, password: str) -> str:
        """
        Hash a password using the configured password hasher.

        Args:
            password: Plain text password to hash

        Returns:
            str: Hashed password

        Example:
            ```python
            auth_manager = AuthenticationManager()
            hashed = auth_manager.hash_password("mypassword")
            ```
        """
        return self._password_hasher.hash_password(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash using the configured password hasher.

        Args:
            plain_password: Plain text password to verify
            hashed_password: Hash to verify against

        Returns:
            bool: True if password matches hash, False otherwise

        Example:
            ```python
            auth_manager = AuthenticationManager()
            is_valid = auth_manager.verify_password("mypassword", hashed)
            ```
        """
        return self._password_hasher.verify_password(plain_password, hashed_password)

    def set_password_hasher(self, password_hasher: PasswordHasher) -> None:
        """
        Update the password hasher used by this authentication manager.

        Args:
            password_hasher: New password hasher implementation to use

        Example:
            ```python
            auth_manager = AuthenticationManager()
            custom_hasher = BCryptPasswordHasher(rounds=14)
            auth_manager.set_password_hasher(custom_hasher)
            ```
        """
        self._password_hasher = password_hasher

    def register_provider(self, name: str, provider: AuthenticationProvider) -> None:
        """
        Register a new authentication provider.

        Adds a provider to the registry, making it available for use in
        authentication requirements.

        Args:
            name: Unique identifier for the provider
            provider: Instance of AuthenticationProvider to register

        Example:
            ```python
            auth_manager.register_provider(
                "google",
                GoogleAuthProvider(
                    client_id="client-id",
                    client_secret="client-secret",
                    redirect_uri="callback-url"
                )
            )
            ```
        """
        self.providers[name] = provider

    def get_provider(self, name: str) -> Optional[AuthenticationProvider]:
        """
        Get a registered provider by name.

        Args:
            name: Name of the provider to retrieve

        Returns:
            Optional[AuthenticationProvider]: The provider instance if found,
            None otherwise

        Example:
            ```python
            google_provider = auth_manager.get_provider("google")
            if google_provider:
                auth_url = google_provider.get_authorization_url()
            ```
        """
        return self.providers.get(name)

    def get_available_providers(self) -> List[str]:
        """
        Get list of registered provider names.

        Returns:
            List[str]: Names of all registered providers

        Example:
            ```python
            providers = auth_manager.get_available_providers()
            # providers = ["google", "github", "jwt"]
            ```
        """
        return list(self.providers.keys())

    def add_requirement(
        self,
        path: str,
        providers: List[str],
        strategy: AuthStrategy = AuthStrategy.ANY,
        optional_providers: Optional[List[str]] = None,
        scopes: Optional[List[str]] = None,
    ) -> None:
        """
        Add authentication requirement for a path.

        Configures which providers and strategy are required for
        authenticating requests to a specific path. Supports path
        patterns with wildcards.

        Args:
            path: URL path or pattern to protect
            providers: List of required provider names
            strategy: Authentication strategy (ANY or ALL)
            optional_providers: Additional optional providers
            scopes: Required OAuth scopes if applicable

        Raises:
            ProviderNotFoundError: If any specified provider is not registered

        Example:
            ```python
            # Simple requirement
            auth_manager.add_requirement(
                path="/api/user/*",
                providers=["google"]
            )

            # Complex requirement
            auth_manager.add_requirement(
                path="/api/admin/*",
                providers=["google", "github"],
                strategy=AuthStrategy.ALL,
                optional_providers=["jwt"],
                scopes=["admin"]
            )
            ```
        """
        requirement = AuthenticationRequirement(
            providers=providers,
            strategy=strategy,
            optional_providers=optional_providers,
            scopes=scopes,
        )

        if not requirement.validate_providers(set(self.providers.keys())):
            raise ProviderNotFoundError("One or more providers not registered")

        self._requirements[path] = requirement

    def get_requirement(self, path: str) -> Optional[AuthenticationRequirement]:
        """
        Get authentication requirement for a path.

        Finds the matching authentication requirement for a given path,
        supporting wildcard patterns.

        Args:
            path: URL path to check

        Returns:
            Optional[AuthenticationRequirement]: Matching requirement if found,
            None otherwise

        Example:
            ```python
            # Matches exact path
            req = auth_manager.get_requirement("/api/user/profile")

            # Matches pattern
            req = auth_manager.get_requirement("/api/admin/users")
            if req:
                print(f"Strategy: {req.strategy}")
            ```
        """
        if path in self._requirements:
            return self._requirements[path]

        parsed_path = urlparse(path)
        path_parts = parsed_path.path.split("/")

        for req_path, requirement in self._requirements.items():
            req_parts = req_path.split("/")
            if self._match_path_pattern(path_parts, req_parts):
                return requirement

        return None

    def _match_path_pattern(
        self, path_parts: List[str], pattern_parts: List[str]
    ) -> bool:
        """
        Match a path against a pattern with wildcards.

        Internal method used to support wildcard matching in path patterns.

        Args:
            path_parts: Components of the actual path
            pattern_parts: Components of the pattern to match against

        Returns:
            bool: True if path matches pattern, False otherwise
        """
        if len(path_parts) != len(pattern_parts):
            return False

        for path_part, pattern_part in zip(path_parts, pattern_parts):
            if pattern_part != "*" and path_part != pattern_part:
                return False

        return True

    async def authenticate(
        self, path: str, credentials: Dict[str, Dict[str, Any]]
    ) -> AuthenticationResult:
        """
        Authenticate using configured strategy for the path.

        Processes authentication credentials according to the path's
        requirements and selected strategy.

        Args:
            path: URL path to authenticate for
            credentials: Dictionary mapping provider names to their credentials

        Returns:
            AuthenticationResult: Result of authentication attempt

        Example:
            ```python
            # Single provider authentication
            result = await auth_manager.authenticate(
                path="/api/user/profile",
                credentials={
                    "google": {"code": "auth_code"}
                }
            )

            # Multi-provider authentication
            result = await auth_manager.authenticate(
                path="/api/admin",
                credentials={
                    "google": {"access_token": "token1"},
                    "github": {"access_token": "token2"}
                }
            )
            ```
        """
        requirement = self.get_requirement(path)
        if not requirement:
            return AuthenticationResult(
                success=False,
                provider="unknown",
                metadata={"error": "No authentication requirement found for path"},
            )

        strategy = self.strategies[requirement.strategy]
        return await strategy.authenticate(self, requirement, credentials)

    async def validate_authentication(
        self, path: str, auth_data: Dict[str, Dict[str, Any]]
    ) -> bool:
        """
        Validate existing authentication.

        Checks if existing authentication data is still valid according
        to the path's requirements.

        Args:
            path: URL path to validate authentication for
            auth_data: Dictionary mapping provider names to their auth data

        Returns:
            bool: True if authentication is valid, False otherwise

        Example:
            ```python
            is_valid = await auth_manager.validate_authentication(
                path="/api/user/profile",
                auth_data={
                    "google": {"access_token": "token"}
                }
            )
            ```
        """
        requirement = self.get_requirement(path)
        if not requirement:
            return False

        if requirement.strategy == AuthStrategy.ANY:
            for provider_name, provider_data in auth_data.items():
                if (
                    provider_name in requirement.required_providers
                    and self.providers.get(provider_name)
                    and await self.providers[provider_name].validate_authentication(
                        provider_data
                    )
                ):
                    return True
            return False

        for provider_name in requirement.required_providers:
            if (
                provider_name not in auth_data
                or not self.providers.get(provider_name)
                or not await self.providers[provider_name].validate_authentication(
                    auth_data[provider_name]
                )
            ):
                return False
        return True

    async def refresh_authentication(
        self, provider_name: str, auth_data: Dict[str, Any]
    ) -> AuthenticationResult:
        """
        Refresh authentication for a provider.

        Attempts to refresh expired authentication using refresh tokens
        or other provider-specific mechanisms.

        Args:
            provider_name: Name of the provider to refresh
            auth_data: Current authentication data including refresh tokens

        Returns:
            AuthenticationResult: Result of refresh attempt

        Raises:
            ProviderNotFoundError: If the specified provider is not registered

        Example:
            ```python
            result = await auth_manager.refresh_authentication(
                provider_name="google",
                auth_data={
                    "refresh_token": "token",
                    "access_token": "expired_token"
                }
            )
            ```
        """
        provider = self.get_provider(provider_name)
        if not provider:
            raise ProviderNotFoundError(f"Provider not found: {provider_name}")

        if not provider.supports_refresh:
            return AuthenticationResult(
                success=False,
                provider=provider_name,
                metadata={"error": "Provider does not support refresh"},
            )

        return await provider.refresh_authentication(auth_data)

    async def revoke_authentication(
        self, provider_name: str, auth_data: Dict[str, Any]
    ) -> bool:
        """
        Revoke authentication for a provider.

        Attempts to revoke or invalidate the given authentication credentials.

        Args:
            provider_name: Name of the provider to revoke authentication for
            auth_data: Current authentication data to revoke

        Returns:
            bool: True if revocation successful, False otherwise

        Raises:
            ProviderNotFoundError: If the specified provider is not registered

        Example:
            ```python
            success = await auth_manager.revoke_authentication(
                provider_name="google",
                auth_data={
                    "access_token": "token_to_revoke"
                }
            )
            ```
        """
        provider = self.get_provider(provider_name)
        if not provider:
            raise ProviderNotFoundError(f"Provider not found: {provider_name}")

        if not provider.supports_revocation:
            return False

        return await provider.revoke_authentication(auth_data)
