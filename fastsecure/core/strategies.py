from abc import ABC, abstractmethod
from typing import Dict, Any

from .types import AuthenticationResult, AuthenticationRequirement
from ..exceptions import AuthenticationError


class AuthenticationStrategy(ABC):
    """
    Base class for implementing authentication strategies.

    This abstract class defines the interface for authentication strategies
    that determine how multiple authentication providers are combined and
    validated. Strategies implement different rules for what constitutes
    successful authentication (e.g., any provider succeeds vs. all must succeed).

    Example:
        Creating a custom strategy:
        ```python
        class CustomStrategy(AuthenticationStrategy):
            async def authenticate(
                self,
                auth_manager: AuthenticationManager,
                requirement: AuthenticationRequirement,
                credentials: Dict[str, Dict[str, Any]]
            ) -> AuthenticationResult:
                # Custom authentication logic
                pass
        ```
    """

    @abstractmethod
    async def authenticate(
        self,
        auth_manager: Any,
        requirement: AuthenticationRequirement,
        credentials: Dict[str, Dict[str, Any]],
    ) -> AuthenticationResult:
        """
        Authenticate using the strategy's rules.

        Args:
            auth_manager: The authentication manager instance
            requirement: Authentication requirements to validate against
            credentials: Dictionary mapping provider names to their credentials

        Returns:
            AuthenticationResult: Result of the authentication attempt
        """
        pass


class AnyAuthStrategy(AuthenticationStrategy):
    """
    Authentication strategy where any required provider can succeed.

    This strategy implements an "OR" logic - authentication is considered
    successful if any of the required providers authenticates successfully.
    It will try each provider in turn until one succeeds or all fail.

    The strategy also validates:
    - At least one required provider has credentials
    - Access tokens are still valid if provided
    - Required scopes are present in the authentication result

    Example:
        Usage with AuthenticationManager:
        ```python
        auth_manager = AuthenticationManager()
        auth_manager.strategies[AuthStrategy.ANY] = AnyAuthStrategy()

        # Configure a requirement using ANY strategy
        auth_manager.add_requirement(
            path="/api/user/*",
            providers=["google", "github"],
            strategy=AuthStrategy.ANY
        )

        # Authentication succeeds if either provider works
        result = await auth_manager.authenticate(
            path="/api/user/profile",
            credentials={
                "google": {"code": "auth_code"},
                "github": {"access_token": "token"}
            }
        )
        ```
    """

    async def authenticate(
        self,
        auth_manager: Any,
        requirement: AuthenticationRequirement,
        credentials: Dict[str, Dict[str, Any]],
    ) -> AuthenticationResult:
        """
        Authenticate using any of the provided credentials.

        Attempts authentication with each provider's credentials until one
        succeeds or all fail. For each provider, it will:
        1. Validate any existing access tokens
        2. Attempt new authentication if needed
        3. Verify required scopes are present

        Args:
            auth_manager: The authentication manager instance
            requirement: Authentication requirements to validate against
            credentials: Dictionary mapping provider names to their credentials

        Returns:
            AuthenticationResult: Success if any provider authenticates,
            failure with error details otherwise

        Example:
            ```python
            strategy = AnyAuthStrategy()
            result = await strategy.authenticate(
                auth_manager,
                requirement,
                {
                    "google": {"code": "auth_code"},
                    "github": {"access_token": "token"}
                }
            )
            if result.success:
                print(f"Authenticated with {result.provider}")
            else:
                print(f"Errors: {result.metadata['errors']}")
            ```
        """

        errors = []

        has_required = False
        for provider_name in requirement.required_providers:
            if provider_name in credentials:
                has_required = True
                break

        if not has_required and requirement.required_providers:
            errors = [
                f"Missing credentials for required provider: {p}"
                for p in requirement.required_providers
            ]
            return AuthenticationResult(
                success=False, provider="any", metadata={"errors": errors}
            )

        for provider_name, auth_data in credentials.items():
            try:
                provider = auth_manager.get_provider(provider_name)
                if not provider:
                    continue

                if "access_token" in auth_data:
                    try:
                        if not await provider.validate_authentication(auth_data):
                            errors.append(
                                f"Token expired or invalid for {provider_name}"
                            )
                            continue
                        return AuthenticationResult(
                            success=True, provider=provider_name
                        )
                    except Exception as e:
                        errors.append(f"{str(e)}")
                        continue

                result = await provider.authenticate(auth_data)
                if result.success and (
                    not requirement.scopes
                    or result.metadata.get("scopes", set()).issuperset(
                        requirement.scopes
                    )
                ):
                    return result

                errors.append(
                    f"Authentication failed for {provider_name}: {result.metadata.get('error', 'Unknown error')}"
                )

            except Exception as e:
                errors.append(str(e))

        return AuthenticationResult(
            success=False, provider="any", metadata={"errors": errors}
        )


class AllAuthStrategy(AuthenticationStrategy):
    """
    Authentication strategy requiring all required providers to succeed.

    This strategy implements an "AND" logic - authentication is only
    considered successful if all required providers authenticate successfully.
    It will attempt authentication with all providers and collect the results.

    The strategy also:
    - Verifies credentials exist for all required providers
    - Validates all required scopes are present
    - Combines metadata from all successful authentications
    - Returns detailed errors for any failures

    Example:
        Usage with AuthenticationManager:
        ```python
        auth_manager = AuthenticationManager()
        auth_manager.strategies[AuthStrategy.ALL] = AllAuthStrategy()

        # Configure a requirement using ALL strategy
        auth_manager.add_requirement(
            path="/api/admin/*",
            providers=["google", "github"],
            strategy=AuthStrategy.ALL
        )

        # Both providers must succeed
        result = await auth_manager.authenticate(
            path="/api/admin/users",
            credentials={
                "google": {"access_token": "token1"},
                "github": {"access_token": "token2"}
            }
        )
        ```
    """

    async def authenticate(
        self,
        auth_manager: Any,
        requirement: AuthenticationRequirement,
        credentials: Dict[str, Dict[str, Any]],
    ) -> AuthenticationResult:
        """
        Authenticate with all required providers.

        Attempts authentication with all providers and requires all
        required providers to succeed. For each provider:
        1. Verifies credentials are present
        2. Attempts authentication
        3. Validates required scopes
        4. Combines successful results

        Args:
            auth_manager: The authentication manager instance
            requirement: Authentication requirements to validate against
            credentials: Dictionary mapping provider names to their credentials

        Returns:
            AuthenticationResult: Success if all required providers authenticate,
            failure with error details otherwise

        Example:
            ```python
            strategy = AllAuthStrategy()
            result = await strategy.authenticate(
                auth_manager,
                requirement,
                {
                    "google": {"access_token": "token1"},
                    "github": {"access_token": "token2"}
                }
            )
            if result.success:
                # Access combined metadata
                google_data = result.metadata["google"]
                github_data = result.metadata["github"]
            else:
                print(f"Errors: {result.metadata['errors']}")
            ```
        """
        errors = []
        successful_results = []

        for provider_name in requirement.all_providers:
            if provider_name not in credentials:
                if provider_name in requirement.required_providers:
                    errors.append(
                        f"Missing credentials for required provider: {provider_name}"
                    )
                continue

            try:
                provider = auth_manager.get_provider(provider_name)
                if not provider:
                    raise AuthenticationError(f"Provider not found: {provider_name}")

                result = await provider.authenticate(credentials[provider_name])
                if result.success:
                    if requirement.scopes and not result.metadata.get(
                        "scopes", set()
                    ).issuperset(requirement.scopes):
                        errors.append(f"Missing required scopes for {provider_name}")
                        continue
                    successful_results.append(result)

                elif provider_name in requirement.required_providers:
                    errors.append(
                        f"Authentication failed for {provider_name}: {result.metadata.get('error', 'Unknown error')}"
                    )

            except Exception as e:
                errors.append(f"Error with {provider_name}: {str(e)}")

        required_succeeded = all(
            any(r.provider == p for r in successful_results)
            for p in requirement.required_providers
        )

        if required_succeeded and successful_results:
            combined_metadata = {}
            for result in successful_results:
                combined_metadata[result.provider] = result.metadata

            base_result = successful_results[0]
            return AuthenticationResult(
                success=True,
                user_id=base_result.user_id,
                access_token=base_result.access_token,
                refresh_token=base_result.refresh_token,
                session_id=base_result.session_id,
                expires_at=base_result.expires_at,
                provider="all",
                metadata=combined_metadata,
            )

        return AuthenticationResult(
            success=False, provider="all", metadata={"errors": errors}
        )
