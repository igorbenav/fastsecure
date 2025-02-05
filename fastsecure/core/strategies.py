from abc import ABC, abstractmethod
from typing import Dict, Any

from .types import AuthenticationResult, AuthenticationRequirement
from ..exceptions import AuthenticationError


class AuthenticationStrategy(ABC):
    """Base class for authentication strategies"""

    @abstractmethod
    async def authenticate(
        self,
        auth_manager: "AuthenticationManager",
        requirement: AuthenticationRequirement,
        credentials: Dict[str, Dict[str, Any]],
    ) -> AuthenticationResult:
        pass


class AnyAuthStrategy(AuthenticationStrategy):
    """Strategy where any one provider must succeed"""

    async def authenticate(
        self,
        auth_manager: "AuthenticationManager",
        requirement: AuthenticationRequirement,
        credentials: Dict[str, Dict[str, Any]],
    ) -> AuthenticationResult:
        errors = []

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
                    return result

                elif provider_name in requirement.required_providers:
                    errors.append(
                        f"Authentication failed for {provider_name}: {result.metadata.get('error', 'Unknown error')}"
                    )

            except Exception as e:
                errors.append(f"Error with {provider_name}: {str(e)}")

        return AuthenticationResult(
            success=False, provider="any", metadata={"errors": errors}
        )


class AllAuthStrategy(AuthenticationStrategy):
    """Strategy where all required providers must succeed"""

    async def authenticate(
        self,
        auth_manager: "AuthenticationManager",
        requirement: AuthenticationRequirement,
        credentials: Dict[str, Dict[str, Any]],
    ) -> AuthenticationResult:
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
