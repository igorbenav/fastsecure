from typing import Dict, Any, Optional, List
from urllib.parse import urlparse

from .types import AuthStrategy, AuthenticationResult, AuthenticationRequirement
from .strategies import AuthenticationStrategy, AnyAuthStrategy, AllAuthStrategy
from ..providers.base import AuthenticationProvider
from ..exceptions import ProviderNotFoundError


class AuthenticationManager:
    """Manages authentication providers and strategies"""

    def __init__(self):
        self.providers: Dict[str, AuthenticationProvider] = {}
        self.strategies: Dict[AuthStrategy, AuthenticationStrategy] = {
            AuthStrategy.ANY: AnyAuthStrategy(),
            AuthStrategy.ALL: AllAuthStrategy(),
        }
        self._requirements: Dict[str, AuthenticationRequirement] = {}

    def register_provider(self, name: str, provider: AuthenticationProvider) -> None:
        """Register a new authentication provider"""
        self.providers[name] = provider

    def get_provider(self, name: str) -> Optional[AuthenticationProvider]:
        """Get a registered provider by name"""
        return self.providers.get(name)

    def get_available_providers(self) -> List[str]:
        """Get list of registered provider names"""
        return list(self.providers.keys())

    def add_requirement(
        self,
        path: str,
        providers: List[str],
        strategy: AuthStrategy = AuthStrategy.ANY,
        optional_providers: Optional[List[str]] = None,
        scopes: Optional[List[str]] = None,
    ) -> None:
        """Add authentication requirement for a path"""
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
        """Get authentication requirement for a path"""
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
        """Match a path against a pattern with wildcards"""
        if len(path_parts) != len(pattern_parts):
            return False

        for path_part, pattern_part in zip(path_parts, pattern_parts):
            if pattern_part != "*" and path_part != pattern_part:
                return False

        return True

    async def authenticate(
        self, path: str, credentials: Dict[str, Dict[str, Any]]
    ) -> AuthenticationResult:
        """Authenticate using configured strategy for the path"""
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
        """Validate existing authentication"""
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
        """Refresh authentication for a provider"""
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
        """Revoke authentication for a provider"""
        provider = self.get_provider(provider_name)
        if not provider:
            raise ProviderNotFoundError(f"Provider not found: {provider_name}")

        if not provider.supports_revocation:
            return False

        return await provider.revoke_authentication(auth_data)
