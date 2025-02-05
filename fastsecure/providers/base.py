from abc import ABC, abstractmethod
from typing import Dict, Any, Set

from ..core.types import AuthenticationResult


class AuthenticationProvider(ABC):
    """Base class for all authentication providers"""

    @property
    def provider_name(self) -> str:
        """Get the name of this provider"""
        return self.__class__.__name__.lower().replace("authenticationprovider", "")

    def get_required_credentials(self) -> Set[str]:
        """Get the set of required credential fields for this provider"""
        return set()

    def get_optional_credentials(self) -> Set[str]:
        """Get the set of optional credential fields for this provider"""
        return set()

    def validate_credentials(self, credentials: Dict[str, Any]) -> bool:
        """Validate that all required credentials are present"""
        required = self.get_required_credentials()
        return all(k in credentials for k in required)

    @abstractmethod
    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """Authenticate user with provided credentials"""
        pass

    @abstractmethod
    async def validate_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """Validate if the current authentication is still valid"""
        pass

    async def revoke_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """Revoke/logout the current authentication"""
        return True

    async def refresh_authentication(
        self, auth_data: Dict[str, Any]
    ) -> AuthenticationResult:
        """Refresh authentication tokens/session"""
        return AuthenticationResult(
            success=False,
            provider=self.provider_name,
            metadata={"error": "Refresh not supported"},
        )

    @property
    def supports_refresh(self) -> bool:
        """Whether this provider supports refreshing authentication"""
        return False

    @property
    def supports_revocation(self) -> bool:
        """Whether this provider supports revoking authentication"""
        return False
