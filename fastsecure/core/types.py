from datetime import datetime
from typing import Any, Dict, Optional
from enum import Enum

from pydantic import BaseModel, Field


class AuthStrategy(str, Enum):
    """Authentication strategy for combining multiple providers"""

    ANY = "any"
    ALL = "all"


class AuthenticationResult(BaseModel):
    """Result of an authentication attempt"""

    success: bool = False
    user_id: Optional[int] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    session_id: Optional[str] = None
    expires_at: Optional[datetime] = None
    provider: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuthenticationRequirement:
    """Defines authentication requirements for a route"""

    def __init__(
        self,
        providers: list[str],
        strategy: AuthStrategy = AuthStrategy.ANY,
        optional_providers: Optional[list[str]] = None,
        scopes: Optional[list[str]] = None,
    ):
        self.required_providers = set(providers)
        self.optional_providers = set(optional_providers or [])
        self.strategy = strategy
        self.scopes = set(scopes or [])

    def validate_providers(self, available_providers: set[str]) -> bool:
        """Verify if all required providers are available"""
        return self.required_providers.issubset(
            available_providers
        ) and self.optional_providers.issubset(available_providers)

    @property
    def all_providers(self) -> set[str]:
        """Get all providers (required and optional)"""
        return self.required_providers.union(self.optional_providers)
