from typing import Any, Dict, List, Optional


class AuthenticationError(Exception):
    """Base authentication error"""

    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        errors: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.provider = provider
        self.errors = errors or []
        self.details = details or {}
        super().__init__(message)


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid"""

    pass


class ProviderNotFoundError(AuthenticationError):
    """Raised when authentication provider is not found"""

    pass


class AuthenticationRequiredError(AuthenticationError):
    """Raised when authentication is required but not provided"""

    pass


class MultipleAuthenticationError(AuthenticationError):
    """Raised when multiple authentication methods fail"""

    pass


class TokenError(AuthenticationError):
    """Base class for token-related errors"""

    pass


class InvalidTokenError(TokenError):
    """Raised when token is invalid"""

    pass


class ExpiredTokenError(TokenError):
    """Raised when token has expired"""

    pass


class RevokedTokenError(TokenError):
    """Raised when token has been revoked"""

    pass
