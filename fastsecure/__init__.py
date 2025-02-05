from .core import (
    AuthenticationManager,
    AuthStrategy,
    AuthenticationResult,
    AuthenticationRequirement,
)
from .providers import (
    AuthenticationProvider,
    JWTAuthenticationProvider,
    SessionAuthenticationProvider,
    GoogleAuthProvider,
    GitHubAuthProvider,
    MemorySessionStore,
    RedisSessionStore,
    DatabaseSessionStore,
    DBSession,
)
from .middleware import AuthenticationMiddleware
from .dependencies import requires_auth
from .exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    ProviderNotFoundError,
)

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Core
    "AuthenticationManager",
    "AuthStrategy",
    "AuthenticationResult",
    "AuthenticationRequirement",
    # Providers
    "AuthenticationProvider",
    "JWTAuthenticationProvider",
    "SessionAuthenticationProvider",
    "GoogleAuthProvider",
    "GitHubAuthProvider",
    # Storage
    "MemorySessionStore",
    "RedisSessionStore",
    "DatabaseSessionStore",
    "DBSession",
    # FastAPI Integration
    "AuthenticationMiddleware",
    "requires_auth",
    # Exceptions
    "AuthenticationError",
    "InvalidCredentialsError",
    "ProviderNotFoundError",
]
