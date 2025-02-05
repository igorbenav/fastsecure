from typing import Dict, Any, Optional, Callable
from functools import partial

from fastapi import Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from ..core.types import AuthenticationResult
from ..exceptions import AuthenticationError

security = HTTPBearer()


async def get_auth_credentials(
    request: Request, token: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Dict[str, Dict[str, Any]]:
    """Extract authentication credentials from request"""
    credentials = {}

    if token:
        credentials["jwt"] = {"access_token": token.credentials}

    if session_id := request.cookies.get("session_id"):
        credentials["session"] = {"session_id": session_id}

    for provider in ["google", "github"]:
        if token := request.cookies.get(f"{provider}_token"):
            credentials[provider] = {"access_token": token}

    return credentials


async def requires_auth(
    request: Request,
    path: str,
    auth_manager: "AuthenticationManager",
    credentials: Dict[str, Dict[str, Any]] = Depends(get_auth_credentials),
) -> AuthenticationResult:
    """Dependency for requiring authentication"""
    result = await auth_manager.authenticate(path, credentials)
    if not result.success:
        raise AuthenticationError(
            message="Authentication failed",
            provider=result.provider,
            errors=result.metadata.get("errors", []),
        )
    return result


def create_auth_dependency(
    path: str, auth_manager: "AuthenticationManager"
) -> Callable:
    """Create a dependency for a specific path"""
    return partial(requires_auth, path=path, auth_manager=auth_manager)
