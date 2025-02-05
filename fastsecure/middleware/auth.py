from typing import Callable, Optional, List
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..core.manager import AuthenticationManager
from ..dependencies.auth import get_auth_credentials
from ..exceptions import AuthenticationError


class AuthenticationMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        auth_manager: AuthenticationManager,
        exclude_paths: Optional[List[str]] = None,
        error_handlers: Optional[dict[type[Exception], Callable]] = None,
        default_error_handler: Optional[Callable] = None,
    ):
        super().__init__(app)
        self.auth_manager = auth_manager
        self.exclude_paths = exclude_paths or []
        self.error_handlers = error_handlers or {}
        self.default_error_handler = (
            default_error_handler or self._default_error_handler
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)

        try:
            requirement = self.auth_manager.get_requirement(request.url.path)
            if not requirement:
                return await call_next(request)

            credentials = await get_auth_credentials(request)

            result = await self.auth_manager.authenticate(request.url.path, credentials)
            if not result.success:
                raise AuthenticationError(
                    message="Authentication failed",
                    provider=result.provider,
                    errors=result.metadata.get("errors", []),
                )

            request.state.auth = result

            return await call_next(request)

        except Exception as e:
            handler = self.error_handlers.get(type(e)) or self.default_error_handler
            return await handler(request, e)

    async def _default_error_handler(
        self, request: Request, exc: Exception
    ) -> JSONResponse:
        """Default error handler for authentication errors"""
        if isinstance(exc, AuthenticationError):
            return JSONResponse(
                status_code=401,
                content={
                    "detail": exc.message,
                    "provider": exc.provider,
                    "errors": exc.errors,
                },
            )

        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "type": str(type(exc).__name__),
            },
        )
