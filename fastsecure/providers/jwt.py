from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Set

from jose import jwt, JWTError

from .base import AuthenticationProvider
from ..core.types import AuthenticationResult
from ..exceptions import InvalidTokenError, ExpiredTokenError


class JWTAuthenticationProvider(AuthenticationProvider):
    """JWT-based authentication provider"""

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
        token_type: str = "Bearer",
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_type = token_type
        self.access_token_expire = timedelta(
            minutes=max(0, access_token_expire_minutes)
        )
        self.refresh_token_expire = timedelta(days=max(0, refresh_token_expire_days))

    def get_required_credentials(self) -> Set[str]:
        """Get required credentials for JWT authentication"""
        return {"user_id"}

    def _create_token(
        self, data: Dict[str, Any], expires_delta: timedelta, token_type: str = "access"
    ) -> str:
        """Create a new JWT token"""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + expires_delta

        to_encode.update(
            {
                "exp": int(expire.timestamp()),
                "token_type": token_type,
                "iat": int(datetime.now(timezone.utc).timestamp()),
            }
        )

        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    def _decode_token(self, token: str) -> Dict[str, Any]:
        """Decode and validate a JWT token"""
        try:
            return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            raise ExpiredTokenError("Token has expired")
        except JWTError as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")

    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """Create new access and refresh tokens"""
        if not self.validate_credentials(credentials):
            return AuthenticationResult(
                success=False,
                provider=self.provider_name,
                metadata={"error": "Missing user_id"},
            )

        user_id = credentials["user_id"]
        scopes = credentials.get("scopes", [])

        try:
            # Create token data
            token_data = {"sub": str(user_id), "scopes": scopes}

            # Create access token
            access_token = self._create_token(
                token_data, self.access_token_expire, "access"
            )

            # Create refresh token
            refresh_token = self._create_token(
                token_data, self.refresh_token_expire, "refresh"
            )

            return AuthenticationResult(
                success=True,
                user_id=user_id,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=datetime.now(timezone.utc) + self.access_token_expire,
                provider=self.provider_name,
                metadata={"token_type": self.token_type, "scopes": set(scopes)},
            )

        except Exception as e:
            return AuthenticationResult(
                success=False, provider=self.provider_name, metadata={"error": str(e)}
            )

    async def validate_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """Validate JWT token"""
        token = auth_data.get("access_token")
        if not token:
            return False

        try:
            payload = self._decode_token(token)
            exp_time = datetime.fromtimestamp(int(payload["exp"]), timezone.utc)
            return payload.get("token_type") == "access" and exp_time > datetime.now(
                timezone.utc
            )
        except (InvalidTokenError, ExpiredTokenError):
            return False

    async def refresh_authentication(
        self, auth_data: Dict[str, Any]
    ) -> AuthenticationResult:
        """Refresh access and refresh tokens"""
        refresh_token = auth_data.get("refresh_token")
        if not refresh_token:
            return AuthenticationResult(
                success=False,
                provider=self.provider_name,
                metadata={"error": "Missing refresh token"},
            )

        try:
            # Validate refresh token
            payload = self._decode_token(refresh_token)
            if payload.get("token_type") != "refresh":
                raise InvalidTokenError("Invalid token type")

            # Check expiration explicitly
            exp_time = datetime.fromtimestamp(int(payload["exp"]), timezone.utc)
            if exp_time <= datetime.now(timezone.utc):
                raise ExpiredTokenError("Refresh token has expired")

            # Create new tokens
            return await self.authenticate(
                {"user_id": int(payload["sub"]), "scopes": payload.get("scopes", [])}
            )

        except (InvalidTokenError, ExpiredTokenError) as e:
            return AuthenticationResult(
                success=False, provider=self.provider_name, metadata={"error": str(e)}
            )

    @property
    def supports_refresh(self) -> bool:
        return True
