from datetime import datetime, timedelta, timezone
from enum import Enum
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError
from typing import Optional, Set, Callable, Dict, Any
from pydantic import BaseModel, Field, model_validator

from .base import AuthenticationProvider
from ..core.types import AuthenticationResult
from ..exceptions import InvalidTokenError, ExpiredTokenError


class SubjectType(str, Enum):
    """
    Defines the type of subject claim to be used in JWT tokens.

    This enum specifies how the subject identifier in the JWT token
    should be determined from the credentials.

    Attributes:
        USER_ID: Use the user's ID as the subject
        USERNAME: Use the username as the subject
        EMAIL: Use the email address as the subject
        CUSTOM: Use a custom function to determine the subject
    """

    USER_ID = "user_id"
    USERNAME = "username"
    EMAIL = "email"
    CUSTOM = "custom"


class JWTConfig(BaseModel):
    """
    Configuration model for JWT authentication settings.

    This model defines all the settings needed to customize JWT token
    generation, validation, and handling. It provides flexibility in
    configuring token claims, expiration, and validation rules.

    Attributes:
        secret_key: The key used for signing JWT tokens
        subject_type: How to determine the token subject (default: USER_ID)
        access_token_expire_minutes: Lifetime of access tokens in minutes (default: 30)
        refresh_token_expire_days: Lifetime of refresh tokens in days (default: 7)
        algorithm: JWT signing algorithm (default: "HS256")
        token_type: Type of bearer token (default: "Bearer")
        subject_claim: Name of the subject claim in the token (default: "sub")
        custom_subject_getter: Optional function to generate custom subjects
        additional_claims: Set of extra claims to include from credentials
        include_issued_at: Whether to include iat claim (default: True)
        include_token_type: Whether to include token_type claim (default: True)
        verify_token_type: Whether to verify token_type during validation (default: True)
        verify_expires: Whether to verify token expiration (default: True)

    Example:
        ```python
        config = JWTConfig(
            secret_key="your-secret-key",
            subject_type=SubjectType.EMAIL,
            access_token_expire_minutes=60,
            additional_claims={"role", "permissions"}
        )
        ```
    """

    secret_key: str
    subject_type: SubjectType = SubjectType.USER_ID

    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    algorithm: str = "HS256"
    token_type: str = "Bearer"

    subject_claim: str = "sub"
    custom_subject_getter: Optional[Callable[[Dict[str, Any]], str]] = None

    additional_claims: Set[str] = Field(default_factory=set)
    include_issued_at: bool = True
    include_token_type: bool = True

    verify_token_type: bool = True
    verify_expires: bool = True

    @model_validator(mode="after")
    def validate_custom_subject(self) -> "JWTConfig":
        if (
            self.subject_type == SubjectType.CUSTOM
            and self.custom_subject_getter is None
        ):
            raise ValueError(
                "custom_subject_getter must be provided when subject_type is CUSTOM"
            )
        return self

    def get_required_credentials(self) -> Set[str]:
        """Get required credentials based on subject type"""
        if self.subject_type == SubjectType.USER_ID:
            return {"user_id"}
        elif self.subject_type == SubjectType.USERNAME:
            return {"username"}
        elif self.subject_type == SubjectType.EMAIL:
            return {"email"}
        else:
            return set()

    def get_subject_from_credentials(self, credentials: Dict[str, Any]) -> str:
        """Extract subject from credentials based on configuration"""
        if self.subject_type == SubjectType.CUSTOM:
            if not self.custom_subject_getter:
                raise ValueError("custom_subject_getter not configured")
            return self.custom_subject_getter(credentials)

        subject_map = {
            SubjectType.USER_ID: lambda c: str(c["user_id"]),
            SubjectType.USERNAME: lambda c: c["username"],
            SubjectType.EMAIL: lambda c: c["email"],
        }

        subject_credentials: str = subject_map[self.subject_type](credentials)
        return subject_credentials

    def get_additional_claims(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Extract configured additional claims from credentials"""
        return {
            claim: credentials[claim]
            for claim in self.additional_claims
            if claim in credentials
        }


class JWTAuthenticationProvider(AuthenticationProvider):
    """
    Authentication provider implementing JWT (JSON Web Token) based authentication.

    This provider handles JWT token generation, validation, and refresh operations.
    It supports flexible configuration of token claims, expiration times, and
    validation rules through JWTConfig.

    Attributes:
        config: The JWT configuration settings
        supports_refresh: Always True as JWT provider supports token refresh

    Example:
        Basic initialization:
        ```python
        provider = JWTAuthenticationProvider(secret_key="your-secret-key")
        ```

        Advanced configuration:
        ```python
        config = JWTConfig(
            secret_key="your-secret-key",
            subject_type=SubjectType.EMAIL,
            access_token_expire_minutes=60,
            additional_claims={"role"}
        )
        provider = JWTAuthenticationProvider(config=config)
        ```

        Usage with AuthenticationManager:
        ```python
        auth_manager = AuthenticationManager()
        auth_manager.register_provider("jwt", JWTAuthenticationProvider(
            secret_key="your-secret-key"
        ))
        ```
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
        token_type: str = "Bearer",
        config: Optional[JWTConfig] = None,
    ):
        """
        Initialize the JWT authentication provider.

        Args:
            secret_key: Key for signing tokens (required if config not provided)
            algorithm: JWT signing algorithm (default: "HS256")
            access_token_expire_minutes: Access token lifetime (default: 30)
            refresh_token_expire_days: Refresh token lifetime (default: 7)
            token_type: Bearer token type (default: "Bearer")
            config: Optional complete JWT configuration

        Raises:
            ValueError: If neither secret_key nor config is provided
        """
        if config is not None:
            self.config = config
        else:
            if secret_key is None:
                raise ValueError("Either config or secret_key must be provided")
            self.config = JWTConfig(
                secret_key=secret_key,
                algorithm=algorithm,
                access_token_expire_minutes=access_token_expire_minutes,
                refresh_token_expire_days=refresh_token_expire_days,
                token_type=token_type,
            )
        self._validate_config()

    def _validate_config(self) -> None:
        """
        Perform additional validation of the JWT configuration.

        Validates that the custom_subject_getter is callable when using
        custom subject type.

        Raises:
            ValueError: If custom_subject_getter is configured but not callable
        """
        if self.config.subject_type == SubjectType.CUSTOM:
            if not callable(self.config.custom_subject_getter):
                raise ValueError("custom_subject_getter must be callable")

    @property
    def secret_key(self) -> str:
        """
        Get the secret key used for signing tokens.

        Returns:
            str: The configured secret key
        """
        return self.config.secret_key

    @property
    def algorithm(self) -> str:
        """
        Get the JWT signing algorithm.

        Returns:
            str: The configured signing algorithm (e.g., "HS256")
        """
        return self.config.algorithm

    def get_required_credentials(self) -> Set[str]:
        """
        Get all required credential fields for JWT authentication.

        Combines the required credentials based on subject_type with any
        configured additional claims.

        Returns:
            Set[str]: Set of required credential field names
        """
        required = self.config.get_required_credentials()
        required.update(self.config.additional_claims)
        return required

    def _create_token(
        self,
        credentials: Dict[str, Any],
        expires_delta: timedelta,
        token_type: str = "access",
    ) -> str:
        """
        Create a new JWT token with the provided credentials and configuration.

        Args:
            credentials: Dictionary containing required credentials and claims
            expires_delta: Token lifetime as a timedelta
            token_type: Type of token to create ("access" or "refresh")

        Returns:
            str: The encoded JWT token

        Note:
            The generated token will include:
            - Subject claim (based on subject_type)
            - Additional configured claims
            - Issued at timestamp (if configured)
            - Token type (if configured)
            - Expiration time (if configured)
            - Scopes (if provided in credentials)
        """
        to_encode = {}

        to_encode[self.config.subject_claim] = self.config.get_subject_from_credentials(
            credentials
        )
        to_encode.update(self.config.get_additional_claims(credentials))

        if self.config.include_issued_at:
            to_encode["iat"] = str(int(datetime.now(timezone.utc).timestamp()))

        if self.config.include_token_type:
            to_encode["token_type"] = token_type

        if self.config.verify_expires:
            if expires_delta.total_seconds() <= 0:
                expire = datetime.now(timezone.utc)
            else:
                expire = datetime.now(timezone.utc) + expires_delta
            to_encode["exp"] = str(int(expire.timestamp()))

        if "scopes" in credentials:
            to_encode["scopes"] = credentials["scopes"]

        return jwt.encode(
            to_encode, self.config.secret_key, algorithm=self.config.algorithm
        )

    def _decode_token(self, token: str) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.

        Performs comprehensive token validation including:
        - Signature verification
        - Token type validation (if configured)
        - Expiration check (if configured)

        Args:
            token: The JWT token to decode and validate

        Returns:
            Dict[str, Any]: The decoded token payload

        Raises:
            ExpiredTokenError: If the token has expired
            InvalidTokenError: If the token is invalid or fails validation
        """
        try:
            payload = jwt.decode(
                token, self.config.secret_key, algorithms=[self.config.algorithm]
            )

            if (
                self.config.verify_token_type
                and self.config.include_token_type
                and payload.get("token_type") != "access"
            ):
                raise InvalidTokenError("Invalid token type")

            if self.config.verify_expires:
                exp = payload.get("exp")
                if not exp:
                    raise InvalidTokenError("Token has no expiration")

                exp_time = datetime.fromtimestamp(int(exp), timezone.utc)
                if exp_time <= datetime.now(timezone.utc):
                    raise ExpiredTokenError("Token has expired")

            return payload

        except ExpiredSignatureError:
            raise ExpiredTokenError("Token has expired")
        except JWTError as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}")

    async def authenticate(self, credentials: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate using JWT by validating credentials and generating tokens.

        Creates both access and refresh tokens if credentials are valid.
        The access token is used for authentication and the refresh token
        can be used to obtain new access tokens.

        Args:
            credentials: Dictionary containing required credentials and optional claims

        Returns:
            AuthenticationResult: Authentication result containing:
                - access_token: The generated access token
                - refresh_token: The generated refresh token
                - expires_at: Access token expiration time
                - metadata: Including token_type, scopes, and additional claims

        Example:
            ```python
            result = await provider.authenticate({
                "user_id": 123,
                "scopes": ["read", "write"],
                "role": "admin"
            })
            ```
        """
        if not self.validate_credentials(credentials):
            missing = self.get_required_credentials() - credentials.keys()
            error_msg = (
                "Missing user_id"
                if "user_id" in missing
                else f"Missing required credentials: {missing}"
            )
            return AuthenticationResult(
                success=False,
                provider=self.provider_name,
                metadata={"error": error_msg},
            )

        try:
            access_token = self._create_token(
                credentials,
                timedelta(minutes=self.config.access_token_expire_minutes),
                "access",
            )

            refresh_token = self._create_token(
                credentials,
                timedelta(days=self.config.refresh_token_expire_days),
                "refresh",
            )

            metadata = {
                "token_type": self.config.token_type,
                "scopes": set(credentials.get("scopes", [])),
                "additional_claims": self.config.get_additional_claims(credentials),
            }
            if "metadata" in credentials:
                metadata.update(credentials["metadata"])

            return AuthenticationResult(
                success=True,
                user_id=credentials.get("user_id"),
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=datetime.now(timezone.utc)
                + timedelta(minutes=self.config.access_token_expire_minutes),
                provider=self.provider_name,
                metadata=metadata,
            )

        except Exception as e:
            return AuthenticationResult(
                success=False, provider=self.provider_name, metadata={"error": str(e)}
            )

    async def validate_authentication(self, auth_data: Dict[str, Any]) -> bool:
        """
        Validate an existing JWT authentication.

        Attempts to decode and validate the access token from the auth data.
        A successful validation means the token is properly signed and
        not expired.

        Args:
            auth_data: Dictionary containing the access token

        Returns:
            bool: True if the token is valid, False otherwise
        """
        token = auth_data.get("access_token")
        if not token:
            return False

        try:
            self._decode_token(token)
            return True
        except (ExpiredTokenError, InvalidTokenError, JWTError):
            return False

    async def refresh_authentication(
        self, auth_data: Dict[str, Any]
    ) -> AuthenticationResult:
        """
        Refresh an authentication by using a refresh token.

        Uses the provided refresh token to generate a new access token
        without requiring full re-authentication. The refresh token must
        be valid and not expired.

        Args:
            auth_data: Dictionary containing the refresh token

        Returns:
            AuthenticationResult: New authentication result with fresh tokens

        Raises:
            ExpiredTokenError: If the refresh token has expired
            InvalidTokenError: If the refresh token is invalid

        Example:
            ```python
            new_auth = await provider.refresh_authentication({
                "refresh_token": "previous-refresh-token"
            })
            ```
        """
        refresh_token = auth_data.get("refresh_token")
        if not refresh_token:
            return AuthenticationResult(
                success=False,
                provider=self.provider_name,
                metadata={"error": "Missing refresh token"},
            )

        try:
            try:
                payload = jwt.decode(
                    refresh_token,
                    self.config.secret_key,
                    algorithms=[self.config.algorithm],
                )
            except ExpiredSignatureError:
                raise ExpiredTokenError("Refresh token has expired")
            except JWTError as e:
                raise InvalidTokenError(f"Invalid refresh token: {str(e)}")

            if payload.get("token_type") != "refresh":
                raise InvalidTokenError("Invalid token type for refresh")

            sub = payload.get(self.config.subject_claim)
            if not sub:
                raise InvalidTokenError("Missing subject claim")

            credentials = {"user_id": int(sub), "scopes": payload.get("scopes", [])}

            for claim in self.config.additional_claims:
                if claim in payload:
                    credentials[claim] = payload[claim]

            return await self.authenticate(credentials)

        except (InvalidTokenError, ExpiredTokenError) as e:
            return AuthenticationResult(
                success=False, provider=self.provider_name, metadata={"error": str(e)}
            )

    @property
    def supports_refresh(self) -> bool:
        """
        Whether this provider supports token refresh operations.

        Returns:
            bool: Always True as JWT provider implements refresh functionality
        """
        return True
