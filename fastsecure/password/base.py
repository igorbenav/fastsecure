from typing import Protocol


class PasswordHasher(Protocol):
    """Protocol defining the interface for password hashers."""

    def hash_password(self, password: str) -> str:
        """Hash a password."""
        ...

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        ...
