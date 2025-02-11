import bcrypt
from .base import PasswordHasher


class BCryptPasswordHasher(PasswordHasher):
    """Default password hasher using BCrypt."""

    def __init__(self, rounds: int = 12):
        """
        Initialize BCrypt password hasher.

        Args:
            rounds: Number of rounds for BCrypt (default: 12)
        """
        self.rounds = rounds

    def hash_password(self, password: str) -> str:
        """
        Hash a password using BCrypt.

        Args:
            password: Plain text password to hash

        Returns:
            str: BCrypt hash of the password
        """
        salt = bcrypt.gensalt(rounds=self.rounds)
        return bcrypt.hashpw(password.encode(), salt).decode()

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its BCrypt hash.

        Args:
            plain_password: Plain text password to verify
            hashed_password: BCrypt hash to verify against

        Returns:
            bool: True if password matches hash, False otherwise
        """
        try:
            return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
        except Exception:
            return False
