# tests/test_password.py
import pytest
from fastsecure import BCryptPasswordHasher, AuthenticationManager
from fastsecure.password import PasswordHasher


class MockPasswordHasher:
    """Mock password hasher for testing custom implementations"""

    def __init__(self, prefix: str = "mock_"):
        self.prefix = prefix
        self.last_verified = None

    def hash_password(self, password: str) -> str:
        return f"{self.prefix}{password}"

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        self.last_verified = plain_password
        return hashed_password == f"{self.prefix}{plain_password}"


@pytest.fixture
def mock_hasher():
    return MockPasswordHasher()


# BCryptPasswordHasher Tests
def test_bcrypt_hasher_initialization():
    """Test BCrypt hasher initialization with different rounds"""
    hasher = BCryptPasswordHasher(rounds=8)
    assert hasher.rounds == 8


def test_bcrypt_password_hash_different():
    """Test that same password produces different hashes"""
    hasher = BCryptPasswordHasher()
    password = "test_password"
    hash1 = hasher.hash_password(password)
    hash2 = hasher.hash_password(password)
    assert hash1 != hash2  # Different salts should produce different hashes


def test_bcrypt_verify_correct_password():
    """Test password verification with correct password"""
    hasher = BCryptPasswordHasher()
    password = "test_password"
    hashed = hasher.hash_password(password)
    assert hasher.verify_password(password, hashed)


def test_bcrypt_verify_incorrect_password():
    """Test password verification with incorrect password"""
    hasher = BCryptPasswordHasher()
    password = "test_password"
    wrong_password = "wrong_password"
    hashed = hasher.hash_password(password)
    assert not hasher.verify_password(wrong_password, hashed)


def test_bcrypt_verify_invalid_hash():
    """Test password verification with invalid hash format"""
    hasher = BCryptPasswordHasher()
    assert not hasher.verify_password("test_password", "invalid_hash")


# AuthenticationManager Password Tests
def test_auth_manager_default_hasher():
    """Test AuthenticationManager uses BCryptPasswordHasher by default"""
    manager = AuthenticationManager()
    password = "test_password"
    hashed = manager.hash_password(password)
    assert manager.verify_password(password, hashed)


def test_auth_manager_custom_hasher(mock_hasher):
    """Test AuthenticationManager with custom password hasher"""
    manager = AuthenticationManager(password_hasher=mock_hasher)
    password = "test_password"
    hashed = manager.hash_password(password)
    assert hashed == f"{mock_hasher.prefix}{password}"
    assert manager.verify_password(password, hashed)


def test_auth_manager_change_hasher(mock_hasher):
    """Test changing password hasher after initialization"""
    manager = AuthenticationManager()

    # Hash with default hasher
    password = "test_password"
    default_hash = manager.hash_password(password)
    assert manager.verify_password(password, default_hash)

    # Change to mock hasher
    manager.set_password_hasher(mock_hasher)
    mock_hash = manager.hash_password(password)
    assert mock_hash == f"{mock_hasher.prefix}{password}"
    assert manager.verify_password(password, mock_hash)


def test_auth_manager_password_validation():
    """Test password validation with AuthenticationManager"""
    manager = AuthenticationManager()
    password = "test_password"
    wrong_password = "wrong_password"
    hashed = manager.hash_password(password)

    assert manager.verify_password(password, hashed)
    assert not manager.verify_password(wrong_password, hashed)


def test_hasher_protocol_compliance(mock_hasher):
    """Test that custom hasher complies with PasswordHasher protocol"""

    def check_hasher(hasher: PasswordHasher):
        """Verify hasher implements required methods"""
        password = "test_password"
        hashed = hasher.hash_password(password)
        assert isinstance(hashed, str)
        assert isinstance(hasher.verify_password(password, hashed), bool)

    # Should not raise type errors
    check_hasher(mock_hasher)
    check_hasher(BCryptPasswordHasher())


def test_password_unicode_support():
    """Test password hashing with Unicode characters"""
    manager = AuthenticationManager()
    password = "пароль123"  # Russian + numbers
    hashed = manager.hash_password(password)
    assert manager.verify_password(password, hashed)

    password = "パスワード"  # Japanese
    hashed = manager.hash_password(password)
    assert manager.verify_password(password, hashed)


def test_password_special_characters():
    """Test password hashing with special characters"""
    manager = AuthenticationManager()
    password = "pass!@#$%^&*()"
    hashed = manager.hash_password(password)
    assert manager.verify_password(password, hashed)


def test_empty_password_handling():
    """Test handling of empty passwords"""
    manager = AuthenticationManager()
    password = ""
    hashed = manager.hash_password(password)
    assert manager.verify_password(password, hashed)
    assert not manager.verify_password("not_empty", hashed)


def test_bcrypt_72_byte_limit():
    """Test bcrypt's 72-byte password length limit"""
    manager = AuthenticationManager()

    # Create a password exactly 72 bytes long
    password_72 = "x" * 72
    hashed = manager.hash_password(password_72)

    # Same password should verify
    assert manager.verify_password(password_72, hashed)

    # Password longer than 72 bytes should still work due to truncation
    password_100 = "x" * 100
    assert manager.verify_password(password_100, hashed)

    # But different password of same length should not work
    different_password = ("x" * 71) + "y"
    assert not manager.verify_password(different_password, hashed)


def test_password_length_warning():
    """Test that very long passwords still work but maintain security"""
    manager = AuthenticationManager()

    # Test with a reasonably long password
    password = "x" * 50
    hashed = manager.hash_password(password)

    # Same password should verify
    assert manager.verify_password(password, hashed)

    # Different password should not verify, even if only last character is different
    wrong_password = ("x" * 49) + "y"
    assert not manager.verify_password(wrong_password, hashed)

    # Test with password longer than bcrypt's limit
    long_password = "x" * 100
    hashed = manager.hash_password(long_password)

    # Same long password should verify
    assert manager.verify_password(long_password, hashed)

    # Different long password should not verify if differs within first 72 bytes
    wrong_long = ("x" * 50) + "y" + ("x" * 49)
    assert not manager.verify_password(wrong_long, hashed)
