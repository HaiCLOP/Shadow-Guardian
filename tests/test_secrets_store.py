"""
Tests for utils.secrets_store — DPAPI / obfuscation round-trip.
"""
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.secrets_store import (
    encrypt_secret, decrypt_secret, is_encrypted,
    is_secret_key, has_dpapi, SECRET_KEYS,
)

class TestSecretsRoundTrip:
    def test_encrypt_decrypt(self):
        original = "my_supabase_key_12345"
        encrypted = encrypt_secret(original)
        assert encrypted != original
        assert is_encrypted(encrypted)
        assert decrypt_secret(encrypted) == original

    def test_empty_string(self):
        assert encrypt_secret("") == ""
        assert decrypt_secret("") == ""

    def test_unicode(self):
        original = "pässwörd_🔑"
        encrypted = encrypt_secret(original)
        assert decrypt_secret(encrypted) == original

    def test_long_value(self):
        original = "x" * 10000
        encrypted = encrypt_secret(original)
        assert decrypt_secret(encrypted) == original

class TestSecretsDetection:
    def test_is_secret_key(self):
        assert is_secret_key("supabase_key") is True
        assert is_secret_key("supabase_url") is True
        assert is_secret_key("encryption_passphrase") is True
        assert is_secret_key("log_level") is False

    def test_is_encrypted_prefix(self):
        assert is_encrypted("dpapi:abc123") is True
        assert is_encrypted("obfs:abc123") is True
        assert is_encrypted("plaintext") is False

    def test_legacy_plaintext_passthrough(self):
        """Unencrypted values should be returned as-is for migration."""
        assert decrypt_secret("legacy_plain_value") == "legacy_plain_value"

class TestDPAPIAvailability:
    def test_has_dpapi_returns_bool(self):
        assert isinstance(has_dpapi(), bool)

    def test_secret_keys_frozen(self):
        assert isinstance(SECRET_KEYS, frozenset)
