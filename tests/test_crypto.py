"""
Tests for utils.crypto — AES-256-GCM encrypt/decrypt round-trip.
"""
import os
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.crypto import encrypt_payload, decrypt_payload, is_encryption_available, SALT_SIZE, NONCE_SIZE

@pytest.mark.skipif(not is_encryption_available(), reason="cryptography not installed")
class TestCryptoRoundTrip:
    def test_encrypt_decrypt(self):
        data = b"Hello, Shadow Guardian!"
        encrypted = encrypt_payload(data, "pass123")
        assert decrypt_payload(encrypted, "pass123") == data

    def test_wrong_passphrase(self):
        encrypted = encrypt_payload(b"Secret", "correct")
        with pytest.raises(Exception):
            decrypt_payload(encrypted, "wrong")

    def test_empty_passphrase_raises(self):
        with pytest.raises(ValueError):
            encrypt_payload(b"data", "")

    def test_empty_data(self):
        enc = encrypt_payload(b"", "pass")
        assert decrypt_payload(enc, "pass") == b""

    def test_unique_ciphertexts(self):
        enc1 = encrypt_payload(b"same", "pass")
        enc2 = encrypt_payload(b"same", "pass")
        assert enc1 != enc2

    def test_truncated_fails(self):
        enc = encrypt_payload(b"test", "pass")
        with pytest.raises(Exception):
            decrypt_payload(enc[:10], "pass")

class TestCryptoAvailability:
    def test_returns_bool(self):
        assert isinstance(is_encryption_available(), bool)
