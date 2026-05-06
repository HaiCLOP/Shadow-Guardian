"""
Shadow Guardian — Cryptography Module

AES-256-GCM encryption for cloud sync payload protection.
Uses PBKDF2 key derivation from passphrase with random salt per encryption.
"""

import os
import struct
from typing import Optional

from utils.logger import get_logger

logger = get_logger("utils.crypto")

# Try to import cryptography; graceful degradation if not installed
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography library not installed — encryption disabled")


# Constants
SALT_SIZE = 16       # 128-bit salt
NONCE_SIZE = 12      # 96-bit nonce (standard for AES-GCM)
KEY_SIZE = 32        # 256-bit key
KDF_ITERATIONS = 100_000


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from passphrase using PBKDF2-HMAC-SHA256."""
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required for encryption")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_payload(data: bytes, passphrase: str) -> bytes:
    """
    Encrypt data using AES-256-GCM.
    
    Output format: [salt:16][nonce:12][ciphertext+tag]
    
    Args:
        data: Raw bytes to encrypt
        passphrase: Encryption passphrase
        
    Returns:
        Encrypted bytes with prepended salt and nonce
    """
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required for encryption")

    if not passphrase:
        raise ValueError("Encryption passphrase cannot be empty")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    # Prepend salt + nonce to ciphertext
    return salt + nonce + ciphertext


def decrypt_payload(encrypted_data: bytes, passphrase: str) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.
    
    Expects format: [salt:16][nonce:12][ciphertext+tag]
    
    Args:
        encrypted_data: Encrypted bytes with prepended salt and nonce
        passphrase: Encryption passphrase
        
    Returns:
        Decrypted raw bytes
    """
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography library required for decryption")

    if not passphrase:
        raise ValueError("Decryption passphrase cannot be empty")

    min_size = SALT_SIZE + NONCE_SIZE + 16  # 16 = GCM tag size
    if len(encrypted_data) < min_size:
        raise ValueError(f"Encrypted data too short (minimum {min_size} bytes)")

    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE:]

    key = _derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def is_encryption_available() -> bool:
    """Check if encryption is available (cryptography library installed)."""
    return HAS_CRYPTO
