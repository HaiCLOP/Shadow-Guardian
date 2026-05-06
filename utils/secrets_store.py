"""
Shadow Guardian — Secrets Store

Encrypts sensitive configuration values at rest using Windows DPAPI
(CryptProtectData / CryptUnprotectData). Falls back to base64 obfuscation
on platforms without DPAPI — not secure, but better than plaintext.

Thread-safe. Stores encrypted blobs as base64 strings in the DB settings table.
"""

import base64
import ctypes
import ctypes.wintypes
import json
import os
import threading
from typing import Optional

from utils.logger import get_logger

logger = get_logger("utils.secrets_store")


# ─── DPAPI Structures ────────────────────────────────────────────────────

class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


_HAS_DPAPI = False
try:
    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _HAS_DPAPI = True
except (AttributeError, OSError):
    logger.warning("DPAPI not available — secrets will use obfuscated storage")

# DPAPI flags
CRYPTPROTECT_LOCAL_MACHINE = 0x04


def _dpapi_encrypt(data: bytes) -> bytes:
    """Encrypt bytes using Windows DPAPI (user-scoped)."""
    if not _HAS_DPAPI:
        raise RuntimeError("DPAPI not available")

    blob_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)),
                                                 ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()

    result = _crypt32.CryptProtectData(
        ctypes.byref(blob_in),
        None,   # description
        None,   # optional entropy
        None,   # reserved
        None,   # prompt struct
        0,      # flags (user-scoped, not machine-scoped)
        ctypes.byref(blob_out),
    )

    if not result:
        raise OSError(f"CryptProtectData failed: {ctypes.GetLastError()}")

    try:
        encrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        return encrypted
    finally:
        _kernel32.LocalFree(blob_out.pbData)


def _dpapi_decrypt(encrypted: bytes) -> bytes:
    """Decrypt bytes using Windows DPAPI."""
    if not _HAS_DPAPI:
        raise RuntimeError("DPAPI not available")

    blob_in = DATA_BLOB(len(encrypted),
                         ctypes.cast(ctypes.create_string_buffer(encrypted, len(encrypted)),
                                     ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()

    result = _crypt32.CryptUnprotectData(
        ctypes.byref(blob_in),
        None,   # description
        None,   # optional entropy
        None,   # reserved
        None,   # prompt struct
        0,      # flags
        ctypes.byref(blob_out),
    )

    if not result:
        raise OSError(f"CryptUnprotectData failed: {ctypes.GetLastError()}")

    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        _kernel32.LocalFree(blob_out.pbData)


def _obfuscate(data: bytes) -> bytes:
    """Simple XOR obfuscation fallback — NOT cryptographically secure."""
    key = b"ShadowGuardian_FallbackKey_v1"
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _deobfuscate(data: bytes) -> bytes:
    """Reverse XOR obfuscation."""
    return _obfuscate(data)  # XOR is self-inverse


# ─── Public API ───────────────────────────────────────────────────────────

# Known secret keys that should be encrypted
SECRET_KEYS = frozenset({
    "supabase_key",
    "supabase_url",
    "encryption_passphrase",
})

_PREFIX_DPAPI = "dpapi:"
_PREFIX_OBFS = "obfs:"
_lock = threading.Lock()


def encrypt_secret(value: str) -> str:
    """
    Encrypt a secret value for storage.

    Returns a prefixed base64 string indicating the protection method:
        dpapi:<base64>  — Windows DPAPI encrypted
        obfs:<base64>   — XOR obfuscated fallback
    """
    if not value:
        return ""

    raw = value.encode("utf-8")

    with _lock:
        if _HAS_DPAPI:
            try:
                encrypted = _dpapi_encrypt(raw)
                return _PREFIX_DPAPI + base64.urlsafe_b64encode(encrypted).decode("ascii")
            except Exception as e:
                logger.warning(f"DPAPI encryption failed, using fallback: {e}")

        # Fallback
        obfuscated = _obfuscate(raw)
        return _PREFIX_OBFS + base64.urlsafe_b64encode(obfuscated).decode("ascii")


def decrypt_secret(stored: str) -> str:
    """
    Decrypt a stored secret value.

    Handles both DPAPI and obfuscated formats. Returns empty string on failure.
    """
    if not stored:
        return ""

    with _lock:
        try:
            if stored.startswith(_PREFIX_DPAPI):
                encrypted = base64.urlsafe_b64decode(stored[len(_PREFIX_DPAPI):])
                return _dpapi_decrypt(encrypted).decode("utf-8")

            elif stored.startswith(_PREFIX_OBFS):
                obfuscated = base64.urlsafe_b64decode(stored[len(_PREFIX_OBFS):])
                return _deobfuscate(obfuscated).decode("utf-8")

            else:
                # Unencrypted legacy value — return as-is
                return stored

        except Exception as e:
            logger.error(f"Failed to decrypt secret: {e}")
            return ""


def is_encrypted(stored: str) -> bool:
    """Check if a stored value is already encrypted."""
    return stored.startswith(_PREFIX_DPAPI) or stored.startswith(_PREFIX_OBFS)


def is_secret_key(key: str) -> bool:
    """Check if a settings key should be treated as a secret."""
    return key in SECRET_KEYS


def has_dpapi() -> bool:
    """Check if DPAPI is available."""
    return _HAS_DPAPI
