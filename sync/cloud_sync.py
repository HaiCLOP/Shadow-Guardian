"""
Shadow Guardian — Cloud Sync Worker

Offline-first Supabase sync with retry, compression, and encryption.
Queues all events locally and syncs in batches.
"""

import time
import zlib
import json
import base64
import threading
from typing import Optional

from utils.logger import get_logger
from utils.config import get_config
from utils.crypto import encrypt_payload, is_encryption_available
from utils.secrets_store import decrypt_secret

logger = get_logger("sync.cloud_sync")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


BACKOFF_SCHEDULE = [1, 2, 4, 8, 16, 30, 60]


class CloudSyncWorker:
    """
    Offline-first cloud sync to Supabase.

    Pipeline: read unsynced → compress (zlib) → encrypt (AES) → POST
    Retries with exponential backoff on failure.
    """

    def __init__(self, db):
        self._db = db
        self._config = get_config()
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._retry_count = 0
        self._synced_count = 0

        self._enabled = False
        self._supabase_url = ""
        self._supabase_key = ""
        self._passphrase = ""
        self._sync_interval = self._config.get("sync_interval", 300)

    def start(self) -> None:
        """Start the sync worker thread."""
        if not HAS_REQUESTS:
            logger.warning("requests library not installed — sync disabled")
            return

        self._refresh_settings()
        if not self._enabled:
            logger.info("Cloud sync disabled")
            return

        if not self._supabase_url or not self._supabase_key:
            logger.warning("Supabase not configured — sync disabled")
            return

        self._running.set()
        self._thread = threading.Thread(
            target=self._sync_loop,
            name="CloudSync",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"Cloud sync started (interval: {self._sync_interval}s)")

    def stop(self) -> None:
        """Stop the sync worker."""
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=10.0)
        logger.info(f"Cloud sync stopped (synced: {self._synced_count})")

    def _sync_loop(self) -> None:
        """Main sync loop — wakes every sync_interval seconds."""
        while self._running.is_set():
            try:
                self._sync_batch()
                self._retry_count = 0  # Reset on success
            except Exception as e:
                self._retry_count = min(self._retry_count + 1, len(BACKOFF_SCHEDULE) - 1)
                delay = BACKOFF_SCHEDULE[self._retry_count]
                logger.error(f"Sync failed: {e} — retrying in {delay}s")
                if self._running.wait(timeout=delay):
                    continue

            # Wait for next sync interval
            self._running.wait(timeout=self._sync_interval)

    def _sync_batch(self) -> None:
        """Sync a batch of unsynced records."""
        self._refresh_settings()
        if not self._enabled or not self._supabase_url or not self._supabase_key:
            return

        unsynced = self._db.get_unsynced(limit=100)
        if not unsynced:
            return

        # Collect actual data for each record
        records = []
        missing_sync_ids = []
        for entry in unsynced:
            table = entry["table_name"]
            record_id = entry["record_id"]

            # Fetch the actual record
            try:
                data = self._db.get_record(table, record_id)

                if data:
                    records.append({
                        "table": table,
                        "record_id": record_id,
                        "data": data,
                        "sync_id": entry["id"],
                    })
                else:
                    missing_sync_ids.append(entry["id"])
            except Exception:
                continue

        if missing_sync_ids:
            self._db.mark_synced(missing_sync_ids)

        if not records:
            return

        # Serialize
        payload = json.dumps(records, default=str).encode("utf-8")

        # Compress
        compressed = zlib.compress(payload, level=6)
        logger.debug(
            f"Sync payload: {len(payload)} → {len(compressed)} bytes "
            f"({100 - len(compressed) * 100 // len(payload)}% reduction)"
        )

        # Encrypt if available
        if is_encryption_available() and self._passphrase:
            final_payload = encrypt_payload(compressed, self._passphrase)
        else:
            final_payload = compressed

        encoded_payload = base64.b64encode(final_payload).decode("ascii")
        request_body = {
            "payload": encoded_payload,
            "encrypted": bool(self._passphrase),
            "compressed": True,
            "record_count": len(records),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # Upload to Supabase
        headers = {
            "apikey": self._supabase_key,
            "Authorization": f"Bearer {self._supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
            "X-ShadowGuardian-Encrypted": str(bool(self._passphrase)),
            "X-ShadowGuardian-Compressed": "true",
        }

        resp = requests.post(
            f"{self._supabase_url}/rest/v1/sync_logs",
            data=json.dumps(request_body),
            headers=headers,
            timeout=30,
        )

        if resp.status_code in (200, 201):
            sync_ids = [r["sync_id"] for r in records]
            self._db.mark_synced(sync_ids)
            self._synced_count += len(sync_ids)
            logger.info(f"Synced {len(sync_ids)} records to cloud")
        else:
            raise RuntimeError(f"Supabase sync failed: {resp.status_code} {resp.text}")

    def _refresh_settings(self) -> None:
        """Load sync settings from DB first, then config defaults.
        
        Secrets are stored encrypted via DPAPI — decrypt_secret handles
        both encrypted and legacy plaintext values transparently.
        """
        enabled_setting = self._db.get_setting("cloud_sync_enabled", "").strip().lower()
        if enabled_setting:
            self._enabled = enabled_setting in {"1", "true", "yes", "on"}
        else:
            self._enabled = self._config.get("feature_flags.cloud_sync_enabled", False)

        self._supabase_url = decrypt_secret(
            self._db.get_setting("supabase_url", "").strip()
        ) or self._config.get("supabase_url", "")

        self._supabase_key = decrypt_secret(
            self._db.get_setting("supabase_key", "").strip()
        ) or self._config.get("supabase_key", "")

        self._passphrase = decrypt_secret(
            self._db.get_setting("encryption_passphrase", "").strip()
        ) or self._config.get("encryption_passphrase", "")

    @property
    def stats(self) -> dict:
        return {
            "synced_count": self._synced_count,
            "retry_count": self._retry_count,
            "running": self._running.is_set(),
        }
