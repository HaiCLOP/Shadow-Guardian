"""
Shadow Guardian — Flask API Server

Localhost-only API server with dynamic port, auth gating,
first-run setup wizard, and IPC-based data access.
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import secrets
import time
import socket
import threading
from pathlib import Path
from functools import wraps
from typing import Optional
from collections import defaultdict

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, request, jsonify, send_from_directory, session
from utils.logger import get_logger, initialize_logging
from utils.config import get_config
from utils.single_instance import SingleInstance
from utils.secrets_store import encrypt_secret, decrypt_secret, is_secret_key
from core.ipc import IPCClient

logger = get_logger("api.server")


def _load_or_create_secret_key() -> str:
    """Load persistent secret key or generate one.
    
    Persists to disk so Flask sessions survive API restarts.
    """
    from utils.paths import get_app_data_dir
    key_file = get_app_data_dir() / "flask_secret.key"
    try:
        if key_file.exists():
            key = key_file.read_text(encoding="ascii").strip()
            if len(key) >= 32:
                return key
    except Exception:
        pass
    key = secrets.token_hex(32)
    try:
        key_file.write_text(key, encoding="ascii")
    except Exception:
        pass
    return key


app = Flask(
    __name__,
    static_folder=str(PROJECT_ROOT / "dashboard"),
    static_url_path="/static",
)
app.secret_key = _load_or_create_secret_key()

# Global IPC client
_ipc_client: Optional[IPCClient] = None
_setup_complete = False
_password_hash: Optional[str] = None


def _setup_marker_path() -> Path:
    """Path to the persistent 'setup completed' marker file."""
    from utils.paths import get_app_data_dir
    return get_app_data_dir() / ".setup_done"
_api_port: int = 0
_token_lock = threading.Lock()
_active_tokens: dict[str, float] = {}

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
PASSWORD_SCHEME = "scrypt"


# ─── Rate Limiter ─────────────────────────────────────────────────────

class RateLimiter:
    """
    Sliding-window rate limiter.
    
    Tracks attempts per key (IP address) and rejects requests that
    exceed the threshold within the window.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self._max_attempts = max_attempts
        self._window = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        """Check if a request is allowed. Records the attempt."""
        now = time.time()
        cutoff = now - self._window

        with self._lock:
            # Prune old entries
            self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]

            if len(self._attempts[key]) >= self._max_attempts:
                return False

            self._attempts[key].append(now)
            return True

    def retry_after(self, key: str) -> int:
        """Seconds until the oldest attempt expires."""
        with self._lock:
            timestamps = self._attempts.get(key, [])
            if not timestamps:
                return 0
            oldest = min(timestamps)
            return max(1, int(self._window - (time.time() - oldest)))


_auth_limiter = RateLimiter(max_attempts=5, window_seconds=300)


def _get_ipc() -> IPCClient:
    """Get or create IPC client."""
    global _ipc_client
    if _ipc_client is None:
        _ipc_client = IPCClient(timeout_ms=5000)
    return _ipc_client


def _ipc_command(command: dict) -> dict:
    """Send command via IPC and return response."""
    try:
        return _get_ipc().send_command(command)
    except Exception as e:
        logger.error(f"IPC command failed: {e}")
        return {"status": "error", "error": str(e)}


def _hash_password(password: str) -> str:
    """Hash a password with a versioned scrypt format."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    digest_b64 = base64.urlsafe_b64encode(digest).decode("ascii")
    return f"{PASSWORD_SCHEME}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt_b64}${digest_b64}"


def _verify_password(password: str, stored_hash: Optional[str]) -> tuple[bool, bool]:
    """
    Verify a password.

    Returns (is_valid, needs_rehash). The legacy SHA-256 format is accepted
    only so existing installs can migrate on the next successful login.
    """
    if not stored_hash:
        return False, False

    password_bytes = password.encode("utf-8")

    if stored_hash.startswith(f"{PASSWORD_SCHEME}$"):
        try:
            _, n_raw, r_raw, p_raw, salt_b64, digest_b64 = stored_hash.split("$", 5)
            salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
            expected = base64.urlsafe_b64decode(digest_b64.encode("ascii"))
            actual = hashlib.scrypt(
                password_bytes,
                salt=salt,
                n=int(n_raw),
                r=int(r_raw),
                p=int(p_raw),
                dklen=len(expected),
            )
            return hmac.compare_digest(actual, expected), False
        except Exception:
            return False, False

    # Legacy format from earlier builds: raw SHA-256 hex digest.
    if len(stored_hash) == 64:
        legacy = hashlib.sha256(password_bytes).hexdigest()
        return hmac.compare_digest(legacy, stored_hash), True

    return False, False


def _load_auth_state():
    """Load auth state from agent settings via IPC, with disk marker fallback."""
    global _setup_complete, _password_hash

    # Fast path: if the disk marker exists, setup was completed in a prior run.
    if _setup_marker_path().exists():
        _setup_complete = True

    try:
        resp = _ipc_command({"command": "GET_SETTINGS", "key": "password_hash"})
        if resp.get("status") == "ok":
            stored = resp.get("data", {}).get("value", "")
            if stored:
                _password_hash = stored
                _setup_complete = True
    except Exception as e:
        logger.error(f"Failed to load auth state: {e}")


def _get_auth_token() -> str:
    """Deprecated compatibility shim for old code paths."""
    return _issue_auth_token()


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _issue_auth_token() -> str:
    """Issue a short-lived random bearer token."""
    ttl = int(get_config().get("auth_token_ttl_seconds", 12 * 60 * 60))
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + max(300, ttl)

    with _token_lock:
        now = time.time()
        expired = [digest for digest, exp in _active_tokens.items() if exp <= now]
        for digest in expired:
            _active_tokens.pop(digest, None)
        _active_tokens[_token_digest(token)] = expires_at

    return token


def _verify_auth_token(token: str) -> bool:
    """Verify a bearer token against active in-memory tokens."""
    if not token:
        return False

    digest = _token_digest(token)
    now = time.time()

    with _token_lock:
        for stored_digest, expires_at in list(_active_tokens.items()):
            if expires_at <= now:
                _active_tokens.pop(stored_digest, None)
                continue
            if hmac.compare_digest(digest, stored_digest):
                return True

    return False


def _bounded_limit(default: int = 50) -> int:
    """Bound API query limits to avoid accidental large reads."""
    configured_max = int(get_config().get("max_query_limit", 500))
    limit = request.args.get("limit", default, type=int)
    return max(1, min(limit, configured_max))


def require_auth(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _setup_complete:
            _load_auth_state()
            
        if not _setup_complete:
            return jsonify({"error": "Setup required", "setup_required": True}), 403

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if _verify_auth_token(token):
                return f(*args, **kwargs)

        return jsonify({"error": "Authentication required"}), 401
    return decorated


@app.after_request
def add_security_headers(response):
    """Apply browser hardening headers for the local dashboard."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    # CORS: allow only same-origin (localhost)
    origin = request.headers.get("Origin", "")
    if origin:
        # Only allow localhost origins
        from urllib.parse import urlparse
        parsed = urlparse(origin)
        if parsed.hostname in ("127.0.0.1", "localhost", "[::1]"):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# ─── Setup Routes ────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the dashboard."""
    return send_from_directory(str(PROJECT_ROOT / "dashboard"), "index.html")


@app.route("/api/setup/status")
def setup_status():
    """Check if first-run setup is complete."""
    if not _setup_complete:
        _load_auth_state()
        
    return jsonify({
        "setup_complete": _setup_complete,
        "api_port": _api_port,
    })


@app.route("/api/setup", methods=["POST"])
def setup():
    """First-run setup — set password and optional cloud sync."""
    global _setup_complete, _password_hash

    if _setup_complete:
        return jsonify({"error": "Setup already completed"}), 400

    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    password = data.get("password", "")
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    # Hash and store password
    _password_hash = _hash_password(password)
    save_resp = _ipc_command({
        "command": "SET_SETTINGS",
        "key": "password_hash",
        "value": _password_hash,
    })
    if save_resp.get("status") != "ok":
        _password_hash = None
        return jsonify({
            "error": "Agent settings unavailable",
            "details": save_resp.get("error", "password save failed"),
        }), 503

    # Handle cloud sync preference
    cloud_sync = data.get("cloud_sync_enabled", False)
    supabase_url = data.get("supabase_url", "")
    supabase_key = data.get("supabase_key", "")

    if cloud_sync and supabase_url and supabase_key:
        # Encrypt secrets before storing
        settings_to_save = [
            ("cloud_sync_enabled", "true"),
            ("supabase_url", encrypt_secret(supabase_url)),
            ("supabase_key", encrypt_secret(supabase_key)),
        ]
        for key, value in settings_to_save:
            resp = _ipc_command({
                "command": "SET_SETTINGS",
                "key": key,
                "value": value,
            })
            if resp.get("status") != "ok":
                return jsonify({
                    "error": "Cloud sync settings unavailable",
                    "details": resp.get("error", f"{key} save failed"),
                }), 503

    _setup_complete = True

    # Persist marker so future boots never re-trigger the setup wizard
    try:
        _setup_marker_path().write_text("1", encoding="ascii")
    except Exception:
        logger.warning("Could not write setup marker file")

    logger.info("First-run setup completed")
    return jsonify({
        "status": "ok",
        "message": "Setup complete",
        "auth_token": _issue_auth_token(),
    })


@app.route("/api/auth", methods=["POST"])
def authenticate():
    """Authenticate with password. Rate-limited to 5 attempts per 5 minutes."""
    client_ip = request.remote_addr or "unknown"

    if not _auth_limiter.is_allowed(client_ip):
        retry = _auth_limiter.retry_after(client_ip)
        resp = jsonify({"error": "Too many login attempts. Try again later."})
        resp.headers["Retry-After"] = str(retry)
        return resp, 429

    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    password = data.get("password", "")

    if not _setup_complete:
        _load_auth_state()

    valid, needs_rehash = _verify_password(password, _password_hash)
    if valid:
        if needs_rehash:
            upgraded_hash = _hash_password(password)
            resp = _ipc_command({
                "command": "SET_SETTINGS",
                "key": "password_hash",
                "value": upgraded_hash,
            })
            if resp.get("status") == "ok":
                globals()["_password_hash"] = upgraded_hash

        return jsonify({
            "status": "ok",
            "auth_token": _issue_auth_token(),
        })

    return jsonify({"error": "Invalid password"}), 401


# ─── Data Routes ─────────────────────────────────────────────────────

@app.route("/api/apps")
@require_auth
def get_apps():
    """Get app usage data."""
    limit = _bounded_limit(50)
    since = request.args.get("since", None, type=float)
    resp = _ipc_command({"command": "GET_APPS", "limit": limit, "since": since})
    return jsonify(resp)


@app.route("/api/sessions")
@require_auth
def get_sessions():
    """Get session timeline."""
    limit = _bounded_limit(50)
    since = request.args.get("since", None, type=float)
    resp = _ipc_command({"command": "GET_SESSIONS", "limit": limit, "since": since})
    return jsonify(resp)


@app.route("/api/alerts")
@require_auth
def get_alerts():
    """Get alerts."""
    limit = _bounded_limit(50)
    severity = request.args.get("severity", None)
    resp = _ipc_command({"command": "GET_ALERTS", "limit": limit, "severity": severity})
    return jsonify(resp)


@app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
@require_auth
def ack_alert(alert_id):
    """Acknowledge an alert."""
    resp = _ipc_command({"command": "ACK_ALERT", "alert_id": alert_id})
    return jsonify(resp)


@app.route("/api/webjail/toggle", methods=["POST"])
@require_auth
def webjail_toggle():
    """Toggle WebJail on/off."""
    data = request.get_json() or {}
    enabled = data.get("enabled", False)
    domains = data.get("domains", [])
    if not isinstance(domains, list):
        return jsonify({"error": "domains must be a list"}), 400
    domains = [str(domain)[:253] for domain in domains[:500]]
    resp = _ipc_command({
        "command": "WEBJAIL_TOGGLE",
        "enabled": enabled,
        "domains": domains,
    })
    return jsonify(resp)


@app.route("/api/status")
@require_auth
def get_status():
    """Get system status."""
    resp = _ipc_command({"command": "STATUS"})
    return jsonify(resp)


@app.route("/api/health")
def health_check():
    """Unauthenticated health endpoint for watchdog probes."""
    return jsonify({"status": "ok", "pid": os.getpid()})


@app.route("/api/browser-history")
@require_auth
def get_browser_history():
    """Get browser history."""
    limit = _bounded_limit(50)
    since = request.args.get("since", None, type=float)
    resp = _ipc_command({"command": "GET_BROWSER_HISTORY", "limit": limit, "since": since})
    return jsonify(resp)


@app.route("/api/usb-events")
@require_auth
def get_usb_events():
    """Get USB device events."""
    limit = _bounded_limit(50)
    since = request.args.get("since", None, type=float)
    resp = _ipc_command({"command": "GET_USB_EVENTS", "limit": limit, "since": since})
    return jsonify(resp)


@app.route("/api/clipboard-log")
@require_auth
def get_clipboard_log():
    """Get clipboard activity log."""
    limit = _bounded_limit(50)
    since = request.args.get("since", None, type=float)
    resp = _ipc_command({"command": "GET_CLIPBOARD_LOG", "limit": limit, "since": since})
    return jsonify(resp)


@app.route("/api/file-events")
@require_auth
def get_file_events():
    """Get file monitoring events."""
    limit = _bounded_limit(50)
    since = request.args.get("since", None, type=float)
    resp = _ipc_command({"command": "GET_FILE_EVENTS", "limit": limit, "since": since})
    return jsonify(resp)


@app.route("/api/all-windows")
@require_auth
def get_all_windows():
    """Get all currently open windows."""
    resp = _ipc_command({"command": "GET_ALL_WINDOWS"})
    return jsonify(resp)


# ─── Error Handlers ──────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ─── Server Startup ─────────────────────────────────────────────────

def find_free_port() -> int:
    """Find a free port for the API server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_server():
    """Start the API server."""
    global _api_port

    config = get_config()
    initialize_logging(config.get("log_level", "production"))
    instance_guard = SingleInstance("ShadowGuardianAPI")
    if not instance_guard.acquire():
        raise RuntimeError("Shadow Guardian API server is already running")

    # Determine port
    if config.get("dynamic_port", True):
        _api_port = find_free_port()
    else:
        _api_port = config.get("api_port", 5000) or find_free_port()

    # Write port file for dashboard discovery
    from utils.paths import get_app_data_dir
    port_file = get_app_data_dir() / "api_port.txt"
    port_file.write_text(str(_api_port))

    # Load auth state (retry a few times in case agent is still starting)
    for _ in range(5):
        try:
            _load_auth_state()
            if _setup_complete:
                break
        except Exception:
            pass
        time.sleep(1)

    # Log setup state (browser is never auto-opened; the dashboard
    # handles setup detection client-side when the user navigates to it).
    if not _setup_complete:
        logger.info("First run detected — setup wizard available at "
                     f"http://127.0.0.1:{_api_port}")

    logger.info(f"API server starting on 127.0.0.1:{_api_port}")

    try:
        try:
            from waitress import serve
            serve(app, host="127.0.0.1", port=_api_port, threads=8)
        except ImportError:
            logger.warning("waitress not installed; falling back to Flask development server")
            app.run(
                host="127.0.0.1",
                port=_api_port,
                debug=False,
                threaded=True,
                use_reloader=False,
            )
    finally:
        instance_guard.release()
