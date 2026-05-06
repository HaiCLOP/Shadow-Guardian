"""
Tests for api.server — auth flow, rate limiting, security headers, health.
"""
import json
import time
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def client():
    """Create Flask test client with mocked IPC."""
    with patch("api.server._load_or_create_secret_key", return_value="test_secret_key_abcdef1234567890"):
        with patch("api.server.IPCClient"):
            from api.server import app, _hash_password, RateLimiter
            app.config["TESTING"] = True
            # Reset rate limiter
            import api.server as srv
            srv._auth_limiter = RateLimiter(max_attempts=5, window_seconds=300)
            srv._setup_complete = True
            srv._password_hash = _hash_password("testpass")
            with app.test_client() as c:
                yield c


class TestSecurityHeaders:
    def test_csp_header(self, client):
        resp = client.get("/api/health")
        assert "Content-Security-Policy" in resp.headers
        csp = resp.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp
        assert "default-src 'self'" in csp

    def test_xframe_deny(self, client):
        resp = client.get("/api/health")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_nosniff(self, client):
        resp = client.get("/api/health")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_no_store(self, client):
        resp = client.get("/api/health")
        assert "no-store" in resp.headers.get("Cache-Control", "")


class TestHealthEndpoint:
    def test_health_no_auth(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"
        assert "pid" in data


class TestRateLimiter:
    def test_allows_within_limit(self):
        from api.server import RateLimiter
        rl = RateLimiter(max_attempts=3, window_seconds=60)
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip1") is True

    def test_blocks_over_limit(self):
        from api.server import RateLimiter
        rl = RateLimiter(max_attempts=3, window_seconds=60)
        rl.is_allowed("ip1")
        rl.is_allowed("ip1")
        rl.is_allowed("ip1")
        assert rl.is_allowed("ip1") is False

    def test_different_ips_independent(self):
        from api.server import RateLimiter
        rl = RateLimiter(max_attempts=1, window_seconds=60)
        assert rl.is_allowed("ip1") is True
        assert rl.is_allowed("ip1") is False
        assert rl.is_allowed("ip2") is True

    def test_retry_after(self):
        from api.server import RateLimiter
        rl = RateLimiter(max_attempts=1, window_seconds=300)
        rl.is_allowed("ip1")
        retry = rl.retry_after("ip1")
        assert 290 <= retry <= 300
