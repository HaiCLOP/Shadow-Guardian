"""
Tests for utils.config — loading, validation, dot notation, schema coercion.
"""
import json
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.config import ConfigManager, DEFAULT_CONFIG, _DEPRECATED_CONFIG_KEYS

class TestConfigValidation:
    def test_default_config_valid(self, temp_config_path):
        cm = ConfigManager(config_path=temp_config_path)
        assert "feature_flags" in cm._config
        assert cm._config["batch_write_interval"] >= 1

    def test_missing_keys_get_defaults(self, temp_dir):
        config_path = temp_dir / "config.json"
        config_path.write_text("{}", encoding="utf-8")
        cm = ConfigManager(config_path=str(config_path))
        for key in DEFAULT_CONFIG:
            assert key in cm._config, f"Missing default key: {key}"

class TestConfigDotNotation:
    def test_nested_access(self, temp_config_path):
        cm = ConfigManager(config_path=temp_config_path)
        assert cm.get("feature_flags.alert_engine") is True
        assert cm.get("adaptive_polling.active_interval") == 5

    def test_missing_nested_returns_default(self, temp_config_path):
        cm = ConfigManager(config_path=temp_config_path)
        assert cm.get("nonexistent.deep.key", "fallback") == "fallback"

class TestConfigDeprecatedKeys:
    def test_deprecated_keys_defined(self):
        assert "supabase_key" in _DEPRECATED_CONFIG_KEYS
        assert "supabase_url" in _DEPRECATED_CONFIG_KEYS
        assert "encryption_passphrase" in _DEPRECATED_CONFIG_KEYS

    def test_defaults_exclude_secrets(self):
        for key in _DEPRECATED_CONFIG_KEYS:
            assert key not in DEFAULT_CONFIG

class TestConfigCoercion:
    def test_batch_interval_minimum(self, temp_dir):
        p = temp_dir / "config.json"
        p.write_text(json.dumps({"batch_write_interval": 0}), encoding="utf-8")
        cm = ConfigManager(config_path=str(p))
        assert cm._config["batch_write_interval"] >= 1

    def test_query_limit_capped(self, temp_dir):
        p = temp_dir / "config.json"
        p.write_text(json.dumps({"max_query_limit": 999999}), encoding="utf-8")
        cm = ConfigManager(config_path=str(p))
        assert cm._config["max_query_limit"] <= 5000
