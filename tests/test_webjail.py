"""
Tests for core.webjail — domain validation, managed sections.
"""
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

class TestWebJailDomainValidation:
    def test_valid_domain(self):
        from core.webjail import WebJail
        wj = WebJail.__new__(WebJail)
        wj._lock = __import__("threading").Lock()
        result = wj._normalize_domain("example.com")
        assert result == "example.com"

    def test_uppercase_normalized(self):
        from core.webjail import WebJail
        wj = WebJail.__new__(WebJail)
        wj._lock = __import__("threading").Lock()
        assert wj._normalize_domain("EXAMPLE.COM") == "example.com"

    def test_empty_returns_none(self):
        from core.webjail import WebJail
        wj = WebJail.__new__(WebJail)
        wj._lock = __import__("threading").Lock()
        assert wj._normalize_domain("") is None
        assert wj._normalize_domain("   ") is None

    def test_trailing_dot_stripped(self):
        from core.webjail import WebJail
        wj = WebJail.__new__(WebJail)
        wj._lock = __import__("threading").Lock()
        assert wj._normalize_domain("example.com.") == "example.com"

class TestManagedSection:
    def test_build_managed_section(self):
        from core.webjail import WebJail, MARKER_START, MARKER_END
        wj = WebJail.__new__(WebJail)
        wj._lock = __import__("threading").Lock()
        section = wj._build_managed_section({"example.com", "test.org"})
        assert MARKER_START in section
        assert MARKER_END in section
        assert "0.0.0.0 example.com" in section
        assert "0.0.0.0 test.org" in section

    def test_empty_domains(self):
        from core.webjail import WebJail
        wj = WebJail.__new__(WebJail)
        wj._lock = __import__("threading").Lock()
        assert wj._build_managed_section(set()) == ""

    def test_strip_managed_section(self):
        from core.webjail import WebJail, MARKER_START, MARKER_END
        wj = WebJail.__new__(WebJail)
        wj._lock = __import__("threading").Lock()
        content = f"# normal\n{MARKER_START}\n0.0.0.0 blocked.com\n{MARKER_END}\n# after"
        stripped = wj._strip_managed_section(content)
        assert MARKER_START not in stripped
        assert "blocked.com" not in stripped
        assert "# normal" in stripped
        assert "# after" in stripped
