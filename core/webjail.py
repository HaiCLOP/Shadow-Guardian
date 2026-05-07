"""
Shadow Guardian — WebJail

Domain blocking via Windows hosts file modification.
Backs up original hosts, uses managed comment markers,
flushes DNS cache after changes, and supports crash-safe rollback.
"""

import os
import shutil
import subprocess
import tempfile
import threading
import re
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

try:
    import webjail_ext
except ImportError:
    webjail_ext = None

logger = get_logger("core.webjail")

HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
BACKUP_PATH = HOSTS_PATH.parent / "hosts.shadowguardian.bak"
MARKER_START = "# >>> ShadowGuardian WebJail START >>>"
MARKER_END = "# <<< ShadowGuardian WebJail END <<<"
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

# Default blocklist — gambling, adult, malware, phishing, time-wasters
DEFAULT_BLOCKLIST = [
    # Gambling
    "bet365.com", "pokerstars.com", "888casino.com", "williamhill.com",
    "bwin.com", "betfair.com", "unibet.com", "draftkings.com",
    "fanduel.com", "bovada.lv",
    # Malware / Phishing known patterns
    "malware-domain.com", "phishing-site.net", "fakeupdates.net",
    "free-prizes-now.com", "your-pc-is-infected.com",
    "urgent-security-alert.com", "virus-scan-online.com",
    # Proxy / VPN bypass
    "hide.me", "kproxy.com", "proxysite.com", "croxyproxy.com",
    "vpnbook.com", "hidester.com",
    # Time wasters (optional — can be removed by user)
    "reddit.com", "9gag.com", "buzzfeed.com", "tiktok.com",
]


class WebJail:
    """
    Domain blocker using the Windows hosts file.

    Features:
        - Backup/restore of original hosts file
        - Managed section markers to avoid corrupting user entries
        - DNS cache flush after every write (ipconfig /flushdns)
        - In-memory rule cache — only rewrites when rules change
        - Default blocklist of known harmful domains
        - Crash-safe: cleans stale entries on startup
        - Thread-safe operations
    """

    def __init__(self, cleanup_on_init: bool = True):
        self._lock = threading.Lock()
        self._active_domains: set[str] = set()
        self._enabled = False
        self._is_admin = self._check_admin()

        if not self._is_admin:
            logger.warning("WebJail requires admin privileges — disabled")
        elif cleanup_on_init:
            self._cleanup_stale()

    def cleanup_stale(self) -> None:
        """Public wrapper for stale entry cleanup (crash recovery)."""
        if self._is_admin:
            self._cleanup_stale()

    @staticmethod
    def _check_admin() -> bool:
        """Check if running with administrator privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def get_default_blocklist() -> list[str]:
        """Return the default domain blocklist."""
        return list(DEFAULT_BLOCKLIST)

    def _backup_hosts(self) -> bool:
        """Create backup of hosts file if none exists."""
        try:
            if not HOSTS_PATH.exists():
                # On very rare Windows configs, hosts file might not exist yet
                HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
                HOSTS_PATH.write_text("# Windows Hosts File\n", encoding="utf-8")
                
            if not BACKUP_PATH.exists():
                shutil.copy2(str(HOSTS_PATH), str(BACKUP_PATH))
                logger.info("Hosts file backed up")
            return True
        except Exception as e:
            logger.error(f"Failed to backup hosts: {e}")
            return False

    def _read_hosts(self) -> str:
        """Read the current hosts file content."""
        try:
            return HOSTS_PATH.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to read hosts: {e}")
            return ""

    def _strip_managed_section(self, content: str) -> str:
        """Remove any existing ShadowGuardian-managed section."""
        if webjail_ext:
            return webjail_ext.strip_managed_section(content)
        
        lines = content.splitlines(keepends=True)
        result = []
        in_managed = False
        for line in lines:
            if MARKER_START in line:
                in_managed = True
                continue
            if MARKER_END in line:
                in_managed = False
                continue
            if not in_managed:
                result.append(line)
        return "".join(result)

    def _build_managed_section(self, domains: set[str]) -> str:
        """Build the managed hosts entries block."""
        if not domains:
            return ""
            
        if webjail_ext:
            return webjail_ext.build_managed_section(list(domains))
            
        # Block DNS over HTTPS (DoH) providers to prevent WebJail bypass
        doh_providers = {
            "cloudflare-dns.com",
            "mozilla.cloudflare-dns.com",
            "dns.google",
            "dns.quad9.net",
            "doh.opendns.com",
            "dns.adguard.com",
            "dns.nextdns.io"
        }
        all_domains = domains.union(doh_providers)

        lines = [MARKER_START + "\n"]
        for domain in sorted(all_domains):
            lines.append(f"0.0.0.0 {domain}\n")
            lines.append(f":: {domain}\n")
            # Also block www subdomain
            if not domain.startswith("www."):
                lines.append(f"0.0.0.0 www.{domain}\n")
                lines.append(f":: www.{domain}\n")
        lines.append(MARKER_END + "\n")
        return "".join(lines)

    def _normalize_domain(self, domain: str) -> Optional[str]:
        """Return a safe DNS name or None."""
        normalized = domain.strip().lower().rstrip(".")
        # Strip protocol prefixes if present
        for prefix in ("http://", "https://", "www."):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
        # Remove path
        normalized = normalized.split("/")[0]
        
        if not normalized or any(ch.isspace() for ch in normalized):
            return None
        if not DOMAIN_RE.match(normalized):
            return None
        return normalized

    def _write_hosts(self, content: str) -> bool:
        """Write content to hosts file atomically."""
        # Remove read-only protection before writing
        self._unprotect_hosts()
        
        if webjail_ext:
            try:
                result = webjail_ext.write_hosts(content, str(HOSTS_PATH))
                if result:
                    self._protect_hosts()
                return result
            except Exception as e:
                logger.error(f"Rust write_hosts failed: {e}")
                # Fall back to python impl if rust panics
        
        try:
            hosts_dir = HOSTS_PATH.parent
            # Write to temp file in the same directory (required for os.replace)
            fd, tmp_path = tempfile.mkstemp(dir=str(hosts_dir), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, str(HOSTS_PATH))
            except OSError:
                # os.replace can fail on some Windows configs; fall back to direct write
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                HOSTS_PATH.write_text(content, encoding="utf-8")

            # Post-write integrity check
            written = self._read_hosts()
            if MARKER_START in content and MARKER_START not in written:
                logger.error("Hosts file integrity check failed after write")
                return False

            # Protect hosts file from casual tampering
            self._protect_hosts()
            return True
        except PermissionError:
            logger.error("Permission denied writing hosts file — run as admin")
            return False
        except Exception as e:
            logger.error(f"Failed to write hosts: {e}")
            return False

    def _flush_dns(self) -> None:
        """Flush the Windows DNS resolver cache so changes take effect immediately."""
        if webjail_ext:
            try:
                webjail_ext.flush_dns()
                logger.debug("DNS cache flushed (Rust)")
                return
            except Exception as e:
                logger.warning(f"Rust DNS flush failed: {e}")

        try:
            # Prefer absolute path for ipconfig to avoid PATH hijack or not-found errors
            ipconfig_path = shutil.which("ipconfig") or r"C:\Windows\System32\ipconfig.exe"
            subprocess.run(
                [ipconfig_path, "/flushdns"],
                capture_output=True,
                timeout=10,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
            logger.debug("DNS cache flushed")
        except Exception as e:
            logger.warning(f"DNS flush failed: {e}")

    def _protect_hosts(self) -> None:
        """Set hosts file to read-only to prevent casual tampering."""
        try:
            attrib = shutil.which("attrib") or r"C:\Windows\System32\attrib.exe"
            subprocess.run(
                [attrib, "+R", str(HOSTS_PATH)],
                capture_output=True,
                creationflags=0x08000000,
            )
            logger.debug("Hosts file protected (read-only)")
        except Exception as e:
            logger.warning(f"Failed to protect hosts file: {e}")

    def _unprotect_hosts(self) -> None:
        """Remove read-only flag from hosts file before writing."""
        try:
            attrib = shutil.which("attrib") or r"C:\Windows\System32\attrib.exe"
            subprocess.run(
                [attrib, "-R", str(HOSTS_PATH)],
                capture_output=True,
                creationflags=0x08000000,
            )
        except Exception:
            pass

    def start_tamper_watch(self) -> None:
        """Start a background thread that monitors the hosts file for tampering."""
        if hasattr(self, '_tamper_thread') and self._tamper_thread and self._tamper_thread.is_alive():
            return
        self._tamper_stop = threading.Event()
        self._tamper_thread = threading.Thread(
            target=self._tamper_watch_loop, name="WebJail-TamperWatch", daemon=True,
        )
        self._tamper_thread.start()
        logger.info("WebJail tamper watch started")

    def stop_tamper_watch(self) -> None:
        """Stop the tamper watch thread."""
        if hasattr(self, '_tamper_stop'):
            self._tamper_stop.set()

    def _tamper_watch_loop(self) -> None:
        """Periodically check if someone removed WebJail entries and re-apply them."""
        while not self._tamper_stop.is_set():
            self._tamper_stop.wait(timeout=15)  # Check every 15 seconds
            if self._tamper_stop.is_set():
                break
            if not self._enabled or not self._active_domains:
                continue
            try:
                content = self._read_hosts()
                if MARKER_START not in content:
                    logger.warning("WebJail tamper detected — re-applying rules")
                    with self._lock:
                        clean = self._strip_managed_section(content)
                        managed = self._build_managed_section(self._active_domains)
                        if not clean.endswith("\n"):
                            clean += "\n"
                        self._write_hosts(clean + managed)
                        self._flush_dns()
            except Exception as e:
                logger.warning(f"Tamper watch error: {e}")

    def _cleanup_stale(self) -> None:
        """Remove any stale managed entries (crash recovery)."""
        content = self._read_hosts()
        if MARKER_START in content:
            cleaned = self._strip_managed_section(content)
            self._write_hosts(cleaned)
            self._flush_dns()
            logger.info("Cleaned stale WebJail entries")

    def apply_rules(self, domains: list[str]) -> bool:
        """Apply domain blocking rules."""
        if not self._is_admin:
            logger.error("Cannot apply WebJail rules without admin privileges")
            return False

        with self._lock:
            new_domains = set()
            for domain in domains:
                normalized = self._normalize_domain(str(domain))
                if normalized:
                    new_domains.add(normalized)

            if new_domains == self._active_domains and self._enabled:
                return True  # No changes needed

            self._backup_hosts()
            content = self._read_hosts()
            clean = self._strip_managed_section(content)
            managed = self._build_managed_section(new_domains)

            if not clean.endswith("\n"):
                clean += "\n"

            if self._write_hosts(clean + managed):
                self._active_domains = new_domains
                self._enabled = True
                self._flush_dns()
                logger.info(f"WebJail applied: {len(new_domains)} domains blocked")
                return True
            return False

    def disable(self) -> bool:
        """Remove all managed entries from hosts file."""
        with self._lock:
            content = self._read_hosts()
            clean = self._strip_managed_section(content)
            if self._write_hosts(clean):
                self._active_domains.clear()
                self._enabled = False
                self._flush_dns()
                logger.info("WebJail disabled")
                return True
            return False

    def rollback(self) -> bool:
        """Restore hosts file from backup."""
        with self._lock:
            try:
                if BACKUP_PATH.exists():
                    shutil.copy2(str(BACKUP_PATH), str(HOSTS_PATH))
                    self._active_domains.clear()
                    self._enabled = False
                    self._flush_dns()
                    logger.info("Hosts file restored from backup")
                    return True
                else:
                    logger.warning("No backup file found for rollback")
                    return False
            except Exception as e:
                logger.error(f"Rollback failed: {e}")
                return False

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    @property
    def blocked_domains(self) -> list[str]:
        with self._lock:
            return sorted(self._active_domains)

    @property
    def is_admin(self) -> bool:
        return self._is_admin
