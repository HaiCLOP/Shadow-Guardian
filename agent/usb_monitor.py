"""
Shadow Guardian — USB Device Monitor

Monitors USB device insertions and removals using WMI queries.
Polls device list and diffs to detect changes.
Alerts on any new USB storage device connections.
"""

import subprocess
import threading
import time
import re
from typing import Optional

from utils.logger import get_logger
from core.event_queue import EventQueue, EVENT_USB, PRIORITY_HIGH

logger = get_logger("agent.usb_monitor")


class USBMonitor:
    """
    Monitors USB device changes by polling WMI via PowerShell.
    
    Detects:
        - USB mass storage device insertions
        - USB device removals
        - New/unknown USB devices
    """

    def __init__(self, event_queue: Optional[EventQueue]):
        self._queue = event_queue
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._known_devices: dict[str, dict] = {}
        self._poll_interval = 10  # seconds

    def start(self) -> None:
        """Start USB monitoring thread."""
        self._running.set()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="USBMonitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("USB device monitor started")

    def stop(self) -> None:
        """Stop USB monitoring."""
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("USB device monitor stopped")

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        # Initial snapshot
        self._known_devices = self._get_usb_devices()
        logger.debug(f"Initial USB device scan: {len(self._known_devices)} devices")

        while self._running.is_set():
            try:
                current = self._get_usb_devices()

                # Detect new devices
                for dev_id, dev_info in current.items():
                    if dev_id not in self._known_devices:
                        self._on_device_connected(dev_info)

                # Detect removed devices
                for dev_id, dev_info in self._known_devices.items():
                    if dev_id not in current:
                        self._on_device_removed(dev_info)

                self._known_devices = current

            except Exception as e:
                logger.error(f"USB monitor error: {e}")

            # Sleep in small increments
            deadline = time.time() + self._poll_interval
            while time.time() < deadline and self._running.is_set():
                time.sleep(1.0)

    def _get_usb_devices(self) -> dict[str, dict]:
        """Get current USB devices via PowerShell WMI query."""
        devices = {}
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive",
                    "-Command",
                    "Get-PnpDevice -Class USB,DiskDrive,WPD -Status OK -ErrorAction SilentlyContinue | "
                    "Select-Object InstanceId,FriendlyName,Class | "
                    "ConvertTo-Json -Compress"
                ],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    dev_id = item.get("InstanceId", "")
                    if dev_id:
                        devices[dev_id] = {
                            "device_id": dev_id,
                            "device_name": item.get("FriendlyName", "Unknown Device"),
                            "device_class": item.get("Class", ""),
                        }
        except subprocess.TimeoutExpired:
            logger.warning("USB device query timed out")
        except Exception as e:
            logger.debug(f"USB device query failed: {e}")

        return devices

    def _on_device_connected(self, device: dict) -> None:
        """Handle a newly connected USB device."""
        is_storage = self._is_storage_device(device)
        severity_note = " [STORAGE]" if is_storage else ""

        logger.info(
            f"USB device connected{severity_note}: {device['device_name']}",
            extra={"data": device}
        )

        if self._queue:
            self._queue.put_event(EVENT_USB, {
                "device_name": device["device_name"],
                "device_id": device["device_id"],
                "action": "connected",
                "is_storage": is_storage,
                "timestamp": time.time(),
            }, priority=PRIORITY_HIGH if is_storage else PRIORITY_HIGH)

    def _on_device_removed(self, device: dict) -> None:
        """Handle a removed USB device."""
        logger.info(f"USB device removed: {device['device_name']}")

        if self._queue:
            self._queue.put_event(EVENT_USB, {
                "device_name": device["device_name"],
                "device_id": device["device_id"],
                "action": "disconnected",
                "is_storage": False,
                "timestamp": time.time(),
            })

    @staticmethod
    def _is_storage_device(device: dict) -> bool:
        """Check if a USB device is a storage device."""
        name = device.get("device_name", "").lower()
        dev_class = device.get("device_class", "").lower()
        dev_id = device.get("device_id", "").lower()

        storage_indicators = [
            "mass storage", "disk drive", "usb flash",
            "thumb drive", "removable", "portable",
            "kingston", "sandisk", "samsung",
        ]
        storage_classes = ["diskdrive", "wpd"]

        if dev_class in storage_classes:
            return True
        return any(ind in name for ind in storage_indicators)

    def get_current_devices(self) -> list[dict]:
        """Get currently connected USB devices (for testing/API)."""
        devices = self._get_usb_devices()
        return list(devices.values())
