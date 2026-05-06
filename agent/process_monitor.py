"""
Shadow Guardian — Process Monitor

Adaptive-polling process monitor with network activity tracking.
Uses Scapy for packet-level inspection when available, falls back
to psutil connection snapshots.
"""

import threading
import time
from typing import Optional
from collections import defaultdict

from utils.logger import get_logger
from utils.config import get_config
from core.event_queue import EventQueue, EVENT_PROCESS, EVENT_NETWORK, PRIORITY_NORMAL

logger = get_logger("agent.process_monitor")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.error("psutil not installed — process monitoring disabled")

# Attempt Scapy import for packet-level capture
try:
    from scapy.all import sniff, IP, TCP, UDP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logger.info("Scapy not available — using psutil connection snapshots")


class ProcessMonitor:
    """
    Monitors running processes and network activity.

    Uses adaptive polling:
        - Active state (recent foreground changes): poll every 5s
        - Idle state (no activity for 2 min): poll every 30s

    Network monitoring:
        - Scapy packet capture when available (production-grade)
        - Falls back to psutil connection snapshots
    """

    def __init__(self, event_queue: EventQueue):
        self._queue = event_queue
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sniffer_thread: Optional[threading.Thread] = None

        # Process tracking state
        self._known_pids: set[int] = set()
        self._last_activity_time: float = time.time()

        # Network tracking state
        self._connection_counts: dict[int, int] = defaultdict(int)
        self._packet_counts: dict[str, int] = defaultdict(int)
        self._scapy_failed = False

        # Config
        config = get_config()
        polling = config.get("adaptive_polling", {})
        self._active_interval = polling.get("active_interval", 5)
        self._idle_interval = polling.get("idle_interval", 30)
        self._idle_threshold = polling.get("idle_threshold", 120)
        self._network_enabled = config.get("feature_flags.network_monitoring", True)

    def start(self) -> None:
        """Start process monitoring thread."""
        if not HAS_PSUTIL:
            logger.error("Cannot start process monitor without psutil")
            return

        self._running.set()

        # Start polling thread
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="ProcessMonitor",
            daemon=True,
        )
        self._thread.start()

        # Start packet sniffer if available and enabled
        if self._network_enabled and HAS_SCAPY:
            self._sniffer_thread = threading.Thread(
                target=self._packet_sniffer,
                name="PacketSniffer",
                daemon=True,
            )
            self._sniffer_thread.start()
            logger.info("Packet-level network monitoring started (Scapy)")
        elif self._network_enabled:
            logger.info("Network monitoring: psutil connection snapshots")

        logger.info("Process monitor started")

    def stop(self) -> None:
        """Stop process monitoring."""
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=5.0)
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=2.0)
        logger.info("Process monitor stopped")

    def notify_activity(self) -> None:
        """Notify the monitor of user activity (resets idle timer)."""
        self._last_activity_time = time.time()

    def _get_poll_interval(self) -> float:
        """Determine polling interval based on activity state."""
        idle_time = time.time() - self._last_activity_time
        if idle_time > self._idle_threshold:
            return self._idle_interval
        return self._active_interval

    def _monitor_loop(self) -> None:
        """Main monitoring loop with adaptive polling."""
        # Take initial snapshot in background thread
        self._snapshot_processes(initial=True)
        
        while self._running.is_set():
            try:
                interval = self._get_poll_interval()
                self._snapshot_processes()

                # Also snapshot connections if Scapy isn't running
                if self._network_enabled and (not HAS_SCAPY or self._scapy_failed):
                    self._snapshot_connections()

            except Exception as e:
                logger.error(f"Process monitor error: {e}")

            # Sleep in small increments for responsive shutdown
            deadline = time.time() + interval
            while time.time() < deadline and self._running.is_set():
                time.sleep(0.5)

    def _snapshot_processes(self, initial: bool = False) -> None:
        """Take a snapshot of running processes and detect new ones."""
        current_pids = set()
        new_processes = []

        try:
            # OPTIMIZATION: Only fetch 'pid' and 'create_time' initially (takes ~2ms vs ~3.25s)
            for proc in psutil.process_iter(['pid', 'create_time']):
                try:
                    info = proc.info
                    pid = info['pid']
                    create_time = info.get('create_time', 0)
                    
                    current_pids.add(pid)

                    if not initial and pid not in self._known_pids:
                        # NEW PROCESS: Only now do we fetch the expensive attributes
                        try:
                            full_info = proc.as_dict(attrs=['name', 'exe', 'status', 'username'])
                            new_processes.append({
                                "pid": pid,
                                "process_name": full_info.get('name', ''),
                                "exe_path": full_info.get('exe', '') or '',
                                "status": full_info.get('status', ''),
                                "create_time": create_time,
                                "username": full_info.get('username', '') or '',
                                "timestamp": time.time(),
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Detect terminated processes
            terminated = self._known_pids - current_pids
            self._known_pids = current_pids

            # Emit events for new processes
            for proc_data in new_processes:
                self._queue.put_event(EVENT_PROCESS, proc_data)

            if new_processes and not initial:
                logger.debug(f"Detected {len(new_processes)} new processes, "
                           f"{len(terminated)} terminated")

        except Exception as e:
            logger.error(f"Process snapshot error: {e}")

    def _snapshot_connections(self) -> None:
        """Snapshot network connections per process using psutil."""
        try:
            connections = psutil.net_connections(kind='inet')
            per_process: dict[int, list] = defaultdict(list)

            for conn in connections:
                if conn.pid and conn.status == 'ESTABLISHED':
                    per_process[conn.pid].append({
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                    })

            for pid, conns in per_process.items():
                if len(conns) != self._connection_counts.get(pid, 0):
                    self._connection_counts[pid] = len(conns)

                    if len(conns) > 0:
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                        except Exception:
                            proc_name = f"PID:{pid}"

                        self._queue.put_event(EVENT_NETWORK, {
                            "pid": pid,
                            "process_name": proc_name,
                            "connection_count": len(conns),
                            "connections": conns[:10],  # Limit detail
                            "timestamp": time.time(),
                        })

        except Exception as e:
            logger.error(f"Connection snapshot error: {e}")

    def _packet_sniffer(self) -> None:
        """Capture packets using Scapy for production-grade network monitoring."""
        if not HAS_SCAPY:
            return

        def _process_packet(packet):
            if not self._running.is_set():
                return

            try:
                if IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
                    proto = "TCP" if TCP in packet else ("UDP" if UDP in packet else "OTHER")

                    key = f"{dst}:{proto}"
                    self._packet_counts[key] += 1

                    # Emit events periodically (not per-packet)
                    if self._packet_counts[key] % 50 == 0:
                        self._queue.put_event(EVENT_NETWORK, {
                            "type": "packet_stats",
                            "destination": dst,
                            "protocol": proto,
                            "packet_count": self._packet_counts[key],
                            "timestamp": time.time(),
                        })
            except Exception:
                pass

        try:
            logger.info("Starting Scapy packet sniffer")
            while self._running.is_set():
                sniff(
                    prn=_process_packet,
                    store=False,
                    stop_filter=lambda _: not self._running.is_set(),
                    timeout=300,
                )
        except Exception as e:
            logger.error(f"Packet sniffer error: {e}")
            logger.info("Falling back to psutil connection monitoring")
            self._scapy_failed = True

    @property
    def known_process_count(self) -> int:
        return len(self._known_pids)

    @property
    def is_idle(self) -> bool:
        return (time.time() - self._last_activity_time) > self._idle_threshold
