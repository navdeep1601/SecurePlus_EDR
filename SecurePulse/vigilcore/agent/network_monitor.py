"""
SecurePulse EDR - Network Monitor
Monitors active network connections using psutil and flags suspicious ports
and unknown external IP connections.
"""

import logging
import socket
import time
from typing import List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger("NetworkMonitor")

# RFC-1918 private ranges (not "external")
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "::1", "0.0.0.0")


def _is_external(ip: str) -> bool:
    return bool(ip) and not any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def _get_connections() -> List[dict]:
    """Return all active TCP/UDP connections as dicts."""
    if not PSUTIL_AVAILABLE:
        return []

    result = []
    try:
        for conn in psutil.net_connections(kind="all"):
            laddr = conn.laddr
            raddr = conn.raddr if conn.raddr else None
            result.append({
                "pid":            conn.pid,
                "status":         conn.status,
                "local_address":  laddr.ip  if laddr else "",
                "local_port":     laddr.port if laddr else 0,
                "remote_address": raddr.ip  if raddr else "",
                "remote_port":    raddr.port if raddr else 0,
                "type":           conn.type.name if hasattr(conn.type, "name") else str(conn.type),
            })
    except (psutil.AccessDenied, AttributeError) as e:
        logger.warning("Could not list connections (may need root): %s", e)
    return result


class NetworkMonitor:
    def __init__(self, detection_engine, interval: int = 10):
        self.engine   = detection_engine
        self.interval = interval
        self.running  = False
        self._seen    = set()   # (local_port, remote_address, remote_port) tuples

        if not PSUTIL_AVAILABLE:
            logger.error("psutil not installed — NetworkMonitor disabled.")

    # ── Public API ──────────────────────────────────────────────────────────
    def scan_once(self) -> List[dict]:
        """Single scan of active connections. Returns list of alert dicts."""
        connections = _get_connections()
        all_alerts  = []

        for conn in connections:
            key = (conn["local_port"], conn["remote_address"], conn["remote_port"])
            if key in self._seen:
                continue
            self._seen.add(key)

            alerts = self.engine.analyze_network(conn)
            all_alerts.extend(alerts)

            if _is_external(conn["remote_address"]) and conn["remote_address"]:
                logger.info(
                    "External connection: %s:%d → %s:%d [%s]",
                    conn["local_address"], conn["local_port"],
                    conn["remote_address"], conn["remote_port"],
                    conn["status"],
                )

        return all_alerts

    def run_continuous(self):
        """Continuously monitor connections every `interval` seconds."""
        if not PSUTIL_AVAILABLE:
            logger.error("psutil not available. Cannot start NetworkMonitor.")
            return

        self.running = True
        logger.info("NetworkMonitor started (interval=%ds)", self.interval)

        try:
            while self.running:
                self.scan_once()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.running = False
            logger.info("NetworkMonitor stopped.")

    def stop(self):
        self.running = False

    # ── Static helpers ──────────────────────────────────────────────────────
    @staticmethod
    def get_all_connections() -> List[dict]:
        return _get_connections()

    @staticmethod
    def get_external_connections() -> List[dict]:
        return [c for c in _get_connections() if _is_external(c["remote_address"])]

    @staticmethod
    def get_listening_ports() -> List[int]:
        """Return all locally listening ports."""
        return [c["local_port"] for c in _get_connections() if c["status"] == "LISTEN"]

    @staticmethod
    def get_hostname() -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"
