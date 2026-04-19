"""
SecurePulse EDR - Port Scanner
Scans localhost for open ports and flags unexpected ones against the whitelist.
"""

import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

logger = logging.getLogger("PortScanner")

DEFAULT_TIMEOUT = 0.5
MAX_WORKERS     = 100


def _check_port(host: str, port: int, timeout: float) -> Tuple[int, bool]:
    """Return (port, is_open) for a single port probe."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return port, result == 0
    except (socket.error, OSError):
        return port, False


class PortScanner:
    def __init__(
        self,
        detection_engine,
        target: str = "127.0.0.1",
        port_range: Tuple[int, int] = (1, 10000),
        interval: int = 60,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.engine     = detection_engine
        self.target     = target
        self.port_range = port_range
        self.interval   = interval
        self.timeout    = timeout
        self.running    = False
        self._last_open: List[int] = []

    # ── Public API ──────────────────────────────────────────────────────────
    def scan_once(self) -> List[int]:
        """
        Scan the full port range using a thread pool.
        Returns list of open port numbers.
        """
        start_port, end_port = self.port_range
        total  = end_port - start_port + 1
        open_ports: List[int] = []

        logger.info("PortScanner: scanning %s ports %d–%d …", self.target, start_port, end_port)
        t0 = time.time()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(_check_port, self.target, p, self.timeout): p
                for p in range(start_port, end_port + 1)
            }
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)

        elapsed = time.time() - t0
        open_ports.sort()
        logger.info(
            "PortScanner: found %d open port(s) in %.1fs — %s",
            len(open_ports), elapsed, open_ports,
        )
        return open_ports

    def analyze_ports(self, open_ports: List[int]) -> List[dict]:
        """Run detection engine against each open port. Returns alert dicts."""
        all_alerts = []
        for port in open_ports:
            alerts = self.engine.analyze_open_port(port)
            all_alerts.extend(alerts)
        return all_alerts

    def run_once_and_analyze(self) -> List[dict]:
        """Convenience: scan + analyze in one call."""
        open_ports = self.scan_once()
        self._last_open = open_ports
        return self.analyze_ports(open_ports)

    def run_continuous(self):
        """Periodically scan and report new open ports."""
        self.running = True
        logger.info("PortScanner started (interval=%ds, range=%d-%d)",
                    self.interval, *self.port_range)
        try:
            while self.running:
                self.run_once_and_analyze()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.running = False
            logger.info("PortScanner stopped.")

    def stop(self):
        self.running = False

    # ── Helpers ─────────────────────────────────────────────────────────────
    @property
    def last_open_ports(self) -> List[int]:
        return self._last_open

    @staticmethod
    def quick_check(host: str, port: int, timeout: float = 1.0) -> bool:
        """Quick single-port reachability check."""
        _, is_open = _check_port(host, port, timeout)
        return is_open
