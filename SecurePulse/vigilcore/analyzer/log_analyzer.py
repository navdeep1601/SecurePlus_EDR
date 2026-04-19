"""
SecurePulse EDR - Log Analyzer
Parses auth.log, Apache access logs, and syslog to detect:
  - SQL injection attempts
  - XSS payloads
  - Brute-force login attacks
  - Directory traversal
"""

import logging
import os
import re
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("LogAnalyzer")

# Regex to extract IP from common log formats
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Brute-force tracking: ip → list of timestamps
_brute_tracker: Dict[str, List[float]] = defaultdict(list)

BRUTE_THRESHOLD  = 5
BRUTE_WINDOW_SEC = 60.0


class LogAnalyzer:
    def __init__(
        self,
        detection_engine,
        log_files: Optional[List[str]] = None,
        interval: int = 30,
    ):
        self.engine    = detection_engine
        self.log_files = log_files or [
            "/var/log/auth.log",
            "/var/log/apache2/access.log",
            "/var/log/syslog",
        ]
        self.interval  = interval
        self.running   = False

        # Track file positions so we only read new lines (tail behaviour)
        self._positions: Dict[str, int] = {}

    # ── Public API ──────────────────────────────────────────────────────────
    def analyze_file(self, path: str) -> List[dict]:
        """
        Read new lines from `path` since last call.
        Returns list of alert dicts.
        """
        if not os.path.exists(path):
            logger.debug("Log file not found: %s", path)
            return []

        all_alerts: List[dict] = []
        last_pos = self._positions.get(path, 0)

        try:
            with open(path, "r", errors="replace") as f:
                f.seek(last_pos)
                lines = f.readlines()
                self._positions[path] = f.tell()
        except PermissionError:
            logger.warning("Permission denied reading log: %s", path)
            return []
        except OSError as e:
            logger.error("Cannot read log %s: %s", path, e)
            return []

        for line in lines:
            alerts = self._process_line(line, path)
            all_alerts.extend(alerts)

        if lines:
            logger.info("LogAnalyzer: %s — %d new line(s), %d alert(s)",
                        os.path.basename(path), len(lines), len(all_alerts))

        return all_alerts

    def analyze_all(self) -> List[dict]:
        """Analyze all configured log files in one pass."""
        combined: List[dict] = []
        for path in self.log_files:
            combined.extend(self.analyze_file(path))
        return combined

    def analyze_string(self, content: str, source: str = "inline") -> List[dict]:
        """
        Analyze an arbitrary string (e.g. from sample data / tests).
        Each line is processed independently.
        """
        all_alerts: List[dict] = []
        for line in content.splitlines():
            all_alerts.extend(self._process_line(line + "\n", source))
        return all_alerts

    def run_continuous(self):
        """Tail all log files continuously."""
        self.running = True
        logger.info("LogAnalyzer started (interval=%ds)", self.interval)

        # Seek to end of existing files so we only catch new entries
        for path in self.log_files:
            if os.path.exists(path):
                try:
                    with open(path, "r", errors="replace") as f:
                        f.seek(0, 2)          # seek to end
                        self._positions[path] = f.tell()
                except OSError:
                    pass

        try:
            while self.running:
                self.analyze_all()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.running = False
            logger.info("LogAnalyzer stopped.")

    def stop(self):
        self.running = False

    # ── Internal ────────────────────────────────────────────────────────────
    def _process_line(self, line: str, source: str) -> List[dict]:
        alerts: List[dict] = []

        # 1. General pattern rules (SQLi, XSS, traversal)
        pattern_alerts = self.engine.analyze_log_line(line, source)
        alerts.extend(pattern_alerts)

        # 2. Brute-force detection
        bf_alert = self._check_brute_force(line, source)
        if bf_alert:
            alerts.extend(bf_alert)

        return alerts

    def _check_brute_force(self, line: str, source: str) -> List[dict]:
        """Track failure patterns per IP and alert on threshold breach."""
        failure_indicators = [
            "Failed password",
            "authentication failure",
            "Invalid user",
            "Failed login",
            "FAILED LOGIN",
            "incorrect password",
        ]

        matched = any(indicator.lower() in line.lower() for indicator in failure_indicators)
        if not matched:
            return []

        # Extract source IP
        ips = _IP_RE.findall(line)
        ip  = ips[0] if ips else "unknown"

        now = time.time()
        _brute_tracker[ip].append(now)

        # Prune timestamps outside window
        _brute_tracker[ip] = [
            ts for ts in _brute_tracker[ip]
            if (now - ts) <= BRUTE_WINDOW_SEC
        ]

        count = len(_brute_tracker[ip])
        if count >= BRUTE_THRESHOLD:
            alerts = self.engine.analyze_brute_force(count, ip, source)
            # Reset tracker for this IP after alerting
            _brute_tracker[ip] = []
            return alerts

        return []

    # ── Utility ─────────────────────────────────────────────────────────────
    @staticmethod
    def parse_apache_line(line: str) -> Optional[dict]:
        """
        Parse a Common Log Format / Combined Log Format Apache line.
        Returns dict or None if the line doesn't match.
        """
        pattern = re.compile(
            r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
            r'"(?P<method>\S+) (?P<path>\S+) \S+" '
            r'(?P<status>\d{3}) (?P<size>\S+)'
        )
        m = pattern.match(line.strip())
        if not m:
            return None
        return m.groupdict()

    @staticmethod
    def extract_ips(text: str) -> List[str]:
        return _IP_RE.findall(text)
