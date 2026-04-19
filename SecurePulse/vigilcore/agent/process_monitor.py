"""
SecurePulse EDR - Process Monitor
Monitors running processes using psutil, flags suspicious activity.
"""

import logging
import time
from typing import Callable, List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger("ProcessMonitor")


def _get_proc_info(proc) -> Optional[dict]:
    """Safely extract process info from a psutil Process object."""
    try:
        info = proc.as_dict(
            attrs=["pid", "name", "cmdline", "username", "status",
                   "cpu_percent", "memory_percent", "create_time"]
        )
        # Filter out zombie / dead processes
        if info.get("status") in ("zombie", "dead"):
            return None
        info["cmdline"] = info.get("cmdline") or []
        return info
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


class ProcessMonitor:
    def __init__(self, detection_engine, interval: int = 5):
        self.engine   = detection_engine
        self.interval = interval
        self.running  = False
        self._seen_pids = set()

        if not PSUTIL_AVAILABLE:
            logger.error("psutil not installed — ProcessMonitor disabled.")

    # ── Public API ──────────────────────────────────────────────────────────
    def scan_once(self) -> List[dict]:
        """Single scan of all running processes. Returns list of alerts."""
        if not PSUTIL_AVAILABLE:
            return []

        all_alerts = []
        for proc in psutil.process_iter():
            info = _get_proc_info(proc)
            if info is None:
                continue
            alerts = self.engine.analyze_process(info)
            all_alerts.extend(alerts)

        logger.info("Process scan complete — %d processes checked, %d alerts",
                    len(list(psutil.process_iter())), len(all_alerts))
        return all_alerts

    def scan_new_processes(self) -> List[dict]:
        """Only scan newly spawned processes since last call."""
        if not PSUTIL_AVAILABLE:
            return []

        all_alerts = []
        current_pids = set()

        for proc in psutil.process_iter():
            info = _get_proc_info(proc)
            if info is None:
                continue
            pid = info["pid"]
            current_pids.add(pid)

            if pid not in self._seen_pids:
                alerts = self.engine.analyze_process(info)
                all_alerts.extend(alerts)
                if alerts:
                    logger.info("New suspicious process detected: PID=%d name=%s",
                                pid, info.get("name"))

        self._seen_pids = current_pids
        return all_alerts

    def run_continuous(self, callback: Optional[Callable] = None):
        """Continuously monitor processes every `interval` seconds."""
        if not PSUTIL_AVAILABLE:
            logger.error("psutil not available. Cannot start ProcessMonitor.")
            return

        self.running = True
        logger.info("ProcessMonitor started (interval=%ds)", self.interval)

        try:
            while self.running:
                alerts = self.scan_new_processes()
                if callback and alerts:
                    callback(alerts)
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.running = False
            logger.info("ProcessMonitor stopped.")

    def stop(self):
        self.running = False

    # ── Static helpers ──────────────────────────────────────────────────────
    @staticmethod
    def list_all_processes() -> List[dict]:
        """Return all running processes as list of dicts."""
        if not PSUTIL_AVAILABLE:
            return []
        result = []
        for proc in psutil.process_iter():
            info = _get_proc_info(proc)
            if info:
                result.append(info)
        return result

    @staticmethod
    def get_high_cpu_processes(threshold: float = 50.0) -> List[dict]:
        """Return processes consuming more than `threshold`% CPU."""
        if not PSUTIL_AVAILABLE:
            return []
        result = []
        for proc in psutil.process_iter():
            info = _get_proc_info(proc)
            if info and (info.get("cpu_percent") or 0) > threshold:
                result.append(info)
        return result
