"""
SecurePulse EDR - File Monitor
Uses watchdog to detect suspicious file system activity including
ransomware-like bulk modifications and sensitive file access.
"""

import logging
import os
import time
from collections import deque
from typing import List, Optional

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    FileSystemEventHandler = object   # fallback base class

logger = logging.getLogger("FileMonitor")

# Sliding window to track modification rate
MODIFICATION_WINDOW = 10   # seconds
RANSOMWARE_THRESHOLD = 20  # files modified within the window


class _EDREventHandler(FileSystemEventHandler):
    """Internal watchdog event handler wired to the detection engine."""

    def __init__(self, detection_engine):
        super().__init__()
        self.engine = detection_engine
        self._mod_timestamps: deque = deque()   # timestamps of recent modifications

    # ── watchdog callbacks ──────────────────────────────────────────────────
    def on_created(self, event: "FileSystemEvent"):
        if not event.is_directory:
            self._handle_event(event.src_path, "created")

    def on_modified(self, event: "FileSystemEvent"):
        if not event.is_directory:
            self._handle_event(event.src_path, "modified")
            self._check_ransomware_pattern()

    def on_deleted(self, event: "FileSystemEvent"):
        if not event.is_directory:
            self._handle_event(event.src_path, "deleted")

    def on_moved(self, event: "FileSystemEvent"):
        if not event.is_directory:
            self._handle_event(event.dest_path, "moved")

    # ── Internal ────────────────────────────────────────────────────────────
    def _handle_event(self, path: str, event_type: str):
        ext = os.path.splitext(path)[1].lower()
        ev  = {"path": path, "event_type": event_type, "extension": ext}
        self.engine.analyze_file_event(ev)

    def _check_ransomware_pattern(self):
        now = time.time()
        self._mod_timestamps.append(now)

        # Prune old timestamps outside the window
        while self._mod_timestamps and (now - self._mod_timestamps[0]) > MODIFICATION_WINDOW:
            self._mod_timestamps.popleft()

        count = len(self._mod_timestamps)
        if count >= RANSOMWARE_THRESHOLD:
            self.engine.analyze_ransomware_behavior(count, MODIFICATION_WINDOW)
            self._mod_timestamps.clear()   # reset after alert


class FileMonitor:
    def __init__(self, detection_engine, watch_paths: Optional[List[str]] = None, interval: int = 2):
        self.engine      = detection_engine
        self.watch_paths = watch_paths or ["/tmp", "/home", "/var/www"]
        self.interval    = interval
        self._observer: Optional["Observer"] = None

        if not WATCHDOG_AVAILABLE:
            logger.error("watchdog not installed — FileMonitor disabled.")

    # ── Public API ──────────────────────────────────────────────────────────
    def start(self):
        if not WATCHDOG_AVAILABLE:
            logger.error("watchdog not available. FileMonitor not started.")
            return

        handler  = _EDREventHandler(self.engine)
        self._observer = Observer()

        for path in self.watch_paths:
            if os.path.exists(path):
                self._observer.schedule(handler, path, recursive=True)
                logger.info("FileMonitor watching: %s", path)
            else:
                logger.warning("Watch path does not exist (skipping): %s", path)

        self._observer.start()
        logger.info("FileMonitor started — watching %d path(s)", len(self.watch_paths))

    def stop(self):
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join()
            logger.info("FileMonitor stopped.")

    def run_continuous(self):
        """Start and block until keyboard interrupt."""
        self.start()
        try:
            while True:
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.stop()

    # ── Snapshot helper ─────────────────────────────────────────────────────
    @staticmethod
    def scan_directory_once(path: str, detection_engine) -> List[dict]:
        """
        One-shot scan of a directory; reports existing suspicious files.
        Useful for on-demand checks without the observer running.
        """
        if not os.path.exists(path):
            return []

        all_alerts = []
        for root, _, files in os.walk(path):
            for fname in files:
                fpath = os.path.join(root, fname)
                ext   = os.path.splitext(fname)[1].lower()
                ev    = {"path": fpath, "event_type": "existing", "extension": ext}
                alerts = detection_engine.analyze_file_event(ev)
                all_alerts.extend(alerts)

        return all_alerts
