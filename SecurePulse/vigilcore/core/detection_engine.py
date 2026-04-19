"""
SecurePulse EDR - Detection Engine
Central rule-based detection engine. Loads YAML rules, evaluates events,
correlates across modules, and dispatches alerts.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional

import yaml

from vigilcore.core.alert_manager import AlertManager

logger = logging.getLogger("DetectionEngine")

# ─── Config Paths ─────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_PATH  = os.path.join(BASE_DIR, "config", "detection_rules.yaml")
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yaml")


def _load_yaml(path: str) -> dict:
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.error("Config file not found: %s", path)
        return {}
    except yaml.YAMLError as e:
        logger.error("YAML parse error in %s: %s", path, e)
        return {}


# ─── Detection Engine ─────────────────────────────────────────────────────────
class DetectionEngine:
    def __init__(self, alert_manager: Optional[AlertManager] = None):
        self.rules   = _load_yaml(RULES_PATH)
        self.config  = _load_yaml(CONFIG_PATH)
        self.am      = alert_manager or AlertManager(
            self.config.get("system", {}).get("alert_log", "vigilcore/logs/alerts.json")
        )
        logger.info("DetectionEngine initialised — rules loaded from %s", RULES_PATH)

    # ══════════════════════════════════════════════════════════════════════════
    # PROCESS DETECTION
    # ══════════════════════════════════════════════════════════════════════════
    def analyze_process(self, proc_info: Dict[str, Any]) -> List[dict]:
        """
        proc_info expected keys:
          pid, name, cmdline, username, connections, cpu_percent, memory_percent
        """
        alerts = []
        name    = (proc_info.get("name")    or "").lower()
        cmdline = " ".join(proc_info.get("cmdline") or []).lower()

        for rule in self.rules.get("process_rules", []):
            matched = None
            for pattern in rule.get("patterns", []):
                p = pattern.lower()
                if p in name or p in cmdline:
                    matched = pattern
                    break

            if matched:
                alert = self.am.create_alert(
                    rule_id        = rule["id"],
                    rule_name      = rule["name"],
                    severity       = rule["severity"],
                    risk_score     = rule["risk_score"],
                    description    = rule["description"],
                    source_module  = "ProcessMonitor",
                    mitre_tactic   = rule.get("mitre_tactic", "Unknown"),
                    mitre_technique= rule.get("mitre_technique", "Unknown"),
                    details={
                        "pid":          proc_info.get("pid"),
                        "name":         proc_info.get("name"),
                        "cmdline":      cmdline,
                        "username":     proc_info.get("username"),
                        "matched_rule": matched,
                    },
                )
                alerts.append(alert.to_dict())

        return alerts

    # ══════════════════════════════════════════════════════════════════════════
    # NETWORK DETECTION
    # ══════════════════════════════════════════════════════════════════════════
    def analyze_network(self, connection: Dict[str, Any]) -> List[dict]:
        """
        connection expected keys:
          local_address, remote_address, local_port, remote_port, status, pid
        """
        alerts = []
        remote_port = connection.get("remote_port", 0)
        local_port  = connection.get("local_port", 0)

        for rule in self.rules.get("network_rules", []):
            if rule["id"] == "NET-001":
                suspicious = rule.get("suspicious_ports", [])
                if remote_port in suspicious or local_port in suspicious:
                    alerts.append(self.am.create_alert(
                        rule_id        = rule["id"],
                        rule_name      = rule["name"],
                        severity       = rule["severity"],
                        risk_score     = rule["risk_score"],
                        description    = rule["description"],
                        source_module  = "NetworkMonitor",
                        mitre_tactic   = rule.get("mitre_tactic", "Unknown"),
                        mitre_technique= rule.get("mitre_technique", "Unknown"),
                        details={
                            "local":        f"{connection.get('local_address')}:{local_port}",
                            "remote":       f"{connection.get('remote_address')}:{remote_port}",
                            "status":       connection.get("status"),
                            "pid":          connection.get("pid"),
                            "flagged_port": remote_port if remote_port in suspicious else local_port,
                        },
                    ).to_dict())

        return alerts

    # ══════════════════════════════════════════════════════════════════════════
    # FILE DETECTION
    # ══════════════════════════════════════════════════════════════════════════
    def analyze_file_event(self, event: Dict[str, Any]) -> List[dict]:
        """
        event expected keys:
          path, event_type (created/modified/deleted), extension
        """
        alerts = []
        path      = event.get("path", "")
        ext       = os.path.splitext(path)[1].lower()
        evt_type  = event.get("event_type", "")

        for rule in self.rules.get("file_rules", []):
            if rule["id"] == "FILE-001":
                if ext in [e.lower() for e in rule.get("suspicious_extensions", [])]:
                    alerts.append(self.am.create_alert(
                        rule_id        = rule["id"],
                        rule_name      = rule["name"],
                        severity       = rule["severity"],
                        risk_score     = rule["risk_score"],
                        description    = rule["description"],
                        source_module  = "FileMonitor",
                        mitre_tactic   = rule.get("mitre_tactic", "Unknown"),
                        mitre_technique= rule.get("mitre_technique", "Unknown"),
                        details={"path": path, "event_type": evt_type, "extension": ext},
                    ).to_dict())

            elif rule["id"] == "FILE-002":
                for sensitive in rule.get("sensitive_paths", []):
                    if sensitive in path:
                        alerts.append(self.am.create_alert(
                            rule_id        = rule["id"],
                            rule_name      = rule["name"],
                            severity       = rule["severity"],
                            risk_score     = rule["risk_score"],
                            description    = rule["description"],
                            source_module  = "FileMonitor",
                            mitre_tactic   = rule.get("mitre_tactic", "Unknown"),
                            mitre_technique= rule.get("mitre_technique", "Unknown"),
                            details={"path": path, "event_type": evt_type, "sensitive_match": sensitive},
                        ).to_dict())
                        break

            elif rule["id"] == "FILE-003":
                watch_dirs = rule.get("watch_dirs", [])
                susp_exts  = [e.lower() for e in rule.get("suspicious_extensions", [])]
                in_watch   = any(path.startswith(d) for d in watch_dirs)
                if in_watch and ext in susp_exts and evt_type == "created":
                    alerts.append(self.am.create_alert(
                        rule_id        = rule["id"],
                        rule_name      = rule["name"],
                        severity       = rule["severity"],
                        risk_score     = rule["risk_score"],
                        description    = rule["description"],
                        source_module  = "FileMonitor",
                        mitre_tactic   = rule.get("mitre_tactic", "Unknown"),
                        mitre_technique= rule.get("mitre_technique", "Unknown"),
                        details={"path": path, "event_type": evt_type, "extension": ext},
                    ).to_dict())

        return alerts

    def analyze_ransomware_behavior(self, file_count: int, time_window: float) -> List[dict]:
        """Detect rapid bulk file modification (ransomware pattern)."""
        alerts = []
        for rule in self.rules.get("file_rules", []):
            if rule["id"] == "FILE-001":
                threshold = rule.get("threshold", 20)
                if file_count >= threshold:
                    alerts.append(self.am.create_alert(
                        rule_id        = rule["id"],
                        rule_name      = rule["name"],
                        severity       = "CRITICAL",
                        risk_score     = 97,
                        description    = f"Rapid mass file modification detected — {file_count} files in {time_window:.1f}s",
                        source_module  = "FileMonitor",
                        mitre_tactic   = rule.get("mitre_tactic", "Impact"),
                        mitre_technique= rule.get("mitre_technique", "T1486"),
                        details={
                            "files_modified": file_count,
                            "time_window_seconds": time_window,
                            "pattern": "Ransomware-like bulk modification",
                        },
                    ).to_dict())
        return alerts

    # ══════════════════════════════════════════════════════════════════════════
    # PORT DETECTION
    # ══════════════════════════════════════════════════════════════════════════
    def analyze_open_port(self, port: int) -> List[dict]:
        """Flag ports not in the allowed list."""
        alerts = []
        for rule in self.rules.get("port_rules", []):
            if rule["id"] == "PORT-001":
                allowed = rule.get("allowed_ports", [])
                if port not in allowed:
                    alerts.append(self.am.create_alert(
                        rule_id        = rule["id"],
                        rule_name      = rule["name"],
                        severity       = rule["severity"],
                        risk_score     = rule["risk_score"],
                        description    = rule["description"],
                        source_module  = "PortScanner",
                        mitre_tactic   = rule.get("mitre_tactic", "Unknown"),
                        mitre_technique= rule.get("mitre_technique", "Unknown"),
                        details={
                            "open_port":    port,
                            "allowed_ports": allowed,
                            "note": "Port not in whitelist",
                        },
                    ).to_dict())
        return alerts

    # ══════════════════════════════════════════════════════════════════════════
    # LOG DETECTION
    # ══════════════════════════════════════════════════════════════════════════
    def analyze_log_line(self, line: str, source_file: str) -> List[dict]:
        """Apply log rules to a single log line."""
        alerts = []

        for rule in self.rules.get("log_rules", []):
            if rule["id"] in ("LOG-001", "LOG-002", "LOG-004"):
                for pattern in rule.get("patterns", []):
                    if pattern.lower() in line.lower():
                        alerts.append(self.am.create_alert(
                            rule_id        = rule["id"],
                            rule_name      = rule["name"],
                            severity       = rule["severity"],
                            risk_score     = rule["risk_score"],
                            description    = rule["description"],
                            source_module  = "LogAnalyzer",
                            mitre_tactic   = rule.get("mitre_tactic", "Unknown"),
                            mitre_technique= rule.get("mitre_technique", "Unknown"),
                            details={
                                "matched_pattern": pattern,
                                "log_line":  line.strip()[:300],
                                "log_source": source_file,
                            },
                        ).to_dict())
                        break   # one alert per rule per line

        return alerts

    def analyze_brute_force(self, failure_count: int, source_ip: str, log_file: str) -> List[dict]:
        """Detect brute-force based on failure count."""
        alerts = []
        for rule in self.rules.get("log_rules", []):
            if rule["id"] == "LOG-003":
                threshold = rule.get("threshold", 5)
                if failure_count >= threshold:
                    alerts.append(self.am.create_alert(
                        rule_id        = rule["id"],
                        rule_name      = rule["name"],
                        severity       = rule["severity"],
                        risk_score     = rule["risk_score"],
                        description    = f"Brute-force detected: {failure_count} failed logins from {source_ip}",
                        source_module  = "LogAnalyzer",
                        mitre_tactic   = rule.get("mitre_tactic", "Credential Access"),
                        mitre_technique= rule.get("mitre_technique", "T1110"),
                        details={
                            "failure_count": failure_count,
                            "source_ip":    source_ip,
                            "log_file":     log_file,
                        },
                    ).to_dict())
        return alerts
