"""
SecurePulse EDR - Alert Manager
Handles alert creation, storage, severity management, and output formatting.
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ─── Constants ────────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "green",
}

SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
}

console = Console() if RICH_AVAILABLE else None


# ─── Alert Model ──────────────────────────────────────────────────────────────
class Alert:
    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        risk_score: int,
        description: str,
        source_module: str,
        details: dict,
        mitre_tactic: str = "Unknown",
        mitre_technique: str = "Unknown",
    ):
        self.alert_id       = str(uuid.uuid4())[:8].upper()
        self.rule_id        = rule_id
        self.rule_name      = rule_name
        self.severity       = severity.upper()
        self.risk_score     = risk_score
        self.description    = description
        self.source_module  = source_module
        self.details        = details
        self.mitre_tactic   = mitre_tactic
        self.mitre_technique = mitre_technique
        self.timestamp      = datetime.now().isoformat()
        self.epoch          = time.time()

    def to_dict(self) -> dict:
        return {
            "alert_id":        self.alert_id,
            "rule_id":         self.rule_id,
            "rule_name":       self.rule_name,
            "severity":        self.severity,
            "risk_score":      self.risk_score,
            "description":     self.description,
            "source_module":   self.source_module,
            "mitre_tactic":    self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "timestamp":       self.timestamp,
            "details":         self.details,
        }

    def __repr__(self):
        return f"<Alert [{self.severity}] {self.rule_name} @ {self.timestamp}>"


# ─── Alert Manager ────────────────────────────────────────────────────────────
class AlertManager:
    def __init__(self, alert_log_path: str = "vigilcore/logs/alerts.json"):
        self.alert_log_path = alert_log_path
        self.alerts: List[Alert] = []
        self._alert_counts: Dict[str, int] = defaultdict(int)  # for dedup
        self._logger = logging.getLogger("AlertManager")

        os.makedirs(os.path.dirname(alert_log_path), exist_ok=True)

        # Init / load existing alert log
        if not os.path.exists(alert_log_path):
            with open(alert_log_path, "w") as f:
                json.dump([], f)

        self._setup_file_logger()

    def _setup_file_logger(self):
        """Set up rotating alert log."""
        handler = logging.FileHandler("vigilcore/logs/securepulse.log")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))
        root = logging.getLogger()
        root.setLevel(logging.INFO)
        if not root.handlers:
            root.addHandler(handler)
            root.addHandler(logging.StreamHandler())

    # ── Public API ──────────────────────────────────────────────────────────
    def create_alert(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        risk_score: int,
        description: str,
        source_module: str,
        details: dict,
        mitre_tactic: str = "Unknown",
        mitre_technique: str = "Unknown",
    ) -> Alert:
        alert = Alert(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            risk_score=risk_score,
            description=description,
            source_module=source_module,
            details=details,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
        )

        self.alerts.append(alert)
        self._alert_counts[rule_id] += 1
        self._persist_alert(alert)
        self._print_alert(alert)
        self._logger.warning(
            "[%s] %s | Rule: %s | Score: %d | %s",
            alert.severity, alert.rule_name, alert.rule_id,
            alert.risk_score, alert.description,
        )
        return alert

    def get_all_alerts(self) -> List[dict]:
        return [a.to_dict() for a in self.alerts]

    def get_alerts_by_severity(self, severity: str) -> List[dict]:
        return [a.to_dict() for a in self.alerts if a.severity == severity.upper()]

    def get_summary(self) -> dict:
        summary: Dict[str, int] = defaultdict(int)
        for a in self.alerts:
            summary[a.severity] += 1
        return dict(summary)

    def export_json(self, path: Optional[str] = None) -> str:
        out_path = path or self.alert_log_path
        with open(out_path, "w") as f:
            json.dump([a.to_dict() for a in self.alerts], f, indent=2)
        return out_path

    # ── Internal Helpers ────────────────────────────────────────────────────
    def _persist_alert(self, alert: Alert):
        """Append alert to JSON log file."""
        try:
            with open(self.alert_log_path, "r") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            existing = []

        existing.append(alert.to_dict())

        with open(self.alert_log_path, "w") as f:
            json.dump(existing, f, indent=2)

    def _print_alert(self, alert: Alert):
        """Pretty-print alert to terminal."""
        if RICH_AVAILABLE and console:
            self._rich_print(alert)
        else:
            self._plain_print(alert)

    def _rich_print(self, alert: Alert):
        color = SEVERITY_COLORS.get(alert.severity, "white")
        header = Text(f" ⚡ [{alert.severity}] {alert.rule_name} ", style=f"bold {color}")
        body = (
            f"[dim]ID:[/dim]          {alert.alert_id}\n"
            f"[dim]Rule:[/dim]        {alert.rule_id}\n"
            f"[dim]Module:[/dim]      {alert.source_module}\n"
            f"[dim]Risk Score:[/dim]  {alert.risk_score}/100\n"
            f"[dim]MITRE:[/dim]       {alert.mitre_tactic} | {alert.mitre_technique}\n"
            f"[dim]Description:[/dim] {alert.description}\n"
            f"[dim]Details:[/dim]     {json.dumps(alert.details, indent=2)}\n"
            f"[dim]Timestamp:[/dim]   {alert.timestamp}"
        )
        console.print(Panel(body, title=header, border_style=color))

    def _plain_print(self, alert: Alert):
        sep = "=" * 60
        print(f"\n{sep}")
        print(f"  ALERT [{alert.severity}] {alert.rule_name}")
        print(f"  ID: {alert.alert_id} | Rule: {alert.rule_id}")
        print(f"  Module: {alert.source_module} | Score: {alert.risk_score}/100")
        print(f"  MITRE: {alert.mitre_tactic} | {alert.mitre_technique}")
        print(f"  {alert.description}")
        print(f"  Details: {json.dumps(alert.details)}")
        print(f"  Time: {alert.timestamp}")
        print(sep)

    def print_summary_table(self):
        """Print a summary table of all alerts."""
        if not self.alerts:
            if RICH_AVAILABLE and console:
                console.print("[green]✅ No alerts generated.[/green]")
            else:
                print("No alerts generated.")
            return

        if RICH_AVAILABLE and console:
            table = Table(title="🛡  SecurePulse Alert Summary", show_lines=True)
            table.add_column("ID",         style="dim")
            table.add_column("Severity",   style="bold")
            table.add_column("Rule",       style="cyan")
            table.add_column("Module",     style="magenta")
            table.add_column("Score",      justify="right")
            table.add_column("MITRE",      style="yellow")
            table.add_column("Time",       style="dim")

            for a in sorted(self.alerts, key=lambda x: SEVERITY_RANK.get(x.severity, 0), reverse=True):
                color = SEVERITY_COLORS.get(a.severity, "white")
                table.add_row(
                    a.alert_id,
                    Text(a.severity, style=color),
                    a.rule_name,
                    a.source_module,
                    str(a.risk_score),
                    f"{a.mitre_tactic} / {a.mitre_technique}",
                    a.timestamp[11:19],
                )
            console.print(table)
        else:
            print("\n" + "=" * 80)
            print(" SECUREPULSE - ALERT SUMMARY")
            print("=" * 80)
            for a in self.alerts:
                print(f"  [{a.severity:8}] {a.rule_name:40} Score:{a.risk_score:3}  {a.source_module}")
            print("=" * 80)
