# 🛡️ Mini SIEM — Cross-Platform Log Monitor & Alert Tool

A Python-based Security Information & Event Management (SIEM) tool that
collects system logs, detects suspicious activity, generates alerts, and
produces a full security report. Inspired by enterprise tools like Splunk
and IBM QRadar.

---

## 📁 Project Structure

```
log_monitor/
├── collector.py     # Layer 1 — Log collection (Windows/macOS/demo)
├── parser.py        # Layer 2 — Log normalisation
├── detector.py      # Layer 3 — Rule-based detection + risk scoring
├── alert.py         # Layer 4 — Console, file, and email alerts
├── report.py        # Layer 5 — TXT + CSV security reports
├── dashboard.py     # Bonus  — Flask web dashboard (Chart.js)
├── main.py          # Orchestrator / CLI entry point
└── requirements.txt
```

---

## ⚙️ Installation

```bash
# 1. Clone or download the project
cd log_monitor

# 2. Install dependencies
pip install -r requirements.txt

# Windows only — for real Event Log access:
pip install pywin32

# For the web dashboard:
pip install flask
```

---

## 🚀 Usage

### Quick start (demo mode — works on any OS)
```bash
python main.py --demo
```

### Auto-detect OS and read real logs
```bash
# Windows (run as Administrator) or macOS (run with sudo)
python main.py

# macOS with sudo
sudo python main.py --hours 48
```

### Launch the web dashboard
```bash
python main.py --demo --dashboard
# Then open: http://127.0.0.1:5000/
```

### Send email alerts (set env vars first)
```bash
export SIEM_SENDER="you@gmail.com"
export SIEM_PASSWORD="your_app_password"
export SIEM_RECIPIENT="security@yourcompany.com"
export SIEM_MIN_SEVERITY="HIGH"

python main.py --demo --email
```

### All CLI flags
```
--demo           Use simulated logs (safe testing, no OS access needed)
--hours N        How many hours back to look (default: 24)
--email          Dispatch email alerts via SMTP
--no-report      Skip report file generation
--dashboard      Launch Flask web dashboard after analysis
--output-dir     Directory for output files (default: current dir)
```

---

## 🔍 Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| `BRUTE_FORCE` | > 5 failed logins in 120s from same IP | HIGH |
| `NEW_IP_LOGIN` | Successful login from unrecognised IP | MEDIUM |
| `PRIVILEGE_ESCALATION` | Any sudo / privilege escalation event | HIGH |
| `ERROR_SPIKE` | > 10 errors/failures in 60s | MEDIUM |
| `CRITICAL_RISK_THRESHOLD` | Aggregate risk score exceeds threshold | CRITICAL |

---

## 🧠 Risk Scoring

Each event is assigned a score:

| Condition | Points |
|---|---|
| Failed login | +2 |
| Privilege escalation | +5 |
| Account lockout | +4 |
| Explicit credential use | +3 |
| Unknown external IP | +3 |
| Brute-force window bonus | +8 |
| Error spike bonus | +6 |

When the **total system risk score ≥ 20**, a CRITICAL alert fires.

---

## 📊 Outputs

After each run, the tool generates:

| File | Description |
|---|---|
| `alerts.txt` | All alerts in human-readable format |
| `security_report.txt` | Full daily report with summary + hourly chart |
| `security_events.csv` | All parsed events in CSV format |
| `security_alerts.csv` | All alerts in CSV format |

---

## 🌐 Web Dashboard

Run with `--dashboard` to get:

- **Failed login graph** (bar chart by hour)
- **Risk score breakdown** by event type (doughnut)
- **Top suspicious IPs** (horizontal bar chart)
- **Alert severity distribution** (pie chart)
- **Live alerts table** with severity badges

---

## 🔐 Email Alerts (Optional)

Configure via environment variables or edit `alert.py` directly:

```bash
SIEM_SMTP_HOST      # default: smtp.gmail.com
SIEM_SMTP_PORT      # default: 587
SIEM_SENDER         # your sending email address
SIEM_PASSWORD       # SMTP password or app-specific password
SIEM_RECIPIENT      # who receives the alert email
SIEM_MIN_SEVERITY   # minimum severity to email (default: HIGH)
```

For Gmail, use an **App Password** (not your main password).
Enable it at: myaccount.google.com → Security → App Passwords.

---

## 🧪 Extending the Tool

### Add a new detection rule
In `detector.py`, create a function following this pattern:

```python
def _rule_my_new_rule(events):
    alerts = []
    for ev in events:
        if <your_condition>:
            alerts.append({
                "rule":        "MY_RULE",
                "severity":    "HIGH",
                "timestamp":   ev["timestamp"],
                "description": f"...",
                "events":      [ev],
                "risk_score":  ev["risk_score"],
                "entity":      ev["user"],
            })
    return alerts
```

Then call it inside `detect()`.

### Add a new log source
In `collector.py`, create a new function that returns a list of dicts
matching the raw log schema, and call it from `collect_logs()`.

---

## 📚 Skills Demonstrated

- Cross-platform system log access (Windows Event Logs, macOS unified logging)
- Regex-based log parsing and normalisation
- Rule-based threat detection logic
- Risk scoring (simplified SIEM concept)
- Alert routing (console, file, email)
- Data aggregation and reporting (TXT + CSV)
- Web dashboard with REST API endpoints (Flask + Chart.js)

---

*Built as a portfolio project demonstrating defensive security engineering fundamentals.*
