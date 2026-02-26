# 🛡️ Mini SIEM — Log Monitor & Alert Tool

A Python-based Security Information & Event Management (SIEM) tool built for **macOS**.
Collects system logs, detects threats in real time, stores everything in a database,
and displays it all on a password-protected web dashboard.

Inspired by enterprise tools like **Splunk**, **IBM QRadar**, and **Microsoft Sentinel** —
built from scratch using only Python.

---

## 📸 What It Looks Like

```
  ╔╦╗╦╔╗╔╦  ╔═╗╦╔═╗╔╦╗
  ║║║║║║║║  ╚═╗║║╣ ║║║
  ╩ ╩╩╝╚╝╩  ╚═╝╩╚═╝╩ ╩
  Cross-Platform Log Monitor & Alert Tool

[1/4] Collecting logs...
      → 27 raw entries collected.

[2/4] Parsing & normalising...
[*] Parser: 27 events normalised.

[3/4] Running detection engine...
[TI] Threat intel loaded: 5 IPs, 1 CIDR blocks
[*] Detector: 8 alerts — HIGH=3, MEDIUM=2, CRITICAL=3

[4/4] Dispatching alerts...

============================================================
  🚨  SECURITY ALERTS
============================================================
[!!!!!! CRITICAL !!!!!!] CRITICAL_RISK_THRESHOLD | Score: 272
  ↳ Aggregate risk score 272 exceeds critical threshold 20.
[!!! HIGH !!!] BRUTE_FORCE | Score: 104
  ↳ 8 failed login attempts in 120s from '203.0.113.42'
[!!! HIGH !!!] THREAT_INTEL_MATCH | Score: 15
  ↳ IP 203.0.113.42 matched threat intelligence list
============================================================
```

Dashboard runs at `http://127.0.0.1:5000` with login screen and live charts.

---

## 📁 Project Structure

```
log_monitor/
│
├── main.py              # CLI entry point (Click-based, 6 commands)
├── collector.py         # macOS log collection + demo mode
├── parser.py            # Log normalisation and validation
├── detector.py          # 6 detection rules + risk scoring
├── alert.py             # Console, file, and email alerts
├── report.py            # TXT + CSV report generator
├── database.py          # SQLite persistent storage + queries
├── threat_intel.py      # Malicious IP list + CIDR matching
├── siem_logger.py       # Internal SIEM activity logging
├── dashboard.py         # Flask web dashboard with login
│
├── data/
│   └── threat_intel.txt # Known malicious IPs (edit this)
│
├── logs/
│   └── siem.log         # SIEM's own internal activity log
│
├── tests/
│   ├── test_parser.py   # 20+ parser tests
│   ├── test_detector.py # 25+ detection rule tests
│   └── test_database.py # 15+ database tests
│
├── Dockerfile           # Container support
├── requirements.txt     # Python dependencies
└── LICENSE              # MIT License
```

---

## ⚙️ Installation (macOS)

### 1. Check Python version
```bash
python3 --version
```
You need Python **3.10 or higher**. Download from [python.org](https://python.org) if needed.

### 2. Navigate to the project folder
```bash
cd ~/Desktop/log_monitor
```

### 3. Install dependencies
```bash
pip3 install click flask colorama
```

Verify everything installed:
```bash
python3 -c "import click, flask, colorama; print('All good!')"
```

### 4. (Optional) Install pytest for running tests
```bash
pip3 install pytest
```

---

## 🚀 Quick Start

### Run a full scan with demo data
```bash
python3 main.py run --demo
```
No admin access needed. Uses realistic simulated attack logs.

### Open the web dashboard
```bash
python3 main.py dashboard --demo
```
Then open your browser and go to `http://127.0.0.1:5000`

**Login credentials:**
- Username: `admin`
- Password: `siem2025`

---

## 📟 All CLI Commands

### `run` — Analyse logs and fire alerts

```bash
# Go to project folder
cd ~/Desktop/log_monitor

# Activate the vnev
source venv/bin/activate

# Demo mode (safe, works without admin)
python3 main.py run --demo

# Real macOS logs (needs admin for full access)
sudo python3 main.py run

# Look back further in time
python3 main.py run --demo --hours 48

# Live monitoring — scans every 10 seconds continuously
python3 main.py run --demo --live

# Live monitoring with custom interval
python3 main.py run --demo --live --interval 5

# Skip saving to database
python3 main.py run --demo --no-db

# Skip generating report files
python3 main.py run --demo --no-report

# Send email alerts (set env vars first — see Email section below)
python3 main.py run --demo --email
```

### `dashboard` — Web dashboard

```bash
# Launch with demo data
python3 main.py dashboard --demo

# Launch with real data from database
python3 main.py dashboard

# Use a different port
python3 main.py dashboard --demo --port 8080

# Allow access from other devices on your network
python3 main.py dashboard --demo --host 0.0.0.0
```

### `query` — Search the database

```bash
# All recent alerts
python3 main.py query --alerts

# Events from a specific IP
python3 main.py query --ip 203.0.113.42

# Failed logins for a specific user
python3 main.py query --user admin --type FAILED_LOGIN

# Events after a specific date
python3 main.py query --since 2025-01-15

# Limit how many results show
python3 main.py query --alerts --limit 10
```

### `stats` — Database and threat intel summary

```bash
python3 main.py stats
```

Shows total events stored, total alerts, critical alert count, top suspicious IPs,
top targeted users, and threat intel file info.

### `logs` — View SIEM's own internal log

```bash
# Show last 30 lines
python3 main.py logs

# Show more lines
python3 main.py logs --lines 50
```

### Get help anytime

```bash
python3 main.py --help
python3 main.py run --help
python3 main.py query --help
```

---

## 🔍 Detection Rules

The tool runs 6 independent rules on every batch of events:

| Rule | What triggers it | Severity |
|---|---|---|
| `BRUTE_FORCE` | More than 5 failed logins from same IP within 120 seconds | HIGH |
| `NEW_IP_LOGIN` | Successful login from an IP never seen before | MEDIUM |
| `PRIVILEGE_ESCALATION` | Any `sudo` or privilege escalation event | HIGH |
| `ERROR_SPIKE` | More than 10 failures within 60 seconds | MEDIUM |
| `THREAT_INTEL_MATCH` | Source IP found in the threat intelligence list | CRITICAL |
| `CRITICAL_RISK_THRESHOLD` | Total system risk score exceeds 20 points | CRITICAL |

---

## 🧠 Risk Scoring System

Every event gets a risk score. Scores accumulate to the system total:

| Condition | Points |
|---|---|
| Failed login | +2 |
| Privilege escalation | +5 |
| Account lockout | +4 |
| Explicit credential use | +3 |
| Login from unknown external IP | +3 |
| Part of a brute-force burst | +8 bonus |
| Part of an error spike | +6 bonus |
| IP matched threat intel | +10 bonus |

When total score across all events **≥ 20** → CRITICAL alert fires automatically.

---

## 💾 Persistent Database

All events and alerts are stored in `data/siem.db` (SQLite).
Data survives between runs — your history builds up over time.

The database is queried through the `query` command or directly in Python:

```python
from database import query_events, query_alerts, get_top_ips

# Find all events from a bad IP
events = query_events(ip="203.0.113.42")

# Find critical alerts from the last week
alerts = query_alerts(severity="CRITICAL", since="2025-01-08")

# Top 10 most active attacking IPs
top = get_top_ips(10)
```

To clean up old data (keeps DB from growing forever):
```python
from database import clear_old_data
clear_old_data(days=30)  # delete records older than 30 days
```

---

## 🌐 Threat Intelligence

The tool checks every source IP against a list of known malicious addresses stored in `data/threat_intel.txt`.

**To add your own malicious IPs**, open the file and add one per line:
```
# data/threat_intel.txt
203.0.113.42       # known scanner
198.51.100.7       # brute force bot
10.0.0.99          # internal compromised host
185.220.101.0/24   # tor exit nodes (CIDR block)
```

Lines starting with `#` are comments. CIDR blocks (like `/24`) are supported
and will match entire subnets.

Any event whose source IP matches fires a **CRITICAL** `THREAT_INTEL_MATCH` alert immediately.

In a production environment you would replace this file with feeds from:
- [AbuseIPDB](https://www.abuseipdb.com)
- [Emerging Threats](https://rules.emergingthreats.net)
- [Spamhaus DROP list](https://www.spamhaus.org/drop/)

---

## 🌐 Web Dashboard Features

Launch with `python3 main.py dashboard --demo` then visit `http://127.0.0.1:5000`

**Login page** — username/password protected. Default: `admin` / `siem2025`

**Dashboard includes:**
- 7 KPI cards — failed logins, privilege escalations, critical alerts, total risk score, threat intel hits
- **Attack timeline** — bar chart of failed logins in 5-minute windows. Bars turn red during burst attacks
- **Failed vs Successful logins** — side-by-side bar chart by hour
- **Top suspicious IPs** — horizontal bar chart
- **Top targeted users** — horizontal bar chart  
- **Alert severity distribution** — doughnut chart
- **Alerts table** — all alerts with colour-coded severity badges
- **SIEM internal log** — last 20 lines of `logs/siem.log` rendered live
- **REST API** — `/api/events` and `/api/alerts` return JSON for external tools

**To change the dashboard password**, open `dashboard.py` and edit these two lines:
```python
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "siem2025"
```

---

## 📊 Output Files

After each `run`, these files are created or updated:

| File | Description |
|---|---|
| `alerts.txt` | All alerts, human-readable, appended each run |
| `security_report.txt` | Full daily report with ASCII hourly chart |
| `security_events.csv` | All events — open in Excel or Numbers |
| `security_alerts.csv` | All alerts — open in Excel or Numbers |
| `data/siem.db` | SQLite database with all historical data |
| `logs/siem.log` | SIEM's own internal activity log |

---

## 📧 Email Alerts (Optional)

To receive email alerts for HIGH and CRITICAL severity:

**Step 1** — Set environment variables in Terminal before running:
```bash
export SIEM_SENDER="youremail@gmail.com"
export SIEM_PASSWORD="your_app_password"
export SIEM_RECIPIENT="whereyouwant@email.com"
export SIEM_MIN_SEVERITY="HIGH"
```

**Step 2** — Run with the email flag:
```bash
python3 main.py run --demo --email
```

**Gmail note:** You need an App Password, not your regular password.
Generate one at: Google Account → Security → 2-Step Verification → App Passwords

---

## 🧪 Running Tests

```bash
python3 -m pytest tests/ -v
```

The `-v` flag shows each test name individually. You should see all green PASSED lines.

To run one specific test file:
```bash
python3 -m pytest tests/test_detector.py -v
python3 -m pytest tests/test_parser.py -v
python3 -m pytest tests/test_database.py -v
```

To see test coverage (how much of your code the tests actually check):
```bash
pip3 install pytest-cov
python3 -m pytest tests/ --cov=. --cov-report=term-missing
```

**What's tested:**
- `test_parser.py` — timestamp parsing, IP validation, string sanitisation, batch parsing
- `test_detector.py` — all 6 detection rules, risk scoring, deduplication, full pipeline
- `test_database.py` — save/retrieve events and alerts, all query filters, stats, cleanup

---

## 🐳 Docker Support

Run the entire tool in a container without installing anything on your Mac:

```bash
# Build the container
docker build -t mini-siem .

# Run the dashboard (demo mode)
docker run -p 5000:5000 mini-siem

# Run a one-time scan
docker run mini-siem run --demo

# Keep database data between container restarts
docker run -p 5000:5000 -v $(pwd)/data:/app/data mini-siem
```

Then open `http://localhost:5000` in your browser.

---

## 🍎 macOS-Specific Notes

**Real log collection** uses two macOS sources:

1. **`log show` command** — macOS unified logging system. Searches for authentication failures, SSH events, sudo usage, and privilege escalation across all system services.

2. **`/var/log/system.log`** — Traditional syslog file. Used as a fallback.

**To read real logs you need admin access:**
```bash
sudo python3 main.py run
```

Without sudo, the tool automatically falls back to demo mode with simulated logs.

**What real macOS logs detect:**
- SSH brute-force attempts (`Failed password for root from 1.2.3.4`)
- Sudo usage (`session opened for user root by admin`)
- Invalid user login attempts (`Invalid user oracle from 5.6.7.8`)
- Account lockouts

---

## 🔒 Internal Logging

The SIEM logs its own activity to `logs/siem.log`. This is separate from the security logs it monitors.

Every run records:
- When the program started and what mode it ran in
- How many events were collected and parsed
- Every alert that fired (with severity and entity)
- Any errors that occurred
- How long the run took

The log file automatically rotates when it reaches 5MB, keeping 3 backup files
(`siem.log.1`, `siem.log.2`, `siem.log.3`). Old files are deleted automatically.

View recent activity:
```bash
python3 main.py logs
# or
cat logs/siem.log
```

---

## ⚡ Quick Reference

```bash
# First time setup
pip3 install click flask colorama pytest

# Most common commands
python3 main.py run --demo                        # full scan
python3 main.py run --demo --live                 # continuous monitoring
python3 main.py dashboard --demo                  # web dashboard
python3 main.py query --alerts                    # see all stored alerts
python3 main.py query --ip 203.0.113.42           # find events by IP
python3 main.py stats                             # database summary
python3 main.py logs                              # internal log viewer
python3 -m pytest tests/ -v                       # run all tests
```

---

## 🛠️ Troubleshooting

**Port 5000 already in use:**
```bash
python3 main.py dashboard --demo --port 8080
# then visit http://127.0.0.1:8080
```

**"No module named click" or similar:**
```bash
pip3 install click flask colorama
```

**"Permission denied" reading real logs:**
```bash
sudo python3 main.py run
```

**Database locked or corrupted:**
```bash
rm data/siem.db
python3 main.py run --demo  # recreates it automatically
```

**Nothing shows in real mode (no sudo):**
The tool automatically falls back to demo mode. This is expected behaviour on macOS without admin access.

---

## 📚 Concepts This Project Covers

| Concept | Where it's used |
|---|---|
| Log analysis | `collector.py` reads macOS system logs |
| Regex parsing | `parser.py` extracts IPs, users, timestamps |
| SQLite database | `database.py` stores all events permanently |
| Threat intelligence | `threat_intel.py` compares IPs against blocklist |
| Rule-based detection | `detector.py` — 6 independent detection rules |
| Risk scoring | Each event gets a numerical danger score |
| Alert routing | Console output, file, and email |
| Web dashboard | Flask + Chart.js real-time visualisation |
| Authentication | Flask session-based login |
| Internal logging | Python `logging` module with log rotation |
| Containerisation | Dockerfile for reproducible deployment |
| Unit testing | pytest with 60+ test cases |
| CLI design | Click framework with sub-commands |
| CIDR networking | Subnet-based IP matching in threat intel |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full text.

Free to use, modify, and distribute. Keep the copyright notice.

---

*Built as a portfolio project demonstrating defensive security engineering fundamentals.*
*Inspired by enterprise SIEM tools: Splunk, IBM QRadar, Microsoft Sentinel.*
