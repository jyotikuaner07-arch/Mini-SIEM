# 🛡️ Mini SIEM

> A pip-installable, cross-platform Security Information & Event Management (SIEM) tool built in Python.
> Collects real system logs on **macOS, Windows, and Linux**, detects threats in real time,
> stores everything in a database, and displays it all on a password-protected web dashboard.

Inspired by enterprise tools like **Splunk**, **IBM QRadar**, and **Microsoft Sentinel** —
built from scratch using only Python and distributed as a proper CLI package.

---

## ⚡ Install & Run in 3 Commands

```bash
pip install mini-siem
mini-siem init
mini-siem run --demo
```

That's it. No cloning. No manual file execution. Real software distribution.

---

## 📸 What It Looks Like

```
  ╔╦╗╦╔╗╔╦  ╔═╗╦╔═╗╔╦╗
  ║║║║║║║║  ╚═╗║║╣ ║║║
  ╩ ╩╩╝╚╝╩  ╚═╝╩╚═╝╩ ╩
  Cross-Platform Log Monitor & Alert Tool

[1/4] Collecting logs...        → 9 raw entries collected.
[2/4] Parsing & normalising...  → 9 events parsed.
[3/4] Running detection engine...
      → 2 alert(s) suppressed (trusted activity — audit trail preserved)
[4/4] Dispatching alerts...

============================================================
  🚨  SECURITY ALERTS
============================================================
[!!!!!! CRITICAL !!!!!!] THREAT_INTEL_MATCH | Score: 15
  ↳ IP 203.0.113.42 matched threat intelligence list
[!!! HIGH !!!] BRUTE_FORCE | Score: 42
  ↳ 8 failed login attempts in 120s from '198.51.100.7'
============================================================
```

Dashboard at `http://127.0.0.1:5000` — login protected, live charts, attack timeline.

---

## 📁 Project Structure

```
Mini SIEM/
│
├── mini_siem/                  ← Python package (the actual tool)
│   ├── __init__.py
│   ├── __main__.py             ← enables: python -m mini_siem
│   ├── main.py                 ← CLI entry point (all commands live here)
│   └── core/                   ← engine modules
│       ├── __init__.py
│       ├── collector.py        ← macOS, Windows & Linux log collection
│       ├── parser.py           ← normalisation & validation
│       ├── detector.py         ← 6 detection rules + risk scoring
│       ├── alert.py            ← console, file, email alerts
│       ├── report.py           ← TXT + CSV report generator
│       ├── database.py         ← SQLite persistent storage
│       ├── threat_intel.py     ← malicious IP matching
│       ├── siem_logger.py      ← internal SIEM activity log
│       ├── dashboard.py        ← Flask web dashboard
│       └── whitelist.py        ← false positive suppression
│
├── tests/
│   ├── test_parser.py          ← 20+ parser tests
│   ├── test_detector.py        ← 25+ detection rule tests
│   └── test_database.py        ← 15+ database tests
│
├── data/
│   └── threat_intel.txt        ← known malicious IPs (edit this)
│
├── pyproject.toml              ← package config (how pip install works)
├── Dockerfile                  ← container support
├── requirements.txt            ← dependencies
├── whitelist.json              ← trusted users/IPs (auto-created)
├── LICENSE                     ← MIT
└── README.md
```

**User data** is stored in `~/.mini_siem/` — completely separate from the code:
```
~/.mini_siem/
├── siem.db              ← SQLite database (all events + alerts)
├── threat_intel.txt     ← your threat intel list
├── whitelist.json       ← your trusted users/IPs
└── logs/
    └── siem.log         ← internal SIEM activity log
```

---

## 💻 Platform Support

| Feature | macOS | Windows | Linux |
|---|---|---|---|
| `mini-siem run --demo` | ✅ | ✅ | ✅ |
| Real log collection | ✅ | ✅ | ✅ |
| Web dashboard | ✅ | ✅ | ✅ |
| Database & queries | ✅ | ✅ | ✅ |
| Threat intelligence | ✅ | ✅ | ✅ |
| Whitelist suppression | ✅ | ✅ | ✅ |
| Email alerts | ✅ | ✅ | ✅ |
| Docker | ✅ | ✅ | ✅ |
| Tests | ✅ | ✅ | ✅ |

**Log sources by platform:**

| Platform | Log Source | Admin Required |
|---|---|---|
| macOS | `log show` unified logging + `/var/log/system.log` | `sudo` |
| Windows | Windows Event Log (IDs 4624, 4625, 4672, 4740) | Run as Administrator |
| Linux (Ubuntu/Debian/Kali) | `/var/log/auth.log` | `sudo` |
| Linux (CentOS/RHEL/Fedora) | `/var/log/secure` | `sudo` |

---

## 🍎 Installation on macOS

### Requirements
- Python 3.10 or higher
- macOS Monterey, Ventura, or Sonoma

```bash
# Clone the repo
git clone https://github.com/yourusername/mini-SIEM.git
cd mini-SIEM

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the package
pip install .

# First time setup
mini-siem init
```

### Shortcut — activate venv automatically

```bash
echo 'alias siem="cd ~/Documents/PROJECTS/Mini\ SIEM && source venv/bin/activate"' >> ~/.zshrc
source ~/.zshrc
```

Now just type `siem` in any terminal window to get started.

---

## 🪟 Installation on Windows

### Requirements
- Python 3.10 or higher — download from [python.org](https://python.org)
- Run **Command Prompt as Administrator** for real log access

```bash
# Clone the repo
git clone https://github.com/yourusername/mini-SIEM.git
cd mini-SIEM

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate

# Install the package + Windows log support
pip install .
pip install pywin32

# First time setup
mini-siem init
```

### Real log collection on Windows

Open **Command Prompt as Administrator** (right-click → Run as Administrator):

```bash
mini-siem run
```

Without Administrator rights, use demo mode:
```bash
mini-siem run --demo
```

**What gets detected from Windows Event Log:**

| Event ID | What It Means |
|---|---|
| 4625 | Failed login attempt |
| 4624 | Successful login |
| 4740 | Account lockout |
| 4672 | Privilege escalation |

---

## 🐧 Installation on Linux

### Requirements
- Python 3.10 or higher
- Ubuntu, Debian, Kali, CentOS, RHEL, or Fedora

```bash
# Clone the repo
git clone https://github.com/yourusername/mini-SIEM.git
cd mini-SIEM

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the package
pip install .

# First time setup
mini-siem init
```

### Real log collection on Linux

```bash
# Ubuntu / Debian / Kali — reads /var/log/auth.log
sudo mini-siem run

# CentOS / RHEL / Fedora — reads /var/log/secure
sudo mini-siem run
```

**What gets detected from Linux logs:**
- SSH brute-force attempts (`Failed password for root from 1.2.3.4`)
- Invalid user login attempts
- Sudo usage and privilege escalation
- Account authentication failures

---

## 🚀 Daily Usage

### macOS
```bash
siem                        # activate venv (if alias set up)
sudo mini-siem run          # collect real logs
mini-siem dashboard         # open web dashboard
```

### Windows (Command Prompt as Administrator)
```bash
venv\Scripts\activate
mini-siem run               # collect real Windows Event Log
mini-siem dashboard         # open web dashboard
```

### Linux
```bash
source venv/bin/activate
sudo mini-siem run          # collect real logs
mini-siem dashboard         # open web dashboard
```

Then visit `http://localhost:5000` — login: `admin` / `siem2025`

---

## 📟 All Commands

### `mini-siem init`
First-time setup. Creates `~/.mini_siem/` with database and config files.
```bash
mini-siem init
```

### `mini-siem run` — Analyse logs and fire alerts

```bash
# Real logs — macOS (requires sudo)
sudo mini-siem run

# Real logs — Windows (run Command Prompt as Administrator)
mini-siem run

# Real logs — Linux (requires sudo)
sudo mini-siem run

# Demo mode — works on ALL platforms, no admin needed
mini-siem run --demo

# Look back further in time
sudo mini-siem run --hours 48

# Live monitoring — scans every 10 seconds continuously
sudo mini-siem run --live

# Live monitoring with custom interval
sudo mini-siem run --live --interval 30

# Skip saving to database
sudo mini-siem run --no-db

# Skip generating report files
sudo mini-siem run --no-report

# Send email alerts (configure env vars first)
sudo mini-siem run --email
```

### `mini-siem dashboard` — Web dashboard

```bash
mini-siem dashboard                    # uses data from database
mini-siem dashboard --demo             # uses simulated demo data
mini-siem dashboard --port 8080        # use different port
```

### `mini-siem query` — Search the database

```bash
mini-siem query --alerts               # all recent alerts
mini-siem query --ip 203.0.113.42      # events from specific IP
mini-siem query --user admin           # events for specific user
mini-siem query --type FAILED_LOGIN    # filter by event type
mini-siem query --since 2025-01-15     # events after a date
mini-siem query --alerts --limit 10    # limit results
```

### `mini-siem stats` — Summary of everything stored

```bash
mini-siem stats
```

### `mini-siem logs` — View SIEM's own internal log

```bash
mini-siem logs
mini-siem logs --lines 50
```

### Get help anytime

```bash
mini-siem --help
mini-siem run --help
mini-siem query --help
```

### Alternative — run without installing

```bash
python -m mini_siem run --demo
python -m mini_siem dashboard --demo
```

---

## 🔍 Detection Rules

Six independent rules run on every batch of events:

| Rule | What Triggers It | Severity |
|---|---|---|
| `BRUTE_FORCE` | 5+ failed logins from same IP within 120 seconds | HIGH |
| `NEW_IP_LOGIN` | Successful login from a previously unseen IP | MEDIUM |
| `PRIVILEGE_ESCALATION` | Any sudo or privilege escalation event | HIGH |
| `ERROR_SPIKE` | 10+ failures within 60 seconds | MEDIUM |
| `THREAT_INTEL_MATCH` | Source IP found in threat intelligence list | CRITICAL |
| `CRITICAL_RISK_THRESHOLD` | Total system risk score exceeds 20 points | CRITICAL |

---

## 🧠 Risk Scoring

Every event gets a numerical risk score. Scores accumulate to the system total:

| Condition | Points |
|---|---|
| Failed login | +2 |
| Privilege escalation | +5 |
| Account lockout | +4 |
| Explicit credential use | +3 |
| Unknown external IP | +3 |
| Part of brute-force burst | +8 bonus |
| Part of error spike | +6 bonus |
| IP matched threat intel | +10 bonus |

When total score **≥ 20** → CRITICAL alert fires automatically.

---

## 🛡️ Whitelist — False Positive Suppression

Your own legitimate admin activity (like running `sudo`) would normally trigger
PRIVILEGE_ESCALATION alerts. The whitelist suppresses these so you only see real threats.

Your username is added automatically when you run `mini-siem init`.

**Edit the whitelist** at `~/.mini_siem/whitelist.json`:

```json
{
  "trusted_users": ["jyotikuaner", "root"],
  "trusted_ips":   ["127.0.0.1", "::1", "192.168.1.5"],
  "trusted_processes": ["sudo", "python3", "venv"]
}
```

Whitelisted events are still saved to the database — full audit trail is preserved.
They just don't show up as loud alerts.

---

## 🌐 Threat Intelligence

Every source IP is checked against `~/.mini_siem/threat_intel.txt`.
Any match fires a **CRITICAL** alert immediately.

**Add your own malicious IPs** — one per line:

```
# ~/.mini_siem/threat_intel.txt
203.0.113.42        # known scanner
198.51.100.7        # brute force bot
185.220.101.0/24    # tor exit nodes (CIDR block)
```

CIDR blocks (like `/24`) are supported — matches entire subnets.

In production, replace with real threat feeds:
- [AbuseIPDB](https://www.abuseipdb.com)
- [Emerging Threats](https://rules.emergingthreats.net)
- [Spamhaus DROP list](https://www.spamhaus.org/drop/)

---

## 💻 Web Dashboard

```bash
mini-siem dashboard --demo
```

Visit `http://127.0.0.1:5000` — login: `admin` / `siem2025`

**Features:**
- Login page — password protected
- 7 KPI cards — failed logins, escalations, critical alerts, risk score, threat intel hits
- Attack timeline — 5-minute bucket chart, bars turn red during burst attacks
- Failed vs successful logins by hour
- Top suspicious IPs chart
- Top targeted users chart
- Alert severity distribution
- Colour-coded alerts table
- Live SIEM internal log viewer
- REST API — `/api/events` and `/api/alerts` return JSON

**Change the dashboard password** — open `mini_siem/core/dashboard.py`:
```python
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "siem2025"    # change this
```

---

## 💾 Database

All events and alerts are stored permanently in `~/.mini_siem/siem.db` (SQLite).
Data builds up over time — your history is always there.

```python
from mini_siem.core.database import query_events, query_alerts, get_top_ips

# Find all events from a suspicious IP
events = query_events(ip="203.0.113.42")

# Find critical alerts from last week
alerts = query_alerts(severity="CRITICAL", since="2025-01-08")

# Top 10 attacking IPs all time
top = get_top_ips(10)
```

Clean up old data:
```python
from mini_siem.core.database import clear_old_data
clear_old_data(days=30)
```

---

## 📊 Output Files

After each `run`, files are saved to `~/.mini_siem/reports/`:

| File | Description |
|---|---|
| `alerts.txt` | All alerts, human-readable |
| `security_report.txt` | Full report with hourly activity chart |
| `security_events.csv` | All events — open in Excel or Numbers |
| `security_alerts.csv` | All alerts — open in Excel or Numbers |

---

## 📧 Email Alerts (Optional)

```bash
export SIEM_SENDER="you@gmail.com"
export SIEM_PASSWORD="your_app_password"
export SIEM_RECIPIENT="alerts@email.com"
export SIEM_MIN_SEVERITY="HIGH"

sudo mini-siem run --email
```

Gmail requires an App Password — generate at:
Google Account → Security → 2-Step Verification → App Passwords

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

```bash
# Run individual test files
python -m pytest tests/test_detector.py -v
python -m pytest tests/test_parser.py -v
python -m pytest tests/test_database.py -v
```

```bash
# Run with coverage report
pip install pytest-cov
python -m pytest tests/ --cov=mini_siem --cov-report=term-missing
```

---

## 🐳 Docker

```bash
# Build
docker build -t mini-siem .

# Run dashboard
docker run -p 5000:5000 mini-siem

# Keep data between restarts
docker run -p 5000:5000 -v ~/.mini_siem:/root/.mini_siem mini-siem
```

---

## 🔎 Real Log Collection by Platform

### 🍎 macOS
Uses two sources: the `log show` unified logging command and `/var/log/system.log`.

```bash
sudo mini-siem run
```

Give Terminal **Full Disk Access** if you get zero events:
System Settings → Privacy & Security → Full Disk Access → add Terminal

**Generate test events:**
```bash
ssh wronguser@localhost     # failed login
sudo ls                     # privilege escalation
```

### 🪟 Windows
Reads Windows Event Log via `pywin32`. Install it first:
```bash
pip install pywin32
```

Then open Command Prompt **as Administrator** and run:
```bash
mini-siem run
```

**Generate test events:**
```
Lock your screen and type wrong password → Event ID 4625
Open an elevated command prompt → Event ID 4672
```

### 🐧 Linux
Reads `/var/log/auth.log` (Ubuntu/Debian/Kali) or `/var/log/secure` (CentOS/RHEL).

```bash
sudo mini-siem run
```

**Generate test events:**
```bash
ssh wronguser@localhost     # failed login → goes to auth.log
sudo ls                     # privilege escalation
```

---

## 📦 Building for Distribution

```bash
pip install build
python -m build
```

Creates in `dist/`:
- `mini_siem-1.1.0.tar.gz` — source distribution
- `mini_siem-1.1.0-py3-none-any.whl` — installable wheel

Install from wheel:
```bash
pip install mini_siem-1.1.0-py3-none-any.whl

# Windows users — also install pywin32 for real log support
pip install pywin32
```

Publish to PyPI:
```bash
pip install twine
twine upload dist/*
```

Then anyone on any platform installs with:
```bash
pip install mini-siem
```

---

## 🔧 Troubleshooting

**`mini-siem: command not found`**
```bash
# macOS / Linux
source venv/bin/activate

# Windows
venv\Scripts\activate
```

**Port 5000 already in use**
```bash
mini-siem dashboard --port 8080
# visit http://localhost:8080
```

**Zero events on macOS (even with sudo)**
- System Settings → Privacy & Security → Full Disk Access → add Terminal → restart Terminal

**Zero events on Windows**
- Make sure you opened Command Prompt as Administrator
- Right-click Command Prompt → Run as Administrator

**Zero events on Linux**
```bash
# Check which log file exists on your distro
ls /var/log/auth.log    # Ubuntu/Debian/Kali
ls /var/log/secure      # CentOS/RHEL/Fedora
sudo mini-siem run
```

**Windows: `No module named win32evtlog`**
```bash
pip install pywin32
```

**Database issues**
```bash
rm ~/.mini_siem/siem.db    # macOS / Linux
mini-siem init
```
```bash
# Windows — in Command Prompt
del %USERPROFILE%\.mini_siem\siem.db
mini-siem init
```

**ModuleNotFoundError after code changes**
```bash
pip uninstall mini-siem -y
pip install .
```

**Dashboard shows "Access Denied" in Chrome**
Use Safari or Firefox, or type `http://localhost:5000` with `http://` explicitly.

---

## 📚 Concepts This Project Demonstrates

| Concept | Where |
|---|---|
| pip package distribution | `pyproject.toml`, `mini_siem/` structure |
| CLI design | Click framework, `mini_siem/main.py` |
| macOS log collection | `core/collector.py` — `log show` + `/var/log/system.log` |
| Windows log collection | `core/collector.py` — Windows Event Log via `pywin32` |
| Linux log collection | `core/collector.py` — `/var/log/auth.log` + `/var/log/secure` |
| Log parsing & normalisation | `core/parser.py` |
| Rule-based threat detection | `core/detector.py` |
| Risk scoring | Numerical danger scores per event |
| False positive suppression | `core/whitelist.py` |
| SQLite persistence | `core/database.py` |
| Threat intelligence | `core/threat_intel.py`, CIDR matching |
| Web dashboard + auth | `core/dashboard.py`, Flask sessions |
| Internal logging | `core/siem_logger.py`, log rotation |
| Email alerting | `core/alert.py`, smtplib |
| Unit testing | `tests/`, pytest, 60+ test cases |
| Docker containerisation | `Dockerfile` |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full text.

Free to use, modify, and distribute. Keep the copyright notice.

---

*Built as a portfolio project demonstrating defensive security engineering.*
*Supports macOS, Windows, and Linux. Inspired by Splunk, IBM QRadar, and Microsoft Sentinel.*