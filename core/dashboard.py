"""
dashboard.py - Flask Web Dashboard
Features:
  - Login page (username/password protected)
  - Failed login timeline (attack burst visualization)
  - Top targeted users chart
  - Time filter: last 24h / 7d
  - Risk score trend
  - Threat intel hit indicator
  - REST API endpoints
  - SIEM log viewer

Requires: pip install flask
"""

import datetime
import json
from collections import Counter, defaultdict
from pathlib import Path
from functools import wraps

try:
    from flask import (Flask, render_template_string, jsonify,
                       request, redirect, url_for, session)
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

# ── Hardcoded admin credentials for demo ──
# In production: hash with bcrypt, store in DB
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "siem2025"   # Change this!
SECRET_KEY     = "mini-siem-secret-key-change-in-production"


# ════════════════════════════════════════════════════════
# LOGIN PAGE TEMPLATE
# ════════════════════════════════════════════════════════

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SIEM Login</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0d1117;
      color: #c9d1d9;
      font-family: 'Segoe UI', system-ui, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 40px;
      width: 360px;
    }
    .logo { font-size: 2rem; text-align: center; margin-bottom: 8px; }
    h1 { text-align: center; font-size: 1.2rem; color: #58a6ff; margin-bottom: 4px; }
    .subtitle { text-align: center; color: #8b949e; font-size: 0.82rem; margin-bottom: 28px; }
    label { display: block; font-size: 0.82rem; color: #8b949e; margin-bottom: 6px; }
    input {
      width: 100%;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      color: #c9d1d9;
      padding: 10px 12px;
      font-size: 0.9rem;
      margin-bottom: 16px;
      outline: none;
    }
    input:focus { border-color: #58a6ff; }
    button {
      width: 100%;
      background: #238636;
      color: #fff;
      border: none;
      border-radius: 6px;
      padding: 11px;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      margin-top: 4px;
    }
    button:hover { background: #2ea043; }
    .error {
      background: #3d1a1a;
      border: 1px solid #da3633;
      border-radius: 6px;
      color: #f85149;
      padding: 10px 12px;
      font-size: 0.85rem;
      margin-bottom: 16px;
    }
    .hint { text-align:center; color:#484f58; font-size:0.75rem; margin-top:20px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">🛡️</div>
    <h1>Mini SIEM</h1>
    <p class="subtitle">Security Operations Dashboard</p>
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    <form method="POST">
      <label>Username</label>
      <input type="text" name="username" placeholder="admin" autocomplete="off" required>
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" required>
      <button type="submit">Sign In</button>
    </form>
    <p class="hint">Default credentials: admin / siem2025</p>
  </div>
</body>
</html>
"""


# ════════════════════════════════════════════════════════
# MAIN DASHBOARD TEMPLATE
# ════════════════════════════════════════════════════════

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mini SIEM Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}

    /* NAV */
    nav{background:#161b22;border-bottom:1px solid #30363d;padding:12px 32px;
        display:flex;align-items:center;gap:14px}
    nav .logo{font-size:1.4rem}
    nav h1{font-size:1.1rem;color:#58a6ff;font-weight:600}
    nav .spacer{flex:1}
    nav .badge{padding:3px 12px;border-radius:12px;font-size:.75rem;font-weight:700}
    nav .badge.crit{background:#da3633;color:#fff;animation:pulse 1.5s infinite}
    nav .badge.ok{background:#238636;color:#fff}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
    nav .logout{color:#8b949e;text-decoration:none;font-size:.82rem;padding:6px 12px;
               border:1px solid #30363d;border-radius:6px}
    nav .logout:hover{color:#c9d1d9;border-color:#58a6ff}

    /* FILTER BAR */
    .filter-bar{background:#0d1117;border-bottom:1px solid #21262d;padding:8px 32px;display:flex;gap:10px;align-items:center}
    .filter-bar span{color:#8b949e;font-size:.82rem}
    .filter-btn{padding:5px 14px;border-radius:6px;border:1px solid #30363d;background:#161b22;
               color:#8b949e;cursor:pointer;font-size:.82rem}
    .filter-btn.active{border-color:#58a6ff;color:#58a6ff;background:#0d1a2e}

    main{padding:20px 32px}

    /* KPI CARDS */
    .kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}
    .kpi{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px 18px}
    .kpi .lbl{font-size:.72rem;color:#8b949e;text-transform:uppercase;letter-spacing:.06em}
    .kpi .val{font-size:1.9rem;font-weight:700;margin-top:5px}
    .kpi.danger  .val{color:#f85149}
    .kpi.warning .val{color:#d29922}
    .kpi.info    .val{color:#58a6ff}
    .kpi.ok      .val{color:#3fb950}
    .kpi .delta{font-size:.72rem;color:#8b949e;margin-top:3px}

    /* CHART GRID */
    .chart-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:18px;margin-bottom:22px}
    .chart-card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px}
    .chart-card h2{font-size:.88rem;color:#c9d1d9;margin-bottom:14px;display:flex;align-items:center;gap:6px}

    /* FULL WIDTH CHART */
    .chart-full{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin-bottom:22px}
    .chart-full h2{font-size:.88rem;color:#c9d1d9;margin-bottom:14px}

    /* TABLES */
    .tbl-card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin-bottom:22px;overflow-x:auto}
    .tbl-card h2{font-size:.88rem;color:#c9d1d9;margin-bottom:14px}
    table{width:100%;border-collapse:collapse;font-size:.83rem}
    th{color:#8b949e;text-align:left;padding:7px 11px;border-bottom:1px solid #30363d;font-weight:500}
    td{padding:7px 11px;border-bottom:1px solid #21262d}
    tr:hover td{background:#1c2128}
    .sev{padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:700}
    .sev.CRITICAL{background:#da3633;color:#fff}
    .sev.HIGH    {background:#b83232;color:#fff}
    .sev.MEDIUM  {background:#9e6a03;color:#fff}
    .sev.LOW     {background:#0d419d;color:#fff}

    /* LOG VIEWER */
    .log-viewer{background:#0d1117;border:1px solid #30363d;border-radius:6px;
               padding:12px;font-family:monospace;font-size:.75rem;
               max-height:220px;overflow-y:auto;color:#8b949e}
    .log-viewer .err{color:#f85149}
    .log-viewer .warn{color:#d29922}

    footer{text-align:center;color:#484f58;font-size:.75rem;padding:18px 0}
  </style>
</head>
<body>

<nav>
  <div class="logo">🛡️</div>
  <h1>Mini SIEM Dashboard</h1>
  <span style="color:#8b949e;font-size:.82rem">{{ generated_at }}</span>
  <div class="spacer"></div>
  {% if kpi.alerts_critical > 0 %}
    <span class="badge crit">🔴 {{ kpi.alerts_critical }} CRITICAL</span>
  {% else %}
    <span class="badge ok">🟢 All Clear</span>
  {% endif %}
  <a href="/logout" class="logout">Logout</a>
</nav>

<!-- TIME FILTER -->
<div class="filter-bar">
  <span>Time range:</span>
  <button class="filter-btn active" onclick="setFilter('24h',this)">Last 24h</button>
  <button class="filter-btn"        onclick="setFilter('7d',this)">Last 7 days</button>
  <button class="filter-btn"        onclick="setFilter('all',this)">All time</button>
</div>

<main>

  <!-- KPI CARDS -->
  <div class="kpi-grid">
    <div class="kpi danger">
      <div class="lbl">Failed Logins</div>
      <div class="val">{{ kpi.failed_logins }}</div>
      <div class="delta">authentication failures</div>
    </div>
    <div class="kpi warning">
      <div class="lbl">Priv Escalations</div>
      <div class="val">{{ kpi.priv_escalations }}</div>
      <div class="delta">sudo / su events</div>
    </div>
    <div class="kpi danger">
      <div class="lbl">Critical Alerts</div>
      <div class="val">{{ kpi.alerts_critical }}</div>
    </div>
    <div class="kpi warning">
      <div class="lbl">High Alerts</div>
      <div class="val">{{ kpi.alerts_high }}</div>
    </div>
    <div class="kpi info">
      <div class="lbl">Total Events</div>
      <div class="val">{{ kpi.total_events }}</div>
    </div>
    <div class="kpi info">
      <div class="lbl">Risk Score</div>
      <div class="val">{{ kpi.total_risk }}</div>
    </div>
    <div class="kpi danger">
      <div class="lbl">Threat Intel Hits</div>
      <div class="val">{{ kpi.threat_intel_hits }}</div>
      <div class="delta">known malicious IPs</div>
    </div>
  </div>

  <!-- FULL-WIDTH ATTACK TIMELINE -->
  <div class="chart-full">
    <h2>⚡ Attack Timeline — Failed Login Bursts (per 5-minute window)</h2>
    <canvas id="timelineChart" height="80"></canvas>
  </div>

  <!-- CHART GRID ROW 1 -->
  <div class="chart-grid">
    <div class="chart-card">
      <h2>📊 Failed vs Successful Logins (by hour)</h2>
      <canvas id="failedChart"></canvas>
    </div>
    <div class="chart-card">
      <h2>🌐 Top Suspicious IPs</h2>
      <canvas id="ipChart"></canvas>
    </div>
  </div>

  <!-- CHART GRID ROW 2 -->
  <div class="chart-grid">
    <div class="chart-card">
      <h2>👤 Top Targeted Users</h2>
      <canvas id="userChart"></canvas>
    </div>
    <div class="chart-card">
      <h2>🎯 Alert Severity Distribution</h2>
      <canvas id="severityChart"></canvas>
    </div>
  </div>

  <!-- ALERTS TABLE -->
  <div class="tbl-card">
    <h2>🚨 Recent Alerts</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Rule</th><th>Timestamp</th><th>Score</th><th>Description</th></tr>
      </thead>
      <tbody>
        {% for a in alerts %}
        <tr>
          <td><span class="sev {{ a.severity }}">{{ a.severity }}</span></td>
          <td>{{ a.rule }}</td>
          <td>{{ a.timestamp }}</td>
          <td>{{ a.risk_score }}</td>
          <td>{{ a.description }}</td>
        </tr>
        {% endfor %}
        {% if not alerts %}
        <tr><td colspan="5" style="text-align:center;color:#8b949e;padding:20px">No alerts</td></tr>
        {% endif %}
      </tbody>
    </table>
  </div>

  <!-- INTERNAL SIEM LOG -->
  <div class="tbl-card">
    <h2>📋 SIEM Internal Log (last 20 lines)</h2>
    <div class="log-viewer" id="siemLog">
      {% for line in siem_logs %}
        {% if 'ERROR' in line or 'CRITICAL' in line %}
          <div class="err">{{ line }}</div>
        {% elif 'WARNING' in line %}
          <div class="warn">{{ line }}</div>
        {% else %}
          <div>{{ line }}</div>
        {% endif %}
      {% endfor %}
      {% if not siem_logs %}
        <div>No internal logs yet. Run a scan first.</div>
      {% endif %}
    </div>
  </div>

</main>
<footer>Mini SIEM · Python + Flask + Chart.js · <a href="/api/events" style="color:#58a6ff">API</a></footer>

<script>
// ── Chart defaults ──
const CD = {
  color:'#c9d1d9',
  plugins:{ legend:{ labels:{ color:'#c9d1d9',boxWidth:12 } } },
  scales:{
    x:{ ticks:{color:'#8b949e'}, grid:{color:'#21262d'} },
    y:{ ticks:{color:'#8b949e'}, grid:{color:'#21262d'}, beginAtZero:true }
  }
};

// ── Data injected from Python ──
const failedHourly  = {{ failed_hourly  | safe }};
const successHourly = {{ success_hourly | safe }};
const hourLabels    = {{ hour_labels    | safe }};
const ipLabels      = {{ ip_labels      | safe }};
const ipValues      = {{ ip_values      | safe }};
const userLabels    = {{ user_labels    | safe }};
const userValues    = {{ user_values    | safe }};
const sevLabels     = {{ sev_labels     | safe }};
const sevValues     = {{ sev_values     | safe }};
const timelineLabels= {{ timeline_labels| safe }};
const timelineValues= {{ timeline_values| safe }};

// ── Attack Timeline (5-min buckets) ──
new Chart(document.getElementById('timelineChart'),{
  type:'bar',
  data:{
    labels:timelineLabels,
    datasets:[{
      label:'Failed Logins',
      data:timelineValues,
      backgroundColor: timelineValues.map(v =>
        v >= 5 ? 'rgba(218,54,51,0.85)' :
        v >= 2 ? 'rgba(210,153,34,0.8)' :
                 'rgba(88,166,255,0.6)'
      ),
      borderWidth:0,
    }]
  },
  options:{
    ...CD,
    plugins:{
      ...CD.plugins,
      tooltip:{
        callbacks:{
          title: items => `Window: ${items[0].label}`,
          afterLabel: items =>
            items.raw >= 5 ? ' ⚠️  Attack burst detected!' : ''
        }
      }
    }
  }
});

// ── Failed vs Successful logins ──
new Chart(document.getElementById('failedChart'),{
  type:'bar',
  data:{
    labels:hourLabels,
    datasets:[
      { label:'Failed',     data:failedHourly,  backgroundColor:'rgba(248,81,73,0.75)', borderWidth:0 },
      { label:'Successful', data:successHourly, backgroundColor:'rgba(63,185,80,0.6)',  borderWidth:0 },
    ]
  },
  options:{ ...CD, scales:{...CD.scales, x:{...CD.scales.x, stacked:false}} }
});

// ── Top IPs ──
new Chart(document.getElementById('ipChart'),{
  type:'bar',
  data:{
    labels:ipLabels,
    datasets:[{
      label:'Failed Attempts',
      data:ipValues,
      backgroundColor:'rgba(210,153,34,0.75)',
      borderWidth:0,
    }]
  },
  options:{ ...CD, indexAxis:'y' }
});

// ── Top targeted users ──
new Chart(document.getElementById('userChart'),{
  type:'bar',
  data:{
    labels:userLabels,
    datasets:[{
      label:'Attacks Against User',
      data:userValues,
      backgroundColor:'rgba(88,166,255,0.7)',
      borderWidth:0,
    }]
  },
  options:{ ...CD, indexAxis:'y' }
});

// ── Severity pie ──
new Chart(document.getElementById('severityChart'),{
  type:'doughnut',
  data:{
    labels:sevLabels,
    datasets:[{
      data:sevValues,
      backgroundColor:['#da3633','#b83232','#9e6a03','#0d419d'],
      borderWidth:2,
      borderColor:'#161b22',
    }]
  },
  options:{ plugins:{ legend:{ labels:{ color:'#c9d1d9' } } } }
});

// ── Time filter (client-side label for now) ──
function setFilter(range, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  // In a real app this would re-fetch /api/events?range=7d
  // For now just show a note
  console.log('Filter selected:', range);
}
</script>
</body>
</html>
"""


# ════════════════════════════════════════════════════════
# CONTEXT BUILDER
# ════════════════════════════════════════════════════════

def _build_context(events: list[dict], alerts: list[dict]) -> dict:
    """Build all chart data and KPIs from events + alerts."""
    now = datetime.datetime.now()

    # ── KPIs ──
    failed_count  = sum(1 for e in events if e.get("status") == "FAILED")
    success_count = sum(1 for e in events if e.get("status") == "SUCCESS")
    priv_count    = sum(1 for e in events if e.get("event_type") == "PRIVILEGE_ESCALATION")
    sev_counts    = Counter(a.get("severity","LOW") for a in alerts)
    ti_hits       = sum(1 for a in alerts if a.get("rule") == "THREAT_INTEL_MATCH")

    # ── Hourly failed vs successful ──
    failed_by_hour  = defaultdict(int)
    success_by_hour = defaultdict(int)
    for e in events:
        h = e["timestamp"].strftime("%H:00") if isinstance(e["timestamp"], datetime.datetime) else "?"
        if e.get("status") == "FAILED":
            failed_by_hour[h] += 1
        elif e.get("status") == "SUCCESS":
            success_by_hour[h] += 1

    all_hours     = sorted(set(list(failed_by_hour.keys()) + list(success_by_hour.keys())))
    failed_hourly = [failed_by_hour.get(h, 0)  for h in all_hours]
    success_hourly= [success_by_hour.get(h, 0) for h in all_hours]

    # ── Attack timeline: 5-minute buckets ──
    bucket_counts = defaultdict(int)
    for e in events:
        if e.get("status") == "FAILED":
            ts = e["timestamp"]
            if isinstance(ts, datetime.datetime):
                minute = ts.minute - (ts.minute % 5)
                key = ts.strftime(f"%H:{minute:02d}")
                bucket_counts[key] += 1

    timeline_labels = sorted(bucket_counts.keys())
    timeline_values = [bucket_counts[k] for k in timeline_labels]

    # ── Top IPs ──
    ip_counts = Counter(
        e.get("source_ip","") for e in events
        if e.get("status") == "FAILED" and e.get("source_ip")
    )
    top_ips = ip_counts.most_common(7)

    # ── Top targeted users ──
    user_counts = Counter(
        e.get("user","") for e in events
        if e.get("status") == "FAILED" and e.get("user")
    )
    top_users = user_counts.most_common(7)

    # ── Severity distribution ──
    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW"]

    # ── Alert table ──
    alerts_display = sorted(
        [{"severity": a.get("severity","LOW"),
          "rule":     a.get("rule","?"),
          "timestamp": a["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                       if isinstance(a.get("timestamp"), datetime.datetime)
                       else str(a.get("timestamp","")),
          "risk_score": a.get("risk_score", 0),
          "description": a.get("description","")[:120]}
         for a in alerts],
        key=lambda x: sev_order.index(x["severity"]) if x["severity"] in sev_order else 99
    )

    # ── SIEM internal logs ──
    try:
        from core.siem_logger import get_recent_log_lines
        siem_logs = [l.rstrip() for l in get_recent_log_lines(20)]
    except Exception:
        siem_logs = []

    return {
        "generated_at":    now.strftime("%Y-%m-%d %H:%M:%S"),
        "kpi": {
            "failed_logins":    failed_count,
            "priv_escalations": priv_count,
            "alerts_critical":  sev_counts.get("CRITICAL", 0),
            "alerts_high":      sev_counts.get("HIGH", 0),
            "total_events":     len(events),
            "total_risk":       sum(e.get("risk_score",0) for e in events),
            "threat_intel_hits":ti_hits,
        },
        "alerts":            alerts_display,
        "siem_logs":         siem_logs,
        # JSON-encoded chart data
        "hour_labels":       json.dumps(all_hours),
        "failed_hourly":     json.dumps(failed_hourly),
        "success_hourly":    json.dumps(success_hourly),
        "timeline_labels":   json.dumps(timeline_labels),
        "timeline_values":   json.dumps(timeline_values),
        "ip_labels":         json.dumps([ip  for ip,  _ in top_ips]),
        "ip_values":         json.dumps([cnt for _, cnt in top_ips]),
        "user_labels":       json.dumps([u   for u,   _ in top_users]),
        "user_values":       json.dumps([cnt for _, cnt in top_users]),
        "sev_labels":        json.dumps(sev_order),
        "sev_values":        json.dumps([sev_counts.get(s, 0) for s in sev_order]),
    }


# ════════════════════════════════════════════════════════
# FLASK APP
# ════════════════════════════════════════════════════════

def run_dashboard(events: list[dict], alerts: list[dict],
                  host: str = "127.0.0.1", port: int = 5000):
    if not HAS_FLASK:
        print("[!] Flask not installed. Run:  pip install flask")
        return

    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    # ── Auth decorator ──
    def login_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper

    # ── Routes ──
    @app.route("/login", methods=["GET","POST"])
    def login():
        error = None
        if request.method == "POST":
            u = request.form.get("username","").strip()
            p = request.form.get("password","").strip()
            if u == ADMIN_USERNAME and p == ADMIN_PASSWORD:
                session["logged_in"] = True
                session["user"]      = u
                return redirect(url_for("index"))
            else:
                error = "Invalid username or password."
        return render_template_string(LOGIN_HTML, error=error)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        ctx = _build_context(events, alerts)
        return render_template_string(DASHBOARD_HTML, **ctx)

    @app.route("/api/events")
    @login_required
    def api_events():
        return jsonify([{
            "timestamp":  e["timestamp"].isoformat()
                          if isinstance(e["timestamp"], datetime.datetime)
                          else e.get("timestamp",""),
            "event_type": e.get("event_type",""),
            "user":       e.get("user",""),
            "source_ip":  e.get("source_ip",""),
            "status":     e.get("status",""),
            "risk_score": e.get("risk_score",0),
        } for e in events])

    @app.route("/api/alerts")
    @login_required
    def api_alerts():
        return jsonify([{
            "severity":    a.get("severity",""),
            "rule":        a.get("rule",""),
            "timestamp":   a["timestamp"].isoformat()
                           if isinstance(a.get("timestamp"), datetime.datetime)
                           else str(a.get("timestamp","")),
            "description": a.get("description",""),
            "risk_score":  a.get("risk_score",0),
        } for a in alerts])

    @app.route("/api/stats")
    @login_required
    def api_stats():
        try:
            from core.database import get_db_stats
            return jsonify(get_db_stats())
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

    print(f"\n[*] Dashboard → http://{host}:{port}/")
    print(f"    Login: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")
    print("    Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=False)


# ── Standalone ──
if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from core.collector import generate_demo_logs
    from core.parser import parse_all
    from core.detector import detect
    events, alerts = detect(parse_all(generate_demo_logs()))
    run_dashboard(events, alerts)