"""
Mini SIEM — CLI Entry Point
This file is the entry point when the package is installed via pip.

After installation, users run:
    mini-siem run --demo
    mini-siem dashboard --demo
    mini-siem query --alerts
    mini-siem stats
    mini-siem logs

During development, you can also run:
    python -m mini_siem run --demo
"""

import sys
import time
import datetime
from pathlib import Path

try:
    import click
except ImportError:
    print("[!] Click not installed. Run:  pip install mini-siem")
    sys.exit(1)

from mini_siem.core.siem_logger import (
    setup_logging, log_startup, log_shutdown,
    log_alert_fired, log_live_cycle, log_error, get_recent_log_lines,
)


# ── User data directory ──
# Everything gets stored in ~/.mini_siem/
# This is the standard location for CLI tool data on Mac/Linux
USER_DATA_DIR = Path.home() / ".mini_siem"


# ════════════════════════════════════════════════════════
# ROOT COMMAND GROUP
# ════════════════════════════════════════════════════════

@click.group()
@click.version_option(version="1.0.0", prog_name="mini-siem")
@click.option(
    "--log-level",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Internal SIEM log verbosity",
)
@click.pass_context
def cli(ctx, log_level):
    """
    \b
    🛡️  Mini SIEM — Log Monitor & Alert Tool
    ─────────────────────────────────────────
    A professional security monitoring tool that collects
    macOS system logs, detects threats, and alerts you.

    \b
    Quick start:
        mini-siem run --demo
        mini-siem run --demo --live
        mini-siem dashboard --demo
        mini-siem query --alerts
        mini-siem stats

    \b
    Data is stored in:  ~/.mini_siem/
    """
    ctx.ensure_object(dict)
    ctx.obj["log_level"] = log_level
    setup_logging(level=log_level)


# ════════════════════════════════════════════════════════
# COMMAND: run
# ════════════════════════════════════════════════════════

@cli.command()
@click.option("--demo",      is_flag=True, help="Use simulated demo logs (no admin needed)")
@click.option("--live",      is_flag=True, help="Continuous monitoring mode")
@click.option("--interval",  default=10,   help="Seconds between live scans (default: 10)")
@click.option("--hours",     default=24,   help="Hours of logs to look back (default: 24)")
@click.option("--email",     is_flag=True, help="Send email alerts (set env vars first)")
@click.option("--no-report", is_flag=True, help="Skip generating report files")
@click.option("--no-db",     is_flag=True, help="Skip saving to database")
@click.option(
    "--output-dir",
    default=str(USER_DATA_DIR / "reports"),
    help="Directory for output files",
    show_default=True,
)
@click.pass_context
def run(ctx, demo, live, interval, hours, email, no_report, no_db, output_dir):
    """
    Collect logs, detect threats, fire alerts.

    \b
    Examples:
        mini-siem run --demo
        mini-siem run --demo --live
        mini-siem run --demo --live --interval 5
        mini-siem run --hours 48
        mini-siem run --email
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    _print_banner()
    log_startup(mode="demo" if demo else "macos", hours_back=hours)

    if live:
        _run_live(demo, hours, interval, email, no_db, output_path)
    else:
        _run_once(demo, hours, email, no_report, no_db, output_path)


def _run_once(demo, hours, email, no_report, no_db, output_path):
    """Execute a single full analysis pass."""
    start_time = time.time()
    session_id = datetime.datetime.now().strftime("session_%Y%m%d_%H%M%S")

    # ── Database setup ──
    if not no_db:
        from mini_siem.core.database import init_db
        init_db()

    # ── Threat Intel ──
    from mini_siem.core.threat_intel import load_threat_intel
    load_threat_intel()

    # ── 1. Collect ──
    click.echo("\n[1/4] " + click.style("Collecting logs...", fg="cyan"))
    from mini_siem.core.collector import collect_logs
    raw_logs = collect_logs(hours_back=hours, demo_mode=demo)
    click.echo(f"      → {len(raw_logs)} raw entries collected.")
    if not raw_logs:
        click.echo(click.style("[!] No logs collected. Try --demo mode.", fg="yellow"))
        return

    # ── 2. Parse ──
    click.echo("\n[2/4] " + click.style("Parsing & normalising...", fg="cyan"))
    from mini_siem.core.parser import parse_all
    events = parse_all(raw_logs)
    click.echo(f"      → {len(events)} events parsed.")
    if not events:
        click.echo(click.style("[!] No valid events after parsing.", fg="yellow"))
        return

    # ── 3. Detect ──
    click.echo("\n[3/4] " + click.style("Running detection engine...", fg="cyan"))
    from mini_siem.core.detector import detect
    events, alerts = detect(events)

    # Whitelist filtering (suppress your own legitimate admin activity)
    try:
        from mini_siem.core.whitelist import load_whitelist, filter_all_alerts
        load_whitelist()
        real_alerts, whitelisted_alerts = filter_all_alerts(alerts)
        for alert in real_alerts:
            log_alert_fired(alert["rule"], alert["severity"],
                            alert.get("entity", ""), alert["risk_score"])
        for alert in whitelisted_alerts:
            log_alert_fired(alert["rule"], "INFO",
                            alert.get("entity", ""), alert["risk_score"])
        alerts = real_alerts
        if whitelisted_alerts:
            click.echo(click.style(
                f"      → {len(whitelisted_alerts)} alert(s) suppressed "
                f"(trusted activity — audit trail preserved)",
                fg="yellow",
            ))
    except ImportError:
        # whitelist.py is optional
        for alert in alerts:
            log_alert_fired(alert["rule"], alert["severity"],
                            alert.get("entity", ""), alert["risk_score"])

    # ── Save to DB ──
    if not no_db:
        from mini_siem.core.database import save_events, save_alerts
        save_events(events, session_id)
        save_alerts(alerts, session_id)

    # ── 4. Alert output ──
    click.echo("\n[4/4] " + click.style("Dispatching alerts...", fg="cyan"))
    from mini_siem.core.alert import print_all_alerts, save_alerts_to_file
    print_all_alerts(alerts)
    save_alerts_to_file(alerts, output_path / "alerts.txt")

    if email:
        from mini_siem.core.alert import send_email_alerts, email_config_from_env
        send_email_alerts(alerts, email_config_from_env())

    # ── Reports ──
    if not no_report:
        click.echo("\n" + click.style("[*] Generating reports...", fg="cyan"))
        from mini_siem.core.report import (
            build_report_data, generate_txt_report,
            generate_csv_report, generate_alerts_csv,
        )
        data = build_report_data(events, alerts)
        generate_txt_report(data,  output_path / "security_report.txt")
        generate_csv_report(data,  output_path / "security_events.csv")
        generate_alerts_csv(data,  output_path / "security_alerts.csv")
        _print_summary(data)

    duration = time.time() - start_time
    log_shutdown(len(events), len(alerts), duration)
    click.echo(click.style(f"\n[✓] Done in {duration:.1f}s\n", fg="green"))
    click.echo(click.style(
        f"    Reports saved to: {output_path}", fg="blue"
    ))


def _run_live(demo, hours, interval, email, no_db, output_path):
    """Continuous monitoring — scans every `interval` seconds."""
    from mini_siem.core.threat_intel import load_threat_intel
    load_threat_intel()

    if not no_db:
        from mini_siem.core.database import init_db
        init_db()

    click.echo(click.style(
        f"\n  🔴  LIVE MONITORING — every {interval}s  |  Ctrl+C to stop\n",
        fg="red", bold=True,
    ))

    cycle = 0
    last_seen_ts = datetime.datetime.now() - datetime.timedelta(hours=hours)

    try:
        while True:
            cycle += 1
            ts_str = datetime.datetime.now().strftime("%H:%M:%S")
            click.echo(click.style(f"[{ts_str}] Cycle {cycle}", fg="blue"), nl=False)

            try:
                from mini_siem.core.collector import collect_logs
                from mini_siem.core.parser    import parse_all
                from mini_siem.core.detector  import detect
                from mini_siem.core.alert     import print_all_alerts, save_alerts_to_file

                raw_logs  = collect_logs(hours_back=1, demo_mode=demo)
                events    = parse_all(raw_logs)
                new_evts  = [e for e in events if e["timestamp"] > last_seen_ts]

                click.echo(f" — {len(new_evts)} new events")

                if new_evts:
                    last_seen_ts = max(e["timestamp"] for e in new_evts)
                    _, alerts    = detect(new_evts)

                    if alerts:
                        print_all_alerts(alerts)
                        save_alerts_to_file(alerts, output_path / "alerts.txt")
                        if not no_db:
                            from mini_siem.core.database import save_events, save_alerts
                            save_events(new_evts, f"live_{cycle}")
                            save_alerts(alerts,   f"live_{cycle}")
                        for a in alerts:
                            log_alert_fired(a["rule"], a["severity"],
                                            a.get("entity", ""), a["risk_score"])
                    log_live_cycle(cycle, len(new_evts), len(alerts))

            except Exception as exc:
                log_error("live_cycle", exc)
                click.echo(click.style(f"  [!] Error: {exc}", fg="red"))

            time.sleep(interval)

    except KeyboardInterrupt:
        click.echo(click.style("\n\n[Stopped] Live monitoring ended.\n", fg="yellow"))


# ════════════════════════════════════════════════════════
# COMMAND: dashboard
# ════════════════════════════════════════════════════════

@cli.command()
@click.option("--host",  default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
@click.option("--port",  default=5000,         help="Port (default: 5000)")
@click.option("--demo",  is_flag=True,         help="Pre-load with demo data")
def dashboard(host, port, demo):
    """
    Launch the web dashboard (login: admin / siem2025).

    \b
    Examples:
        mini-siem dashboard --demo
        mini-siem dashboard --port 8080
    """
    from mini_siem.core.threat_intel import load_threat_intel
    load_threat_intel()

    if demo:
        events, alerts = _load_demo_data()
    else:
        try:
            import datetime as dt
            from mini_siem.core.database import init_db, query_events, query_alerts
            init_db()
            since      = (dt.datetime.now() - dt.timedelta(hours=24)).isoformat()
            raw_events = query_events(since=since, limit=1000)
            events     = []
            for ev in raw_events:
                try:
                    ev["timestamp"] = dt.datetime.fromisoformat(ev["timestamp"])
                    events.append(ev)
                except Exception:
                    pass
            raw_alerts = query_alerts(since=since, limit=500)
            alerts = []
            for al in raw_alerts:
                try:
                    al["timestamp"] = dt.datetime.fromisoformat(al["timestamp"])
                    al.setdefault("events", [])
                    alerts.append(al)
                except Exception:
                    pass
            if not events:
                click.echo("[~] No DB data — using demo mode.")
                events, alerts = _load_demo_data()
        except Exception as exc:
            click.echo(f"[!] DB error ({exc}) — using demo data.")
            events, alerts = _load_demo_data()

    try:
        from mini_siem.core.dashboard import run_dashboard
        run_dashboard(events, alerts, host=host, port=port)
    except ImportError:
        click.echo(click.style("[!] Flask not installed. Run:  pip install flask", fg="red"))


def _load_demo_data():
    from mini_siem.core.collector import generate_demo_logs
    from mini_siem.core.parser    import parse_all
    from mini_siem.core.detector  import detect
    return detect(parse_all(generate_demo_logs()))


# ════════════════════════════════════════════════════════
# COMMAND: query
# ════════════════════════════════════════════════════════

@cli.command()
@click.option("--ip",    default=None, help="Filter by source IP address")
@click.option("--user",  default=None, help="Filter by username (partial match)")
@click.option("--type",  "event_type", default=None,
              type=click.Choice([
                  "FAILED_LOGIN", "SUCCESSFUL_LOGIN",
                  "PRIVILEGE_ESCALATION", "ACCOUNT_LOCKOUT", "UNKNOWN",
              ]),
              help="Filter by event type")
@click.option("--since",  default=None,  help="Start date e.g. 2025-01-15")
@click.option("--limit",  default=50,    help="Max results (default: 50)")
@click.option("--alerts", "show_alerts", is_flag=True,
              help="Query alerts instead of events")
def query(ip, user, event_type, since, limit, show_alerts):
    """
    Search stored events and alerts in the database.

    \b
    Examples:
        mini-siem query --alerts
        mini-siem query --ip 203.0.113.42
        mini-siem query --user admin --type FAILED_LOGIN
        mini-siem query --since 2025-01-15
    """
    try:
        from mini_siem.core.database import init_db, query_events, query_alerts
        init_db()
    except Exception as exc:
        click.echo(f"[!] DB error: {exc}")
        return

    W = 90
    if show_alerts:
        results = query_alerts(since=since, limit=limit)
        if not results:
            click.echo("No alerts found. Run  mini-siem run --demo  first.")
            return
        click.echo(click.style(f"\n{'─'*W}", fg="blue"))
        click.echo(click.style(
            f"  {'SEV':<10} {'RULE':<28} {'TIMESTAMP':<22} SCORE", bold=True
        ))
        click.echo(click.style(f"{'─'*W}", fg="blue"))
        for row in results:
            color = {
                "CRITICAL": "red", "HIGH": "red",
                "MEDIUM": "yellow", "LOW": "cyan",
            }.get(row["severity"], "white")
            click.echo(
                "  " + click.style(f"{row['severity']:<10}", fg=color) +
                f"{row['rule']:<28} {row['timestamp']:<22} {row['risk_score']}"
            )
            click.echo(f"  {'':10}↳ {row['description']}")
        click.echo(click.style(f"{'─'*W}\n", fg="blue"))

    else:
        results = query_events(
            ip=ip, user=user, event_type=event_type, since=since, limit=limit
        )
        if not results:
            click.echo("No events found. Run  mini-siem run --demo  first.")
            return
        click.echo(click.style(f"\n{'─'*W}", fg="blue"))
        click.echo(click.style(
            f"  {'EVENT TYPE':<25} {'USER':<15} {'IP':<18} {'STATUS':<10} {'SCORE':<6} TIMESTAMP",
            bold=True,
        ))
        click.echo(click.style(f"{'─'*W}", fg="blue"))
        for row in results:
            sc = "red" if row["status"] == "FAILED" else "green"
            click.echo(
                f"  {row['event_type']:<25} {(row['user'] or '?'):<15} "
                f"{(row['source_ip'] or '?'):<18} " +
                click.style(f"{row['status']:<10}", fg=sc) +
                f" {row['risk_score']:<6} {row['timestamp']}"
            )
        click.echo(click.style(f"{'─'*W}\n", fg="blue"))

    click.echo(f"  {len(results)} result(s) shown.\n")


# ════════════════════════════════════════════════════════
# COMMAND: stats
# ════════════════════════════════════════════════════════

@cli.command()
def stats():
    """Show database statistics and threat intel summary."""
    try:
        from mini_siem.core.database import (
            init_db, get_db_stats, get_top_ips, get_top_targeted_users,
        )
        init_db()
        db        = get_db_stats()
        top_ips   = get_top_ips(5)
        top_users = get_top_targeted_users(5)
    except Exception as exc:
        click.echo(f"[!] DB error: {exc}")
        return

    from mini_siem.core.threat_intel import load_threat_intel, get_intel_stats
    load_threat_intel()
    ti = get_intel_stats()

    click.echo(click.style("\n  DATABASE", bold=True, fg="cyan"))
    click.echo(f"  {'─'*45}")
    click.echo(f"  Events stored     : {db['total_events']}")
    click.echo(f"  Alerts stored     : {db['total_alerts']}")
    click.echo(click.style(f"  Critical alerts   : {db['critical_alerts']}", fg="red"))
    click.echo(f"  Oldest event      : {db['oldest_event'] or 'N/A'}")
    click.echo(f"  Newest event      : {db['newest_event'] or 'N/A'}")
    click.echo(f"  DB size           : {db['db_size_kb']} KB")
    click.echo(f"  DB location       : {db['db_path']}")

    click.echo(click.style("\n  THREAT INTELLIGENCE", bold=True, fg="cyan"))
    click.echo(f"  {'─'*45}")
    click.echo(f"  Malicious IPs     : {ti['total_ips']}")
    click.echo(f"  CIDR blocks       : {ti['total_cidrs']}")
    click.echo(f"  Intel file        : {ti['file']}")

    if top_ips:
        click.echo(click.style("\n  TOP SUSPICIOUS IPs (all-time)", bold=True))
        click.echo(f"  {'─'*45}")
        for ip, cnt in top_ips:
            click.echo(f"  {ip:<22}  {cnt} failed attempts")

    if top_users:
        click.echo(click.style("\n  TOP TARGETED USERS (all-time)", bold=True))
        click.echo(f"  {'─'*45}")
        for u, cnt in top_users:
            click.echo(f"  {u:<22}  {cnt} failed attempts")

    click.echo(click.style(
        f"\n  Data directory: {USER_DATA_DIR}\n", fg="blue"
    ))


# ════════════════════════════════════════════════════════
# COMMAND: logs
# ════════════════════════════════════════════════════════

@cli.command()
@click.option("--lines", default=30, help="Lines to show (default: 30)")
def logs(lines):
    """View the SIEM's own internal activity log."""
    recent = get_recent_log_lines(lines)
    if not recent:
        click.echo("[~] No internal logs yet. Run  mini-siem run --demo  first.")
        return
    click.echo(click.style(
        f"\n  Last {len(recent)} lines from SIEM activity log\n", bold=True
    ))
    for line in recent:
        line = line.rstrip()
        if "CRITICAL" in line or "ERROR" in line:
            click.echo(click.style(line, fg="red"))
        elif "WARNING" in line:
            click.echo(click.style(line, fg="yellow"))
        else:
            click.echo(line)
    click.echo()


# ════════════════════════════════════════════════════════
# COMMAND: init
# ════════════════════════════════════════════════════════

@cli.command()
def init():
    """
    Set up Mini SIEM data directory for the first time.

    Creates ~/.mini_siem/ with default config files.
    Run this once after installation.
    """
    from mini_siem.core.database    import init_db
    from mini_siem.core.threat_intel import load_threat_intel

    click.echo(click.style("\n  Setting up Mini SIEM...\n", bold=True))

    USER_DATA_DIR.mkdir(parents=True, exist_ok=True)
    (USER_DATA_DIR / "reports").mkdir(exist_ok=True)
    (USER_DATA_DIR / "logs").mkdir(exist_ok=True)

    init_db()
    load_threat_intel()

    click.echo(click.style(
        f"\n  [✓] Mini SIEM ready!\n"
        f"      Data directory : {USER_DATA_DIR}\n"
        f"      Database       : {USER_DATA_DIR / 'siem.db'}\n"
        f"      Threat intel   : {USER_DATA_DIR / 'threat_intel.txt'}\n"
        f"      Logs           : {USER_DATA_DIR / 'logs' / 'siem.log'}\n",
        fg="green",
    ))
    click.echo("  Run your first scan:")
    click.echo(click.style("      mini-siem run --demo\n", fg="cyan"))


# ════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════

def _print_banner():
    click.echo(click.style("""
  ╔╦╗╦╔╗╔╦  ╔═╗╦╔═╗╔╦╗
  ║║║║║║║║  ╚═╗║║╣ ║║║
  ╩ ╩╩╝╚╝╩  ╚═╝╩╚═╝╩ ╩
  Cross-Platform Log Monitor & Alert Tool
    """, fg="cyan", bold=True))
    click.echo(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")


def _print_summary(data: dict):
    click.echo(click.style("\n  SUMMARY", bold=True))
    click.echo(f"  {'─'*40}")
    click.echo(f"  Events          : {data['total_events']}")
    click.echo(f"  Failed logins   : {data['failed_logins']}")
    click.echo(f"  Priv escalations: {data['priv_escalations']}")
    click.echo(f"  Risk score      : {data['total_risk_score']}")
    click.echo(click.style(f"  CRITICAL alerts : {data['alerts_critical']}", fg="red"))
    click.echo(click.style(f"  HIGH alerts     : {data['alerts_high']}", fg="red"))
    click.echo(click.style(f"  MEDIUM alerts   : {data['alerts_medium']}", fg="yellow"))
    if data.get("top_suspicious_ips"):
        click.echo(f"  Top bad IP      : {data['top_suspicious_ips'][0][0]}")
    click.echo()


# ── Entry point when running as a script ──
if __name__ == "__main__":
    cli(obj={})