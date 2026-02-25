"""
Mini SIEM — Main CLI Entry Point
Uses Click for a professional command-line interface.

Commands:
    python main.py run           # single analysis run
    python main.py run --live    # continuous monitoring every 10s
    python main.py dashboard     # launch web dashboard
    python main.py query         # search the database
    python main.py stats         # show DB stats
    python main.py logs          # view SIEM's own internal log

Install Click first:  pip install click
"""

import sys
import time
import datetime
from pathlib import Path

try:
    import click
except ImportError:
    print("[!] Click not installed. Run:  pip install click")
    sys.exit(1)

from siem_logger import (
    setup_logging, log_startup, log_shutdown,
    log_alert_fired, log_live_cycle, log_error, get_recent_log_lines,
)


# ════════════════════════════════════════════════════════
# ROOT COMMAND GROUP
# ════════════════════════════════════════════════════════

@click.group()
@click.option("--log-level", default="INFO",
              type=click.Choice(["DEBUG","INFO","WARNING","ERROR"]),
              help="Internal SIEM log verbosity")
@click.pass_context
def cli(ctx, log_level):
    """
    Shield  Mini SIEM — Cross-Platform Log Monitor

    \b
    Quick start:
        python main.py run --demo
        python main.py run --demo --live
        python main.py dashboard --demo
        python main.py query --ip 203.0.113.42
        python main.py stats
    """
    ctx.ensure_object(dict)
    ctx.obj["log_level"] = log_level
    setup_logging(level=log_level)


# ════════════════════════════════════════════════════════
# COMMAND: run
# ════════════════════════════════════════════════════════

@cli.command()
@click.option("--demo",       is_flag=True, help="Use simulated demo logs (no admin needed)")
@click.option("--live",       is_flag=True, help="Continuous monitoring mode")
@click.option("--interval",   default=10,   help="Seconds between live scans (default: 10)")
@click.option("--hours",      default=24,   help="Hours of logs to look back (default: 24)")
@click.option("--email",      is_flag=True, help="Send email alerts (set env vars first)")
@click.option("--no-report",  is_flag=True, help="Skip report file generation")
@click.option("--no-db",      is_flag=True, help="Skip saving to SQLite database")
@click.option("--output-dir", default=".",  help="Directory for output files")
@click.pass_context
def run(ctx, demo, live, interval, hours, email, no_report, no_db, output_dir):
    """
    Collect logs, detect threats, fire alerts.

    \b
    Examples:
        python main.py run --demo
        python main.py run --demo --live --interval 5
        python main.py run --hours 48 --email
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    mode = "demo" if demo else "macos"

    _print_banner()
    log_startup(mode=mode, hours_back=hours)

    if live:
        _run_live(demo, hours, interval, email, no_db, output_path)
    else:
        _run_once(demo, hours, email, no_report, no_db, output_path)


def _run_once(demo, hours, email, no_report, no_db, output_path):
    start_time = time.time()
    session_id = datetime.datetime.now().strftime("session_%Y%m%d_%H%M%S")

    if not no_db:
        from database import init_db
        init_db()

    from threat_intel import load_threat_intel
    load_threat_intel()

    click.echo("\n[1/4] " + click.style("Collecting logs...", fg="cyan"))
    from collector import collect_logs
    raw_logs = collect_logs(hours_back=hours, demo_mode=demo)
    click.echo(f"      → {len(raw_logs)} raw entries collected.")
    if not raw_logs:
        click.echo(click.style("[!] No logs collected. Exiting.", fg="yellow"))
        return

    click.echo("\n[2/4] " + click.style("Parsing & normalising...", fg="cyan"))
    from parser import parse_all
    events = parse_all(raw_logs)

    click.echo("\n[3/4] " + click.style("Running detection engine...", fg="cyan"))
    from detector import detect
    events, alerts = detect(events)
    for alert in alerts:
        log_alert_fired(alert["rule"], alert["severity"],
                        alert.get("entity",""), alert["risk_score"])

    if not no_db:
        from database import save_events, save_alerts
        save_events(events, session_id)
        save_alerts(alerts, session_id)

    click.echo("\n[4/4] " + click.style("Dispatching alerts...", fg="cyan"))
    from alert import print_all_alerts, save_alerts_to_file, send_email_alerts, email_config_from_env
    print_all_alerts(alerts)
    save_alerts_to_file(alerts, output_path / "alerts.txt")
    if email:
        send_email_alerts(alerts, email_config_from_env())

    if not no_report:
        click.echo("\n" + click.style("[*] Generating reports...", fg="cyan"))
        from report import build_report_data, generate_txt_report, generate_csv_report, generate_alerts_csv
        data = build_report_data(events, alerts)
        generate_txt_report(data,  output_path / "security_report.txt")
        generate_csv_report(data,  output_path / "security_events.csv")
        generate_alerts_csv(data,  output_path / "security_alerts.csv")
        _print_summary(data)

    duration = time.time() - start_time
    log_shutdown(len(events), len(alerts), duration)
    click.echo(click.style(f"\n[Done] Completed in {duration:.1f}s\n", fg="green"))


def _run_live(demo, hours, interval, email, no_db, output_path):
    """Continuously poll for new logs every `interval` seconds."""
    from threat_intel import load_threat_intel
    load_threat_intel()

    if not no_db:
        from database import init_db
        init_db()

    click.echo(click.style(
        f"\n  LIVE MONITORING — scanning every {interval}s  |  Ctrl+C to stop\n",
        fg="red", bold=True
    ))

    cycle = 0
    last_seen_ts = datetime.datetime.now() - datetime.timedelta(hours=hours)

    try:
        while True:
            cycle += 1
            ts_str = datetime.datetime.now().strftime("%H:%M:%S")
            click.echo(click.style(f"[{ts_str}] Cycle {cycle}", fg="blue"), nl=False)

            try:
                from collector import collect_logs
                from parser import parse_all
                from detector import detect
                from alert import print_all_alerts, save_alerts_to_file

                raw_logs = collect_logs(hours_back=1, demo_mode=demo)
                events   = parse_all(raw_logs)
                new_evts = [e for e in events if e["timestamp"] > last_seen_ts]

                click.echo(f" — {len(new_evts)} new events")

                if new_evts:
                    last_seen_ts = max(e["timestamp"] for e in new_evts)
                    _, alerts = detect(new_evts)

                    if alerts:
                        print_all_alerts(alerts)
                        save_alerts_to_file(alerts, output_path / "alerts.txt")
                        if not no_db:
                            from database import save_events, save_alerts
                            save_events(new_evts, f"live_{cycle}")
                            save_alerts(alerts, f"live_{cycle}")
                        for a in alerts:
                            log_alert_fired(a["rule"], a["severity"],
                                          a.get("entity",""), a["risk_score"])

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
    Launch the Flask web dashboard.

    \b
    Examples:
        python main.py dashboard --demo
        python main.py dashboard --port 8080
    """
    from threat_intel import load_threat_intel
    load_threat_intel()

    events, alerts = [], []

    if demo:
        events, alerts = _load_demo_data()
    else:
        try:
            import datetime as dt
            from database import init_db, query_events, query_alerts
            init_db()
            since = (dt.datetime.now() - dt.timedelta(hours=24)).isoformat()

            raw_events = query_events(since=since, limit=1000)
            events = []
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
                click.echo("[~] No DB data — switching to demo mode.")
                events, alerts = _load_demo_data()

        except Exception as exc:
            click.echo(f"[!] DB error ({exc}) — using demo data.")
            events, alerts = _load_demo_data()

    try:
        from dashboard import run_dashboard
        run_dashboard(events, alerts, host=host, port=port)
    except ImportError:
        click.echo(click.style("[!] Flask not installed. Run:  pip install flask", fg="red"))


def _load_demo_data():
    from collector import generate_demo_logs
    from parser import parse_all
    from detector import detect
    raw = generate_demo_logs()
    events = parse_all(raw)
    events, alerts = detect(events)
    return events, alerts


# ════════════════════════════════════════════════════════
# COMMAND: query
# ════════════════════════════════════════════════════════

@cli.command()
@click.option("--ip",    default=None, help="Filter by source IP")
@click.option("--user",  default=None, help="Filter by username (partial match)")
@click.option("--type",  "event_type", default=None,
              type=click.Choice(["FAILED_LOGIN","SUCCESSFUL_LOGIN",
                                 "PRIVILEGE_ESCALATION","ACCOUNT_LOCKOUT","UNKNOWN"]),
              help="Filter by event type")
@click.option("--since", default=None, help="Start timestamp e.g. 2025-01-15")
@click.option("--limit", default=50,   help="Max results (default: 50)")
@click.option("--alerts","show_alerts", is_flag=True, help="Query alerts instead of events")
def query(ip, user, event_type, since, limit, show_alerts):
    """
    Search the database for events or alerts.

    \b
    Examples:
        python main.py query --ip 203.0.113.42
        python main.py query --user admin --type FAILED_LOGIN
        python main.py query --alerts --since 2025-01-15
        python main.py query --alerts (show all recent alerts)
    """
    try:
        from database import init_db, query_events, query_alerts
        init_db()
    except Exception as exc:
        click.echo(f"[!] DB error: {exc}")
        return

    W = 90
    if show_alerts:
        results = query_alerts(severity=None, rule=None, since=since, limit=limit)
        if not results:
            click.echo("No alerts found.")
            return
        click.echo(click.style(f"\n{'─'*W}", fg="blue"))
        click.echo(click.style(f"  {'SEV':<10} {'RULE':<28} {'TIMESTAMP':<22} {'SCORE'}", bold=True))
        click.echo(click.style(f"{'─'*W}", fg="blue"))
        for row in results:
            color = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"cyan"}.get(row["severity"],"white")
            click.echo(
                "  " + click.style(f"{row['severity']:<10}", fg=color) +
                f"{row['rule']:<28} {row['timestamp']:<22} {row['risk_score']}"
            )
            click.echo(f"  {'':10}↳ {row['description']}")
        click.echo(click.style(f"{'─'*W}\n", fg="blue"))
    else:
        results = query_events(ip=ip, user=user, event_type=event_type, since=since, limit=limit)
        if not results:
            click.echo("No events found.")
            return
        click.echo(click.style(f"\n{'─'*W}", fg="blue"))
        click.echo(click.style(
            f"  {'EVENT TYPE':<25} {'USER':<15} {'IP':<18} {'STATUS':<10} {'SCORE':<6} TIMESTAMP",
            bold=True
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
        from database import init_db, get_db_stats, get_top_ips, get_top_targeted_users
        init_db()
        db        = get_db_stats()
        top_ips   = get_top_ips(5)
        top_users = get_top_targeted_users(5)
    except Exception as exc:
        click.echo(f"[!] DB error: {exc}")
        return

    from threat_intel import load_threat_intel, get_intel_stats
    load_threat_intel()
    ti = get_intel_stats()

    click.echo(click.style("\n  DATABASE", bold=True, fg="cyan"))
    click.echo(f"  {'─'*40}")
    click.echo(f"  Events stored   : {db['total_events']}")
    click.echo(f"  Alerts stored   : {db['total_alerts']}")
    click.echo(click.style(f"  Critical alerts : {db['critical_alerts']}", fg="red"))
    click.echo(f"  Oldest event    : {db['oldest_event'] or 'N/A'}")
    click.echo(f"  DB size         : {db['db_size_kb']} KB  ({db['db_path']})")

    click.echo(click.style("\n  THREAT INTELLIGENCE", bold=True, fg="cyan"))
    click.echo(f"  {'─'*40}")
    click.echo(f"  Malicious IPs   : {ti['total_ips']}")
    click.echo(f"  CIDR blocks     : {ti['total_cidrs']}")
    click.echo(f"  Intel file      : {ti['file']}")

    if top_ips:
        click.echo(click.style("\n  TOP SUSPICIOUS IPs (all-time)", bold=True))
        click.echo(f"  {'─'*40}")
        for ip, cnt in top_ips:
            click.echo(f"  {ip:<22} {cnt} failed attempts")

    if top_users:
        click.echo(click.style("\n  TOP TARGETED USERS (all-time)", bold=True))
        click.echo(f"  {'─'*40}")
        for u, cnt in top_users:
            click.echo(f"  {u:<22} {cnt} failed attempts")
    click.echo()


# ════════════════════════════════════════════════════════
# COMMAND: logs
# ════════════════════════════════════════════════════════

@cli.command()
@click.option("--lines", default=30, help="How many recent lines to show")
def logs(lines):
    """View the SIEM's own internal activity log (logs/siem.log)."""
    recent = get_recent_log_lines(lines)
    if not recent:
        click.echo("[~] No internal logs yet. Run a scan first.")
        return
    click.echo(click.style(f"\n  Last {len(recent)} lines from logs/siem.log\n", bold=True))
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


if __name__ == "__main__":
    cli(obj={})