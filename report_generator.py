"""
SysGuard AI — Report Generator
Compiles a structured Markdown report from snapshot + security + history.
No external dependencies — runs anywhere Python runs.
"""

from datetime import datetime
from pathlib import Path

REPORTS_DIR = Path(__file__).parent / "reports"


def _ensure_dir():
    REPORTS_DIR.mkdir(exist_ok=True)


def generate_report(snapshot: dict, security: dict, health: dict,
                     history_stats: dict = None) -> str:
    """Returns a complete Markdown report as a string."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sys_info = snapshot.get("system", {})
    cpu = snapshot.get("cpu", {})
    ram = snapshot.get("ram", {})
    disk = snapshot.get("disk", [{}])
    root_disk = next((d for d in disk if d.get("mountpoint") == "/"),
                     disk[0] if disk else {})
    net = snapshot.get("network", {})
    procs = snapshot.get("processes", {})

    L = []
    L.append("# SysGuard AI — System Report")
    L.append("")
    L.append(f"**Generated:** {now}  ")
    L.append(f"**Host:** {sys_info.get('hostname', 'unknown')}  ")
    L.append(f"**Uptime:** {sys_info.get('uptime', 'unknown')}")
    L.append("")
    L.append("---")
    L.append("")

    # Executive summary
    L.append("## Executive Summary")
    L.append("")
    L.append(f"**Health Score: {health.get('score', 0)}/100 — "
              f"{health.get('status', 'Unknown')}**")
    L.append("")
    pillars = health.get("pillars", {})
    for key, p in pillars.items():
        L.append(f"- {p['label']}: {p['score']}/{p['max']}")
    L.append("")

    # Issues
    L.append("## Issues Found")
    L.append("")
    deductions = health.get("deductions", [])
    if deductions:
        for d in deductions:
            L.append(f"- ⚠️ {d}")
    else:
        L.append("No issues detected. System is healthy.")
    L.append("")

    # System snapshot
    L.append("## System Snapshot")
    L.append("")
    L.append(f"- CPU: {cpu.get('percent', 0)}% "
              f"({cpu.get('count_logical', '?')} cores)")
    L.append(f"- RAM: {ram.get('percent', 0)}% "
              f"({ram.get('used_gb', 0)}GB / {ram.get('total_gb', 0)}GB)")
    L.append(f"- Swap: {ram.get('swap_percent', 0)}%")
    L.append(f"- Disk (/): {root_disk.get('percent', 0)}% "
              f"({root_disk.get('used_gb', 0)}GB / {root_disk.get('total_gb', 0)}GB)")
    L.append(f"- Processes: {procs.get('total_count', 0)} total, "
              f"{procs.get('total_zombie', 0)} zombie(s)")
    L.append(f"- Network: {net.get('total_connections', 0)} connections, "
              f"{len(net.get('listening_ports', []))} listening ports")
    L.append("")

    # Security
    L.append("## Security Findings")
    L.append("")
    fw = security.get("firewall", {})
    L.append(f"- Firewall: **{fw.get('label', 'Unknown')}** — {fw.get('detail', '')}")
    aa = security.get("apparmor", {})
    L.append(f"- AppArmor: **{aa.get('label', 'Unknown')}**")
    upd = security.get("updates", {})
    L.append(f"- Pending updates: {upd.get('count', 0)}")
    ssh = security.get("failed_ssh", {})
    L.append(f"- Failed SSH attempts: {ssh.get('count', 0)}")
    ports = security.get("open_ports", [])
    high_risk_ports = [p for p in ports if p.get("risk") == "high"]
    L.append(f"- Open ports: {len(ports)} total, {len(high_risk_ports)} high-risk")
    for p in high_risk_ports:
        L.append(f"  - Port {p['port']} ({p.get('label', '')}) — {p['process']}")
    crons = security.get("suspicious_crons", [])
    L.append(f"- Suspicious cron entries: {len(crons)}")
    L.append("")

    # History
    if history_stats and history_stats.get("samples", 0) > 0:
        L.append("## Historical Context")
        L.append("")
        L.append(f"- Samples collected: {history_stats.get('samples')}")
        L.append(f"- CPU avg/peak: {history_stats.get('cpu_avg')}% / "
                  f"{history_stats.get('cpu_max')}%")
        L.append(f"- RAM avg/peak: {history_stats.get('ram_avg')}% / "
                  f"{history_stats.get('ram_max')}%")
        L.append(f"- Health avg/low: {history_stats.get('score_avg')} / "
                  f"{history_stats.get('score_min')}")
        L.append("")

    # Recommendations
    L.append("## Recommendations")
    L.append("")
    recs = []
    if fw.get("status") == "inactive":
        recs.append("Enable firewall: `sudo ufw enable`")
    if upd.get("count", 0) > 5:
        recs.append("Update packages: `sudo apt update && sudo apt upgrade -y`")
    if ram.get("percent", 0) > 80:
        recs.append("High RAM usage — close unused applications or restart browser")
    if procs.get("total_zombie", 0) > 0:
        recs.append("Zombie processes detected — review parent processes")
    if high_risk_ports:
        recs.append("Review high-risk open ports — close unused services")
    if not recs:
        recs.append("No immediate action required. System is in good standing.")
    for r in recs:
        L.append(f"- {r}")
    L.append("")
    L.append("---")
    L.append("*Report generated by SysGuard AI — Security + AI by Arzoo*")

    return "\n".join(L)


def save_report(content: str, filename: str = None) -> str:
    """Save report to ~/sysguard_ai/reports/. Returns full path."""
    _ensure_dir()
    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sysguard_report_{ts}.md"
    path = REPORTS_DIR / filename
    path.write_text(content, encoding="utf-8")
    return str(path)


def list_reports() -> list:
    """List saved reports, newest first."""
    _ensure_dir()
    files = sorted(REPORTS_DIR.glob("sysguard_report_*.md"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return [str(f) for f in files]
