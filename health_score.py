"""
SysGuard AI — Health Score Engine
Transparent, weighted, subcategorized 0-100 health score
"""


def calculate_health_score(snapshot: dict, security: dict) -> dict:
    """
    Returns health score with four subcategory pillars:
    Performance | Security | Stability | Memory
    Each point deduction is explained.
    """
    deductions = []

    # ═══════════════════════════════════════════
    # PILLAR 1 — PERFORMANCE (25 points)
    # ═══════════════════════════════════════════
    perf_score = 25

    cpu_pct = snapshot.get("cpu", {}).get("percent", 0)
    if cpu_pct > 90:
        perf_score -= 15
        deductions.append(f"Lost 15pts — CPU critical at {cpu_pct}%")
    elif cpu_pct > 75:
        perf_score -= 8
        deductions.append(f"Lost 8pts — CPU high at {cpu_pct}%")
    elif cpu_pct > 50:
        perf_score -= 3
        deductions.append(f"Lost 3pts — CPU moderate at {cpu_pct}%")

    disk = snapshot.get("disk", [])
    root_disk = next((d for d in disk if d.get("mountpoint") == "/"), disk[0] if disk else {})
    disk_pct = root_disk.get("percent", 0)
    if disk_pct > 95:
        perf_score -= 10
        deductions.append(f"Lost 10pts — Disk critical at {disk_pct}%")
    elif disk_pct > 85:
        perf_score -= 5
        deductions.append(f"Lost 5pts — Disk nearly full at {disk_pct}%")
    elif disk_pct > 70:
        perf_score -= 2
        deductions.append(f"Lost 2pts — Disk usage at {disk_pct}%")

    perf_score = max(0, perf_score)

    # ═══════════════════════════════════════════
    # PILLAR 2 — SECURITY (30 points)
    # ═══════════════════════════════════════════
    sec_score = 30

    fw = security.get("firewall", {})
    if fw.get("status") == "inactive":
        sec_score -= 15
        deductions.append("Lost 15pts — Firewall is DISABLED")
    elif fw.get("status") == "unknown":
        sec_score -= 5
        deductions.append("Lost 5pts — Firewall status unknown")

    update_count = security.get("updates", {}).get("count", 0)
    if update_count > 20:
        sec_score -= 10
        deductions.append(f"Lost 10pts — {update_count} packages pending update")
    elif update_count > 5:
        sec_score -= 5
        deductions.append(f"Lost 5pts — {update_count} packages pending update")
    elif update_count > 0:
        sec_score -= 2
        deductions.append(f"Lost 2pts — {update_count} minor updates available")

    cron_issues = len(security.get("suspicious_crons", []))
    if cron_issues > 0:
        sec_score -= 10
        deductions.append(f"Lost 10pts — {cron_issues} suspicious cron entries")

    failed_ssh = security.get("failed_ssh", {}).get("count", 0)
    if failed_ssh > 100:
        sec_score -= 5
        deductions.append(f"Lost 5pts — {failed_ssh} failed SSH login attempts")
    elif failed_ssh > 20:
        sec_score -= 2
        deductions.append(f"Lost 2pts — {failed_ssh} failed SSH logins")

    sec_score = max(0, sec_score)

    # ═══════════════════════════════════════════
    # PILLAR 3 — STABILITY (25 points)
    # ═══════════════════════════════════════════
    stab_score = 25

    zombies = snapshot.get("processes", {}).get("total_zombie", 0)
    if zombies > 5:
        stab_score -= 10
        deductions.append(f"Lost 10pts — {zombies} zombie processes")
    elif zombies > 0:
        stab_score -= 4
        deductions.append(f"Lost 4pts — {zombies} zombie process(es)")

    aa = security.get("apparmor", {})
    if not aa.get("enabled"):
        stab_score -= 5
        deductions.append("Lost 5pts — AppArmor disabled/unknown")

    swap_pct = snapshot.get("ram", {}).get("swap_percent", 0)
    if swap_pct > 80:
        stab_score -= 10
        deductions.append(f"Lost 10pts — Heavy swap usage at {swap_pct}%")
    elif swap_pct > 50:
        stab_score -= 5
        deductions.append(f"Lost 5pts — Swap in use at {swap_pct}%")
    elif swap_pct > 20:
        stab_score -= 2
        deductions.append(f"Lost 2pts — Light swap use at {swap_pct}%")

    stab_score = max(0, stab_score)

    # ═══════════════════════════════════════════
    # PILLAR 4 — MEMORY (20 points)
    # ═══════════════════════════════════════════
    mem_score = 20

    ram_pct = snapshot.get("ram", {}).get("percent", 0)
    ram_gb = snapshot.get("ram", {}).get("used_gb", 0)
    total_gb = snapshot.get("ram", {}).get("total_gb", 0)

    if ram_pct > 90:
        mem_score -= 15
        deductions.append(f"Lost 15pts — RAM critical at {ram_pct}% ({ram_gb}GB/{total_gb}GB)")
    elif ram_pct > 80:
        mem_score -= 8
        deductions.append(f"Lost 8pts — RAM high at {ram_pct}% ({ram_gb}GB/{total_gb}GB)")
    elif ram_pct > 65:
        mem_score -= 4
        deductions.append(f"Lost 4pts — RAM moderate at {ram_pct}%")

    mem_score = max(0, mem_score)

    # ═══════════════════════════════════════════
    # TOTALS
    # ═══════════════════════════════════════════
    total = perf_score + sec_score + stab_score + mem_score

    if total >= 85:
        status = "Excellent"
        stars = 5
        color = "#48bb78"
    elif total >= 70:
        status = "Good"
        stars = 4
        color = "#68d391"
    elif total >= 55:
        status = "Fair"
        stars = 3
        color = "#ed8936"
    elif total >= 35:
        status = "Poor"
        stars = 2
        color = "#fc8181"
    else:
        status = "Critical"
        stars = 1
        color = "#e53e3e"

    return {
        "score": total,
        "max": 100,
        "status": status,
        "stars": stars,
        "color": color,
        "pillars": {
            "performance": {"score": perf_score, "max": 25, "label": "Performance"},
            "security": {"score": sec_score, "max": 30, "label": "Security"},
            "stability": {"score": stab_score, "max": 25, "label": "Stability"},
            "memory": {"score": mem_score, "max": 20, "label": "Memory"},
        },
        "deductions": deductions,
        "issues": [d for d in deductions],
    }
