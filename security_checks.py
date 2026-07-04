"""
SysGuard AI — Security Checks Module
CEH-grade security audit for Ubuntu systems
"""

import subprocess
import psutil
import os
import stat
import socket


def check_firewall_status():
    """
    Check UFW firewall status.
    Primary method: systemctl is-active (no root required, reliable).
    Fallback: ufw status (requires root — only works with sudo or NOPASSWD entry).
    """
    # Method 1 — systemctl (non-privileged, most reliable)
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "ufw"],
            capture_output=True, text=True, timeout=5
        )
        state = result.stdout.strip().lower()
        if state == "active":
            return {"status": "active", "label": "ON", "risk": "low",
                    "detail": "UFW firewall service is active."}
        elif state in ("inactive", "failed"):
            return {"status": "inactive", "label": "OFF", "risk": "high",
                    "detail": "UFW firewall is DISABLED. Run: sudo ufw enable"}
        # state is "unknown"/empty/error — fall through to method 2
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Method 2 — ufw status directly (needs root; works via NOPASSWD sudoers)
    try:
        result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
        output = (result.stdout + result.stderr).lower()
        if "you need to be root" in output or "permission denied" in output:
            return {"status": "unknown", "label": "NO PERMISSION", "risk": "medium",
                    "detail": "Cannot verify firewall without elevated access. See sudo setup."}
        if "status: active" in output:
            return {"status": "active", "label": "ON", "risk": "low",
                    "detail": "UFW firewall is active."}
        if "inactive" in output:
            return {"status": "inactive", "label": "OFF", "risk": "high",
                    "detail": "UFW firewall is DISABLED. Run: sudo ufw enable"}
    except FileNotFoundError:
        return {"status": "unknown", "label": "N/A", "risk": "medium",
                "detail": "UFW not installed. Install: sudo apt install ufw"}
    except Exception as e:
        return {"status": "unknown", "label": "N/A", "risk": "medium", "detail": str(e)}

    return {"status": "unknown", "label": "N/A", "risk": "medium",
            "detail": "Could not determine firewall status."}


def check_open_ports():
    """Return list of listening ports with process names"""
    open_ports = []
    risky_ports = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3",
                   139: "NetBIOS", 445: "SMB", 3389: "RDP", 5900: "VNC"}
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr:
                port = conn.laddr.port
                risk = "high" if port in risky_ports else "low"
                label = risky_ports.get(port, "")
                proc_name = "unknown"
                try:
                    if conn.pid:
                        proc_name = psutil.Process(conn.pid).name()
                except Exception:
                    pass
                open_ports.append({
                    "port": port,
                    "process": proc_name,
                    "risk": risk,
                    "label": label,
                    "pid": conn.pid
                })
    except Exception:
        pass
    return sorted(open_ports, key=lambda x: (x["risk"] == "low", x["port"]))


def check_failed_ssh_logins(max_lines=20):
    """Parse auth.log for failed SSH login attempts"""
    log_paths = ["/var/log/auth.log", "/var/log/secure"]
    results = {"count": 0, "recent": [], "top_ips": {}}

    for log_path in log_paths:
        if not os.path.exists(log_path):
            continue
        try:
            result = subprocess.run(
                ["grep", "Failed password", log_path],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().split("\n")
            lines = [l for l in lines if l.strip()]
            results["count"] = len(lines)
            results["recent"] = lines[-max_lines:]

            for line in lines:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "from" and i + 1 < len(parts):
                        ip = parts[i + 1]
                        results["top_ips"][ip] = results["top_ips"].get(ip, 0) + 1

            results["top_ips"] = dict(
                sorted(results["top_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
            )
            break
        except Exception:
            continue

    if not os.path.exists("/var/log/auth.log") and not os.path.exists("/var/log/secure"):
        results["note"] = "Auth log not accessible. Run with sudo for full results."

    return results


def check_world_writable_files(search_path="/tmp", limit=20):
    """Find world-writable files (security risk)"""
    risky = []
    try:
        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    mode = os.stat(fpath).st_mode
                    if mode & stat.S_IWOTH:
                        risky.append(fpath)
                        if len(risky) >= limit:
                            return risky
                except Exception:
                    pass
    except Exception:
        pass
    return risky


def check_suid_binaries():
    """Find SUID binaries (can be privilege escalation vectors)"""
    known_safe = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
        "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/newgrp",
        "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/sbin/pppd", "/bin/ping", "/usr/bin/pkexec"
    }
    suid_files = []
    try:
        result = subprocess.run(
            ["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
             "-perm", "-4000", "-type", "f"],
            capture_output=True, text=True, timeout=15
        )
        for path in result.stdout.strip().split("\n"):
            path = path.strip()
            if path and path not in known_safe:
                suid_files.append({"path": path, "known": False, "risk": "review"})
            elif path in known_safe:
                suid_files.append({"path": path, "known": True, "risk": "normal"})
    except Exception:
        pass
    return suid_files


def check_suspicious_crons():
    """
    Check crontab and cron directories for genuinely suspicious entries.

    v2 — fixed from naive keyword matching (which flagged rkhunter's own
    legitimate updater and Chrome's own legitimate updater as "malware"
    because they contain the words wget/curl/base64, like nearly every
    update script ever written).

    Now uses: (1) YARA rules that match DANGEROUS COMBINATIONS rather
    than single common words, and (2) dpkg package provenance — a file
    owned by a verified installed package is far less suspicious than
    an unowned file in the same location.
    """
    try:
        from malware_analysis import scan_with_yara, check_package_provenance
    except ImportError:
        return []  # malware_analysis.py not present — skip gracefully

    findings = []
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]

    for cdir in cron_dirs:
        if not os.path.isdir(cdir):
            continue
        for fname in os.listdir(cdir):
            fpath = os.path.join(cdir, fname)
            if not os.path.isfile(fpath):
                continue

            yara_result = scan_with_yara(fpath)
            matches = yara_result.get("matches", [])
            if not matches:
                continue  # no dangerous pattern — not flagged at all

            provenance = check_package_provenance(fpath)
            if provenance.get("verified"):
                # Owned by an installed package — almost certainly legitimate,
                # even if it happens to contain a flagged pattern.
                continue

            for m in matches:
                findings.append({
                    "file": fpath,
                    "keyword": m["rule"],
                    "risk": m["severity"],
                    "description": m["description"],
                    "owned_by_package": None
                })

    # Check user crontab the same way
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True,
                               text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            tmp_path = "/tmp/.sysguard_crontab_check"
            with open(tmp_path, "w") as f:
                f.write(result.stdout)
            yara_result = scan_with_yara(tmp_path)
            for m in yara_result.get("matches", []):
                findings.append({
                    "file": "user crontab",
                    "keyword": m["rule"],
                    "risk": m["severity"],
                    "description": m["description"],
                    "owned_by_package": None
                })
            os.remove(tmp_path)
    except Exception:
        pass

    return findings


def check_apparmor_status():
    """Check AppArmor status"""
    try:
        result = subprocess.run(["aa-status", "--enabled"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return {"enabled": True, "label": "Enabled", "risk": "low"}
    except FileNotFoundError:
        pass
    try:
        result = subprocess.run(["systemctl", "is-active", "apparmor"], capture_output=True, text=True, timeout=5)
        if "active" in result.stdout:
            return {"enabled": True, "label": "Enabled", "risk": "low"}
    except Exception:
        pass
    return {"enabled": False, "label": "Disabled/Unknown", "risk": "medium"}


def check_pending_updates():
    """Check number of available apt updates"""
    try:
        result = subprocess.run(
            ["apt-get", "--simulate", "upgrade"],
            capture_output=True, text=True, timeout=20
        )
        lines = result.stdout.split("\n")
        for line in lines:
            if "upgraded," in line:
                count = int(line.strip().split()[0])
                risk = "high" if count > 20 else "medium" if count > 5 else "low"
                return {"count": count, "risk": risk, "detail": line.strip()}
    except Exception:
        pass
    return {"count": 0, "risk": "low", "detail": "Could not check updates."}


def run_security_audit():
    """
    Run all security checks and return a structured report.
    This is the master function called by the Streamlit UI.
    """
    return {
        "firewall": check_firewall_status(),
        "open_ports": check_open_ports(),
        "failed_ssh": check_failed_ssh_logins(),
        "apparmor": check_apparmor_status(),
        "updates": check_pending_updates(),
        "suspicious_crons": check_suspicious_crons(),
        "world_writable": check_world_writable_files(),
    }
