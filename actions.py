"""
SysGuard AI — Actions Module
Safe system actions with result feedback
"""

import subprocess
import psutil
import os
import shutil


def _run_cmd(cmd, use_sudo=False):
    """Helper to run shell commands safely"""
    try:
        full_cmd = ["sudo"] + cmd if use_sudo else cmd
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode == 0:
            return True, result.stdout.strip() or "Done."
        else:
            return False, result.stderr.strip() or "Command failed."
    except subprocess.TimeoutExpired:
        return False, "Timed out."
    except FileNotFoundError as e:
        return False, f"Command not found: {e}"
    except Exception as e:
        return False, str(e)


def clear_ram_cache():
    """
    Drop page cache, dentries and inodes.
    Requires sudo. On systems without sudo, returns a fallback message.
    """
    ok, msg = _run_cmd(["sh", "-c", "sync && echo 3 > /proc/sys/vm/drop_caches"], use_sudo=True)
    if ok:
        return True, "RAM cache cleared successfully (page cache + dentries + inodes dropped)."
    else:
        # Try user-level cache clear as fallback
        return False, f"Needs sudo to drop caches. Error: {msg}\nTip: Run with sudo or add to /etc/sudoers."


def kill_process(pid: int):
    """Kill a process by PID"""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.terminate()
        return True, f"Process '{name}' (PID {pid}) terminated."
    except psutil.NoSuchProcess:
        return False, f"PID {pid} no longer exists."
    except psutil.AccessDenied:
        return False, f"Access denied — PID {pid} is a system process."
    except Exception as e:
        return False, str(e)


def clean_apt_cache():
    """Clean apt package cache"""
    ok, msg = _run_cmd(["apt-get", "clean"], use_sudo=True)
    if ok:
        return True, "APT cache cleaned."
    else:
        return False, f"APT clean failed: {msg}"


def enable_firewall():
    """Enable UFW firewall. --force avoids the interactive y/n prompt."""
    ok, msg = _run_cmd(["ufw", "--force", "enable"], use_sudo=True)
    if ok:
        return True, "Firewall enabled."
    return False, f"Failed to enable firewall: {msg}"


def disable_firewall():
    """Disable UFW firewall. Use with caution."""
    ok, msg = _run_cmd(["ufw", "disable"], use_sudo=True)
    if ok:
        return True, "Firewall disabled."
    return False, f"Failed to disable firewall: {msg}"


def clean_temp_files():
    """Clean /tmp files older than 1 day"""
    removed = 0
    errors = 0
    try:
        for item in os.listdir("/tmp"):
            item_path = os.path.join("/tmp", item)
            try:
                if os.path.isfile(item_path):
                    os.remove(item_path)
                    removed += 1
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                    removed += 1
            except Exception:
                errors += 1
        return True, f"Cleaned {removed} items from /tmp. {errors} items skipped (in use or protected)."
    except Exception as e:
        return False, str(e)


def clean_journal_logs():
    """Vacuum systemd journal logs older than 3 days"""
    ok, msg = _run_cmd(["journalctl", "--vacuum-time=3d"], use_sudo=True)
    if ok:
        return True, f"Journal logs vacuumed: {msg}"
    return False, f"Journal vacuum failed: {msg}"


def get_disk_usage_breakdown():
    """Returns top directories by size in /home"""
    try:
        result = subprocess.run(
            ["du", "-sh", "--max-depth=2", "/home"],
            capture_output=True, text=True, timeout=20
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            return True, "\n".join(lines[:15])
        return False, "Could not read disk usage."
    except Exception as e:
        return False, str(e)


def check_zombie_processes():
    """Find and report zombie processes"""
    zombies = []
    for p in psutil.process_iter(['pid', 'name', 'status', 'ppid']):
        try:
            if p.info['status'] == 'zombie':
                zombies.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if not zombies:
        return True, "No zombie processes found."
    lines = [f"PID {z['pid']} — {z['name']} (parent: {z['ppid']})" for z in zombies]
    return False, f"Found {len(zombies)} zombie(s):\n" + "\n".join(lines)


def restart_network():
    """Restart NetworkManager"""
    ok, msg = _run_cmd(["systemctl", "restart", "NetworkManager"], use_sudo=True)
    if ok:
        return True, "NetworkManager restarted."
    return False, f"Failed: {msg}"


def get_failed_services():
    """List systemd failed services"""
    ok, msg = _run_cmd(["systemctl", "--failed", "--no-pager", "--plain"])
    if ok:
        if "0 loaded units" in msg or msg.strip() == "":
            return True, "No failed services."
        return True, msg
    return False, f"Could not check services: {msg}"
