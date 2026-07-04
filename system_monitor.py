"""
SysGuard AI — System Monitor Module
Collects all system stats via psutil
"""

import psutil
import platform
import datetime
import socket
import subprocess
import os


def get_cpu_info():
    return {
        "percent": psutil.cpu_percent(interval=0.5),
        "count_logical": psutil.cpu_count(logical=True),
        "count_physical": psutil.cpu_count(logical=False),
        "freq_current": round(psutil.cpu_freq().current, 1) if psutil.cpu_freq() else 0,
        "per_core": psutil.cpu_percent(interval=0.3, percpu=True),
    }


def get_ram_info():
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "total_gb": round(vm.total / (1024 ** 3), 2),
        "used_gb": round(vm.used / (1024 ** 3), 2),
        "available_gb": round(vm.available / (1024 ** 3), 2),
        "percent": vm.percent,
        "swap_total_gb": round(swap.total / (1024 ** 3), 2),
        "swap_used_gb": round(swap.used / (1024 ** 3), 2),
        "swap_percent": swap.percent,
    }


def get_disk_info():
    partitions = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            partitions.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": round(usage.total / (1024 ** 3), 2),
                "used_gb": round(usage.used / (1024 ** 3), 2),
                "free_gb": round(usage.free / (1024 ** 3), 2),
                "percent": usage.percent,
            })
        except PermissionError:
            pass
    return partitions


def get_network_info():
    net = psutil.net_io_counters()
    connections = psutil.net_connections(kind='inet')
    listening_ports = []
    for c in connections:
        if c.status == 'LISTEN' and c.laddr:
            proc_name = "unknown"
            try:
                if c.pid:
                    proc_name = psutil.Process(c.pid).name()
            except Exception:
                pass
            listening_ports.append({
                "port": c.laddr.port,
                "process": proc_name,
                "pid": c.pid
            })
    listening_ports = sorted(listening_ports, key=lambda x: x["port"])

    # Get active connections with remote IPs
    active_connections = []
    for c in connections:
        if c.status == 'ESTABLISHED' and c.raddr:
            try:
                proc_name = psutil.Process(c.pid).name() if c.pid else "unknown"
            except Exception:
                proc_name = "unknown"
            active_connections.append({
                "local_port": c.laddr.port if c.laddr else 0,
                "remote_ip": c.raddr.ip,
                "remote_port": c.raddr.port,
                "process": proc_name,
                "pid": c.pid
            })

    return {
        "bytes_sent_mb": round(net.bytes_sent / (1024 ** 2), 2),
        "bytes_recv_mb": round(net.bytes_recv / (1024 ** 2), 2),
        "packets_sent": net.packets_sent,
        "packets_recv": net.packets_recv,
        "listening_ports": listening_ports[:15],
        "active_connections": active_connections[:10],
        "total_connections": len(connections),
    }


def _is_kernel_thread(proc):
    """Returns True if this is a kernel thread — not useful to show users"""
    try:
        # Kernel threads have empty cmdline
        if proc.cmdline() == []:
            return True
        # Also filter by known kernel thread names
        kernel_names = {
            'kthreadd', 'ksoftirqd', 'migration', 'rcu_sched', 'rcu_bh',
            'watchdog', 'kworker', 'kdevtmpfs', 'netns', 'khungtaskd',
            'writeback', 'kintegrityd', 'bioset', 'kblockd', 'ata_sff',
            'md', 'edac-poller', 'kswapd', 'fsnotify_mark', 'ecryptfs',
            'kthrotld', 'ipv6_addrconf', 'deferwq', 'charger_manager',
            'scsi_eh', 'irq', 'pool_workqueue_release', 'kcompactd',
        }
        name = proc.name().lower()
        for kname in kernel_names:
            if name.startswith(kname):
                return True
        return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return True


def get_top_processes(n=8):
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent',
                                   'status', 'username', 'create_time']):
        try:
            if _is_kernel_thread(p):
                continue
            info = p.info
            # Add uptime
            if info.get('create_time'):
                uptime_secs = datetime.datetime.now().timestamp() - info['create_time']
                info['uptime_hours'] = round(uptime_secs / 3600, 1)
            else:
                info['uptime_hours'] = 0
            procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    by_cpu = sorted(procs, key=lambda x: x.get('cpu_percent') or 0, reverse=True)[:n]
    by_mem = sorted(procs, key=lambda x: x.get('memory_percent') or 0, reverse=True)[:n]

    # Count all processes including kernel threads for stats
    all_procs = list(psutil.process_iter(['status']))
    return {
        "by_cpu": by_cpu,
        "by_mem": by_mem,
        "user_count": len(procs),
        "total_running": len([p for p in all_procs if p.info.get('status') == 'running']),
        "total_sleeping": len([p for p in all_procs if p.info.get('status') == 'sleeping']),
        "total_zombie": len([p for p in all_procs if p.info.get('status') == 'zombie']),
        "total_count": len(all_procs),
    }


def get_system_info():
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_time
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, _ = divmod(remainder, 60)
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version()[:60],
        "distro": platform.platform(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "boot_time": boot_time.strftime("%Y-%m-%d %H:%M"),
        "uptime": f"{hours}h {minutes}m",
        "uptime_seconds": int(uptime.total_seconds()),
    }


def get_boot_analysis():
    """
    Analyze boot time using systemd-analyze.
    Returns structured boot timing data.
    """
    result = {
        "available": False,
        "total_seconds": 0,
        "firmware": 0,
        "loader": 0,
        "kernel": 0,
        "userspace": 0,
        "slow_units": [],
        "summary": ""
    }

    try:
        # Get overall boot time
        r = subprocess.run(
            ["systemd-analyze"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            result["available"] = True
            output = r.stdout.strip()
            result["summary"] = output

            # Parse timing values
            import re
            # Look for patterns like "3.142s" or "1min 2.3s"
            def parse_time(s):
                if not s:
                    return 0
                total = 0
                mins = re.search(r'(\d+)min', s)
                secs = re.search(r'([\d.]+)s', s)
                if mins:
                    total += int(mins.group(1)) * 60
                if secs:
                    total += float(secs.group(1))
                return round(total, 2)

            fw_match = re.search(r'firmware\s+([\d.]+\w+)', output)
            loader_match = re.search(r'loader\s+([\d.]+\w+)', output)
            kernel_match = re.search(r'kernel\s+([\d.]+\w+)', output)
            us_match = re.search(r'userspace\s+([\d\w\s.]+)\s*\n', output)

            if fw_match:
                result["firmware"] = parse_time(fw_match.group(1))
            if loader_match:
                result["loader"] = parse_time(loader_match.group(1))
            if kernel_match:
                result["kernel"] = parse_time(kernel_match.group(1))
            if us_match:
                result["userspace"] = parse_time(us_match.group(1))

        # Get slowest units
        r2 = subprocess.run(
            ["systemd-analyze", "blame"],
            capture_output=True, text=True, timeout=10
        )
        if r2.returncode == 0:
            lines = r2.stdout.strip().split('\n')
            slow = []
            for line in lines[:10]:
                line = line.strip()
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        slow.append({
                            "time": parts[0],
                            "unit": parts[-1]
                        })
            result["slow_units"] = slow

    except FileNotFoundError:
        result["summary"] = "systemd-analyze not available"
    except Exception as e:
        result["summary"] = str(e)

    return result


def get_full_snapshot():
    """Returns complete system snapshot — used by AI advisor"""
    cpu = get_cpu_info()
    ram = get_ram_info()
    disk = get_disk_info()
    net = get_network_info()
    procs = get_top_processes(5)
    sys_info = get_system_info()

    return {
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "network": net,
        "processes": procs,
        "system": sys_info,
    }
