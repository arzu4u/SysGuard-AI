"""
SysGuard AI — Network Packet Analysis Engine
==============================================
Wraps tshark for live capture + structured detection of common
attack signatures at the packet level.

STEP 1 — Capture                  (tshark -i <iface>)
STEP 2 — Port Scan Detection      (incomplete TCP handshakes)
STEP 3 — ARP Spoofing Detection   (one IP, multiple MACs)
STEP 4 — DNS Anomaly Detection    (tunneling / exfiltration signs)
STEP 5 — Cleartext Credentials    (HTTP Basic Auth, FTP PASS)
STEP 6 — Conversation Overview    (who's talking to whom, how much)

Privilege note:
tshark needs raw socket access to capture live traffic. The correct,
minimal-privilege way to enable this (NOT full sudo) is to grant the
capability directly to dumpcap, the binary tshark delegates capture to:

    sudo usermod -aG wireshark $USER
    sudo dpkg-reconfigure wireshark-common   # answer "Yes"
    # then log out and back in (group membership needs a new session)

This sets cap_net_raw+eip on /usr/bin/dumpcap specifically — your user
can capture packets without ever needing root for the whole process.

Legal/ethical note:
Only capture traffic on networks you own or are explicitly authorized
to monitor. Capturing traffic on a network you don't control or own
is illegal in most jurisdictions, regardless of intent.
"""

import subprocess
import os
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter

CAPTURE_DIR = Path(__file__).parent / "captures"


def _ensure_capture_dir():
    CAPTURE_DIR.mkdir(exist_ok=True)


def _run_tshark(args: list, timeout: int = 60) -> tuple:
    """Run tshark, strip the noisy 'Running as user root' warning line."""
    try:
        r = subprocess.run(["tshark"] + args, capture_output=True,
                          text=True, timeout=timeout)
        stdout = "\n".join(l for l in r.stdout.split("\n")
                           if "Running as user" not in l)
        return r.returncode == 0, stdout, r.stderr
    except FileNotFoundError:
        return False, "", "tshark not installed. Run: sudo apt install tshark"
    except subprocess.TimeoutExpired:
        return False, "", "tshark command timed out."
    except Exception as e:
        return False, "", str(e)


# ═══════════════════════════════════════════════════════════════════════════
# STEP 1 — INTERFACE LISTING + CAPTURE
# ═══════════════════════════════════════════════════════════════════════════

# Interfaces that are noise for a typical desktop security check
_SKIP_INTERFACES = {"bluetooth-monitor", "nflog", "nfqueue", "dbus-system",
                    "dbus-session", "ciscodump", "dpauxmon", "randpkt",
                    "sdjournal", "sshdump", "udpdump", "wifidump", "any"}


def list_interfaces() -> list:
    """Returns real, usable network interfaces — filters out virtual noise."""
    ok, out, err = _run_tshark(["-D"])
    if not ok:
        return []
    interfaces = []
    for line in out.split("\n"):
        m = re.match(r"^\d+\.\s+(\S+)", line.strip())
        if m and m.group(1) not in _SKIP_INTERFACES:
            interfaces.append(m.group(1))
    return interfaces


def capture_traffic(interface: str, duration_seconds: int = 30,
                     packet_limit: int = 3000) -> dict:
    """
    Captures live traffic, bounded by BOTH time and packet count so it
    never runs away on limited hardware or a busy network.
    """
    _ensure_capture_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = str(CAPTURE_DIR / f"capture_{ts}.pcap")

    ok, out, err = _run_tshark([
        "-i", interface,
        "-a", f"duration:{duration_seconds}",
        "-c", str(packet_limit),
        "-w", out_path
    ], timeout=duration_seconds + 15)

    if not ok:
        return {"success": False, "error": err or "Capture failed.",
                "pcap_path": None}

    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        return {"success": False,
                "error": "No packets captured. Check interface name and permissions.",
                "pcap_path": None}

    return {"success": True, "pcap_path": out_path,
            "size_bytes": os.path.getsize(out_path)}


# ═══════════════════════════════════════════════════════════════════════════
# STEP 2 — PORT SCAN DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def detect_port_scans(pcap_path: str, threshold: int = 15) -> dict:
    """
    Looks for incomplete TCP handshakes (SYN without ACK) — the
    fundamental signature of a port scan. One source IP touching many
    distinct destination ports in the capture window = a scan.
    """
    result = {"scans_detected": [], "raw_syn_count": 0}

    ok, out, err = _run_tshark([
        "-r", pcap_path,
        "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
        "-T", "fields", "-e", "ip.src", "-e", "tcp.dstport",
        "-E", "separator=|"
    ])
    if not ok:
        result["error"] = err
        return result

    ports_by_src = defaultdict(set)
    for line in out.split("\n"):
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) == 2 and parts[0] and parts[1]:
            ports_by_src[parts[0]].add(parts[1])
            result["raw_syn_count"] += 1

    for src_ip, ports in ports_by_src.items():
        if len(ports) >= threshold:
            result["scans_detected"].append({
                "source_ip": src_ip,
                "distinct_ports_hit": len(ports),
                "sample_ports": sorted(list(ports))[:10],
                "severity": "high" if len(ports) >= 50 else "medium"
            })

    return result


# ═══════════════════════════════════════════════════════════════════════════
# STEP 3 — ARP SPOOFING DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def detect_arp_spoofing(pcap_path: str) -> dict:
    """
    Builds an IP -> MAC(s) map from ARP replies. An IP address legitimately
    has exactly one MAC. If it shows more than one within the capture,
    that's the textbook signature of ARP cache poisoning.
    """
    result = {"conflicts": [], "total_arp_replies": 0}

    ok, out, err = _run_tshark([
        "-r", pcap_path, "-Y", "arp.opcode==2",
        "-T", "fields", "-e", "arp.src.proto_ipv4", "-e", "arp.src.hw_mac",
        "-E", "separator=|"
    ])
    if not ok:
        result["error"] = err
        return result

    macs_by_ip = defaultdict(set)
    for line in out.split("\n"):
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) == 2 and parts[0] and parts[1]:
            macs_by_ip[parts[0]].add(parts[1])
            result["total_arp_replies"] += 1

    for ip, macs in macs_by_ip.items():
        if len(macs) > 1:
            result["conflicts"].append({
                "ip": ip,
                "macs_seen": sorted(list(macs)),
                "severity": "high",
                "note": f"{ip} answered from {len(macs)} different MAC addresses — likely ARP spoofing/MITM."
            })

    return result


# ═══════════════════════════════════════════════════════════════════════════
# STEP 4 — DNS ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def detect_dns_anomalies(pcap_path: str, long_query_threshold: int = 50) -> dict:
    """
    Flags two tunneling/exfiltration signatures:
      - Unusually long query names (data smuggled out via subdomains)
      - High proportion of TXT record queries (common tunneling carrier)
    """
    result = {"long_queries": [], "txt_query_count": 0,
              "total_queries": 0, "nxdomain_count": 0}

    ok, out, err = _run_tshark([
        "-r", pcap_path, "-Y", "dns.flags.response==0",
        "-T", "fields", "-e", "dns.qry.name", "-e", "dns.qry.type",
        "-E", "separator=|"
    ])
    if ok:
        for line in out.split("\n"):
            if not line.strip():
                continue
            parts = line.split("|")
            qname = parts[0] if parts else ""
            qtype = parts[1] if len(parts) > 1 else ""
            if not qname:
                continue
            result["total_queries"] += 1
            if len(qname) > long_query_threshold:
                result["long_queries"].append({
                    "query": qname, "length": len(qname),
                    "severity": "high" if len(qname) > 80 else "medium"
                })
            if qtype == "16":  # TXT record
                result["txt_query_count"] += 1

    ok2, out2, _ = _run_tshark([
        "-r", pcap_path, "-Y", "dns.flags.response==1 && dns.flags.rcode==3",
        "-T", "fields", "-e", "dns.qry.name", "-E", "separator=|"
    ])
    if ok2:
        result["nxdomain_count"] = len([l for l in out2.split("\n") if l.strip()])

    return result


# ═══════════════════════════════════════════════════════════════════════════
# STEP 5 — CLEARTEXT CREDENTIAL DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def detect_cleartext_credentials(pcap_path: str) -> dict:
    """
    If this returns ANY result, it's not a 'maybe' — a credential
    crossed the wire in plaintext, visible to anyone capturing traffic.
    """
    result = {"http_basic_auth": [], "ftp_credentials": []}

    ok, out, _ = _run_tshark([
        "-r", pcap_path, "-Y", "http.authorization",
        "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "http.authorization",
        "-E", "separator=|"
    ])
    if ok:
        for line in out.split("\n"):
            if line.strip():
                parts = line.split("|")
                if len(parts) >= 2:
                    result["http_basic_auth"].append({
                        "src": parts[0], "dst": parts[1] if len(parts) > 1 else "",
                        "severity": "high"
                    })

    ok2, out2, _ = _run_tshark([
        "-r", pcap_path, "-Y", 'ftp.request.command=="PASS"',
        "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
        "-E", "separator=|"
    ])
    if ok2:
        for line in out2.split("\n"):
            if line.strip():
                parts = line.split("|")
                result["ftp_credentials"].append({
                    "src": parts[0] if parts else "",
                    "dst": parts[1] if len(parts) > 1 else "",
                    "severity": "high"
                })

    return result


# ═══════════════════════════════════════════════════════════════════════════
# STEP 6 — CONVERSATION OVERVIEW (who's talking to whom)
# ═══════════════════════════════════════════════════════════════════════════

def get_top_conversations(pcap_path: str, top_n: int = 10) -> list:
    """
    Conversation statistics — the foundation for spotting beaconing
    (regular, small, periodic traffic to one external IP is the
    classic signature of malware 'phoning home').
    """
    ok, out, err = _run_tshark(["-r", pcap_path, "-q", "-z", "conv,ip"])
    if not ok:
        return []

    conversations = []
    for line in out.split("\n"):
        m = re.match(
            r"\s*([\d.]+)\s+<->\s+([\d.]+)\s+(\d+)\s+([\d.]+\s*\w*)\s+"
            r"(\d+)\s+([\d.]+\s*\w*)\s+(\d+)\s+([\d.]+\s*\w*)", line
        )
        if m:
            conversations.append({
                "ip_a": m.group(1), "ip_b": m.group(2),
                "frames_total": int(m.group(7)),
                "bytes_total": m.group(8).strip()
            })

    conversations.sort(key=lambda x: x["frames_total"], reverse=True)
    return conversations[:top_n]


# ═══════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR — runs the full pipeline in one call
# ═══════════════════════════════════════════════════════════════════════════

def analyze_network(interface: str, duration_seconds: int = 30,
                     cleanup: bool = True) -> dict:
    """
    Full pipeline: capture, then run every detection step.
    Returns one structured report, same pattern as analyze_file().
    """
    report = {"timestamp": datetime.now().isoformat(),
              "interface": interface, "duration_seconds": duration_seconds}

    cap = capture_traffic(interface, duration_seconds)
    if not cap["success"]:
        report["error"] = cap["error"]
        report["findings_count"] = 0
        return report

    pcap_path = cap["pcap_path"]
    report["pcap_size_bytes"] = cap["size_bytes"]

    report["port_scans"]   = detect_port_scans(pcap_path)
    report["arp_spoofing"] = detect_arp_spoofing(pcap_path)
    report["dns_anomalies"] = detect_dns_anomalies(pcap_path)
    report["credentials"]  = detect_cleartext_credentials(pcap_path)
    report["top_conversations"] = get_top_conversations(pcap_path)

    findings = (len(report["port_scans"].get("scans_detected", [])) +
                len(report["arp_spoofing"].get("conflicts", [])) +
                len(report["dns_anomalies"].get("long_queries", [])) +
                len(report["credentials"].get("http_basic_auth", [])) +
                len(report["credentials"].get("ftp_credentials", [])))
    report["findings_count"] = findings
    report["verdict"] = (f"🔴 {findings} issue(s) found — review below."
                         if findings > 0 else
                         "🟢 No suspicious patterns detected in this capture window.")

    if cleanup and os.path.exists(pcap_path):
        os.remove(pcap_path)
        report["pcap_path"] = None
    else:
        report["pcap_path"] = pcap_path

    return report
