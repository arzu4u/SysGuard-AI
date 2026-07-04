"""
SysGuard AI — Main Streamlit Application
Ubuntu System Intelligence Dashboard
"""

import streamlit as st
import time
import urllib.parse
from metrics_store import MetricsStore, BackgroundSaver
from cache_manager import CacheManager
from system_monitor import (
    get_cpu_info, get_ram_info, get_disk_info,
    get_network_info, get_top_processes,
    get_system_info, get_full_snapshot, get_boot_analysis
)
from actions import (
    clear_ram_cache, kill_process, clean_apt_cache,
    clean_temp_files, clean_journal_logs,
    check_zombie_processes, get_failed_services,
    enable_firewall, disable_firewall
)
from security_checks import (
    check_firewall_status, check_open_ports,
    check_failed_ssh_logins, check_apparmor_status,
    check_pending_updates, check_suspicious_crons,
    check_world_writable_files, run_security_audit
)
from health_score import calculate_health_score
from ai_advisor import (
    is_ollama_running, get_available_models,
    analyze_system, chat_with_system
)
from report_generator import generate_report, save_report
from malware_analysis import analyze_file, run_rkhunter_check
try:
    from network_analysis import list_interfaces_with_diagnostics, analyze_network
except ImportError:
    from network_analysis import list_interfaces, analyze_network
    def list_interfaces_with_diagnostics():
        interfaces = list_interfaces()
        return interfaces, {"command": "tshark -D", "returncode_ok": bool(interfaces),
                            "tshark_found": True, "stdout": "", "stderr": ""}

# ─── Page Config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SysGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── CSS ─────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* ── Global app background ── */
    .stApp { background: #080d14; }
    [data-testid="stAppViewContainer"] { background: #080d14; }
    [data-testid="stMain"]             { background: #080d14; }

    /* ── Hide ALL Streamlit chrome so nothing sits on top of content ── */
    header[data-testid="stHeader"] { display: none !important; }
    [data-testid="stToolbar"]      { display: none !important; }
    .stAppToolbar                  { display: none !important; }
    .stDecoration                  { display: none !important; }
    #MainMenu                      { display: none !important; }
    footer                         { display: none !important; }

    /* ── Content padding — tight to the top now that header is gone ── */
    .block-container {
        padding-top: 1.2rem !important;
        padding-left: 1.5rem !important;
        padding-right: 1.5rem !important;
        max-width: 100% !important;
    }

    /* ── Main content buttons — dark theme ── */
    [data-testid="stMain"] [data-testid="stButton"] > button {
        background: #0d1420 !important;
        border: 1px solid #1e2d3d !important;
        color: #c5cdd8 !important;
        border-radius: 10px !important;
        font-size: 0.82rem !important;
        transition: all 0.15s ease !important;
    }
    [data-testid="stMain"] [data-testid="stButton"] > button:hover {
        background: #1a2d40 !important;
        border-color: #00d4aa !important;
        color: #00d4aa !important;
    }
    /* Primary/danger buttons keep their color */
    [data-testid="stMain"] [data-testid="stButton"] > button[kind="primary"] {
        background: #9b2335 !important;
        border-color: #c53030 !important;
        color: #fff !important;
    }
    [data-testid="stMain"] [data-testid="stButton"] > button[kind="primary"]:hover {
        background: #c53030 !important;
        color: #fff !important;
    }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a0e1a 0%, #0d1420 60%, #0a1628 100%);
        border-right: 1px solid #1a2535;
    }
    [data-testid="stSidebar"] > div { padding: 0 !important; }

    /* ── Sidebar nav buttons — default state ── */
    [data-testid="stSidebar"] [data-testid="stButton"] > button {
        background: transparent !important;
        border: 1px solid #1e2d3d !important;
        border-radius: 10px !important;
        color: #8899aa !important;
        text-align: left !important;
        padding: 0.6rem 1rem !important;
        font-size: 0.82rem !important;
        font-weight: 500 !important;
        width: 100% !important;
        margin-bottom: 4px !important;
        transition: all 0.15s ease !important;
    }
    [data-testid="stSidebar"] [data-testid="stButton"] > button:hover {
        background: #1a2d40 !important;
        border-color: #00d4aa !important;
        color: #00d4aa !important;
    }
    /* Active nav item */
    [data-testid="stSidebar"] [data-testid="stButton"] > button[kind="primaryFormSubmit"],
    [data-testid="stSidebar"] [data-testid="stButton"] > button[kind="primary"] {
        background: #0f2233 !important;
        border-color: #00d4aa !important;
        color: #00d4aa !important;
        font-weight: 700 !important;
    }

    /* ── Section headers ── */
    .section-header {
        color: #00d4aa;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        border-bottom: 1px solid #1a2535;
        padding-bottom: 0.4rem;
        margin-bottom: 0.9rem;
    }

    /* ── Gauge card container ── */
    .gauge-card {
        background: #0d1420;
        border: 1px solid #1a2535;
        border-radius: 14px;
        padding: 1rem 0.5rem 0.7rem;
        text-align: center;
    }

    /* ── Info card ── */
    .info-card {
        background: #0d1420;
        border: 1px solid #1a2535;
        border-radius: 14px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.6rem;
    }

    /* ── Pillar card ── */
    .pillar-card {
        background: #0d1420;
        border: 1px solid #1a2535;
        border-radius: 12px;
        padding: 0.9rem 0.5rem;
        text-align: center;
    }
    .pillar-score { font-size: 1.6rem; font-weight: 800; }
    .pillar-label { font-size: 0.65rem; color: #6b7c93;
                    text-transform: uppercase; letter-spacing: 1px; }

    /* ── Risk cards ── */
    .risk-card {
        border-radius: 10px;
        padding: 0.85rem 1rem;
        margin-bottom: 0.55rem;
        border-left: 3px solid;
    }
    .risk-high   { background: #1e1015; border-color: #e53e3e; }
    .risk-medium { background: #1a170a; border-color: #ed8936; }
    .risk-low    { background: #0d1a10; border-color: #48bb78; }

    /* ── Fix command ── */
    .fix-cmd {
        font-family: 'Courier New', monospace;
        background: #060a10;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.78rem;
        color: #00d4aa;
    }

    /* ── Process row ── */
    .proc-row {
        display: flex;
        justify-content: space-between;
        padding: 0.4rem 0.7rem;
        border-radius: 7px;
        margin-bottom: 0.3rem;
        background: #0d1420;
        border: 1px solid #1a2535;
    }

    /* ── Metric overrides ── */
    [data-testid="stMetricValue"] { color: #e2e8f0 !important; font-size: 1.1rem !important; }
    [data-testid="stMetricLabel"] { color: #6b7c93 !important; font-size: 0.75rem !important; }

    /* ── Streamlit default overrides ── */
    .stMarkdown p { color: #c5cdd8; }
    hr { border-color: #1a2535 !important; }

    /* ── Sidebar nav buttons ── */
    [data-testid="stSidebar"] .stButton > button {
        background: #0d1420;
        border: 1px solid #1a2535;
        border-radius: 10px;
        color: #8899aa;
        text-align: left;
        width: 100%;
        padding: 0.5rem 0.85rem;
        font-size: 0.79rem;
        font-weight: 500;
        margin-bottom: 0;
        transition: all 0.15s;
    }
    [data-testid="stSidebar"] .stButton > button:hover {
        border-color: #00d4aa;
        color: #00d4aa;
        background: #0a1625;
    }
    [data-testid="stSidebar"] .stButton > button[kind="primary"],
    [data-testid="stSidebar"] .stButton > button[kind="primaryFormSubmit"] {
        background: #0f2030 !important;
        border-color: #00d4aa !important;
        color: #00d4aa !important;
    }

    /* ── Main content buttons dark ── */
    [data-testid="stMain"] .stButton > button {
        background: #0d1420 !important;
        border: 1px solid #1e2d3d !important;
        color: #c5cdd8 !important;
        border-radius: 10px !important;
        transition: all 0.15s !important;
    }
    [data-testid="stMain"] .stButton > button:hover {
        background: #1a2d40 !important;
        border-color: #00d4aa !important;
        color: #00d4aa !important;
    }
    [data-testid="stMain"] .stButton > button[kind="primary"] {
        background: #9b2335 !important;
        border-color: #c53030 !important;
        color: #fff !important;
    }

    /* ── Inputs dark ── */
    input, textarea, [data-baseweb="input"] {
        background: #0d1420 !important;
        color: #e2e8f0 !important;
        border-color: #1e2d3d !important;
    }
    [data-testid="stNumberInput"] > div > div > input {
        background: #0d1420 !important;
        color: #e2e8f0 !important;
    }
    /* ── Expander dark ── */
    [data-testid="stExpander"] {
        background: #0d1420 !important;
        border: 1px solid #1e2d3d !important;
        border-radius: 10px !important;
    }
    /* ── Caption / small text ── */
    .stMarkdown p { color: #c5cdd8; }
    caption, [data-testid="stCaptionContainer"] { color: #6b7c93 !important; }
    hr { border-color: #1a2535 !important; }

    @media (max-width: 768px) {
        .pillar-score { font-size: 1.2rem; }
    }
</style>
""", unsafe_allow_html=True)

# ─── Singletons (created once per server session) ────────────────────────────
@st.cache_resource
def get_store():
    return MetricsStore()

@st.cache_resource
def get_cache():
    return CacheManager(ttl_seconds=5)

@st.cache_resource
def get_saver():
    from system_monitor import get_full_snapshot
    from security_checks import check_firewall_status, check_apparmor_status
    from health_score import calculate_health_score

    store = get_store()

    def snapshot_fn():
        return get_full_snapshot()

    def health_fn(snap):
        sec = {
            "firewall": check_firewall_status(),
            "apparmor": check_apparmor_status(),
            "updates": {"count": 0},
            "suspicious_crons": [],
            "failed_ssh": {"count": 0}
        }
        return calculate_health_score(snap, sec)["score"]

    saver = BackgroundSaver(store, snapshot_fn, health_fn, interval=30)
    saver.start()
    return saver

# Start background saving immediately
_saver = get_saver()
store  = get_store()
cache  = get_cache()

# ─── Navigation sections ─────────────────────────────────────────────────────
SECTIONS = {
    "Dashboard":   ("📊", "Live System Monitoring"),
    "Network":     ("🌐", "Network & Packets"),
    "Actions":     ("⚡", "Smart Actions"),
    "AI Analysis": ("🤖", "AI Analysis"),
    "Security":    ("🔐", "Security Audits"),
    "History":     ("📈", "History & Trends"),
    "AI Chat":     ("💬", "AI Chat"),
}

# ─── Session State ────────────────────────────────────────────────────────────
for key in ["chat_history", "action_log", "ai_analysis", "security_data",
            "confirm_action", "selected_proc", "show_proc_detail"]:
    if key not in st.session_state:
        st.session_state[key] = [] if key in ["chat_history", "action_log"] else None
if "active_section" not in st.session_state:
    st.session_state.active_section = "Dashboard"

# ─── Helpers ─────────────────────────────────────────────────────────────────
def risk_color(pct):
    if pct >= 90: return "#e53e3e"
    if pct >= 70: return "#ed8936"
    return "#48bb78"

def risk_icon(pct):
    if pct >= 90: return "🔴"
    if pct >= 70: return "🟡"
    return "🟢"

def log_action(msg, success=True):
    icon = "✅" if success else "❌"
    st.session_state.action_log.insert(0, f"{icon} {msg}")
    st.session_state.action_log = st.session_state.action_log[:20]

def build_ai_url(service, system_summary):
    encoded = urllib.parse.quote(system_summary)
    urls = {
        "ChatGPT": f"https://chatgpt.com/?q={encoded}",
        "Claude":  f"https://claude.ai/new?q={encoded}",
        "Gemini":  f"https://gemini.google.com/app?q={encoded}",
    }
    return urls.get(service, "#")

# ─── Gauge helper ────────────────────────────────────────────────────────────
def render_gauge(label: str, value: float, subtitle: str = "",
                  reverse: bool = False) -> str:
    """
    SVG circular progress gauge.
    reverse=False (default): high value = bad  → CPU, RAM, Disk, Swap usage
    reverse=True:            high value = good → health pillars, scores
    """
    try:
        v = float(value)
    except Exception:
        v = 0.0
    v = max(0.0, min(100.0, v))
    r       = 36
    circ    = 2 * 3.14159265 * r
    filled  = circ * v / 100
    empty   = circ - filled

    if reverse:
        color = ("#e53e3e" if v < 40 else
                 "#ed8936" if v < 70 else
                 "#00d4aa")
    else:
        color = ("#e53e3e" if v >= 90 else
                 "#ed8936" if v >= 70 else
                 "#00d4aa")

    return f"""
    <div class="gauge-card">
      <svg width="100" height="100" viewBox="0 0 90 90">
        <circle cx="45" cy="45" r="{r}" fill="none"
                stroke="#1a2535" stroke-width="9"/>
        <circle cx="45" cy="45" r="{r}" fill="none"
                stroke="{color}" stroke-width="9"
                stroke-dasharray="{filled:.1f} {empty:.1f}"
                stroke-linecap="round"
                transform="rotate(-90 45 45)"/>
        <text x="45" y="42" text-anchor="middle"
              fill="{color}" font-size="14" font-weight="bold"
              font-family="system-ui,sans-serif">{v:.0f}%</text>
        <text x="45" y="56" text-anchor="middle"
              fill="#4a5568" font-size="8"
              font-family="system-ui,sans-serif">{subtitle}</text>
      </svg>
      <div style="color:#e2e8f0;font-size:0.72rem;font-weight:700;
                  text-transform:uppercase;letter-spacing:0.8px;
                  margin-top:2px;">{label}</div>
    </div>"""


# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    # ── Branding ──────────────────────────────────────────────────────────
    st.markdown("""
    <div style="padding:1.5rem 1.2rem 1rem;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:0.25rem;">
        <div style="font-size:1.7rem;">🛡️</div>
        <div>
          <span style="color:#fff;font-size:1.3rem;font-weight:800;">SysGuard </span>
          <span style="color:#00d4aa;font-size:1.3rem;font-weight:800;">AI</span>
        </div>
      </div>
      <div style="color:#6b7c93;font-size:0.72rem;">
          Ubuntu System Intelligence Dashboard</div>
      <div style="color:#00d4aa;font-size:0.75rem;font-weight:600;
                  letter-spacing:0.5px;margin-top:2px;margin-bottom:1.4rem;">
          Monitor &nbsp;•&nbsp; Optimize &nbsp;•&nbsp; Secure</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Navigation buttons ─────────────────────────────────────────────────
    active_now = st.session_state.active_section
    with st.container():
        st.markdown('<div style="padding:0 0.7rem;">', unsafe_allow_html=True)
        for section, (icon, label) in SECTIONS.items():
            is_active = (active_now == section)
            if st.button(f"{icon}  {label}", key=f"nav_{section}",
                         use_container_width=True,
                         type="primary" if is_active else "secondary"):
                st.session_state.active_section = section
                st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    # Scroll to top whenever any nav action happens
    st.components.v1.html("""
    <script>
        (function() {
            var main = window.parent.document.querySelector('[data-testid="stMain"]');
            if (main) main.scrollTo({top: 0, behavior: 'instant'});
        })();
    </script>
    """, height=0)

    # ── Tagline footer ─────────────────────────────────────────────────────
    st.markdown("""
    <div style="padding:1rem 1.2rem;">
      <div style="background:#0d1420;border:1px solid #1a2535;border-radius:12px;
                  padding:0.75rem 1rem;display:flex;align-items:center;gap:10px;">
        <div style="font-size:1.1rem;">🔒</div>
        <div>
          <div style="color:#e2e8f0;font-size:0.72rem;font-weight:700;">
              Secure. Optimized. Intelligent.</div>
          <div style="color:#6b7c93;font-size:0.66rem;">
              Your Ubuntu. Protected by
              <span style="color:#00d4aa;">AI.</span></div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

# ─── Main content — driven by sidebar navigation ─────────────────────────────
active = st.session_state.active_section

# Page title bar
icon, label = SECTIONS.get(active, ("📊", active))
st.markdown(f"""
<div style="display:flex;align-items:center;gap:10px;
            padding:0.6rem 0;margin-bottom:0.5rem;
            border-bottom:1px solid #1a2535;">
    <span style="font-size:1.3rem;">{icon}</span>
    <span style="color:#e2e8f0;font-size:1.1rem;font-weight:700;">{label}</span>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if active == "Dashboard":
    col_hdr, col_auto = st.columns([4, 1])
    with col_hdr:
        st.markdown('<div class="section-header">LIVE SYSTEM METRICS</div>',
                    unsafe_allow_html=True)
    with col_auto:
        auto_refresh = st.toggle("Auto-refresh", value=False)

    # Collect data
    cpu = get_cpu_info()
    ram = get_ram_info()
    disk = get_disk_info()
    net = get_network_info()
    procs = get_top_processes()
    sys_info = get_system_info()

    quick_security = {
        "firewall": check_firewall_status(),
        "apparmor": check_apparmor_status(),
        "updates": {"count": 0, "risk": "low"},
        "suspicious_crons": [],
        "world_writable": [],
        "failed_ssh": {"count": 0}
    }
    snapshot = {"cpu": cpu, "ram": ram, "disk": disk,
                "network": net, "processes": procs, "system": sys_info}
    health = calculate_health_score(snapshot, quick_security)

    # ── Health Score + Circular Gauges ───────────────────────────────────
    root_disk = next((d for d in disk if d.get("mountpoint") == "/"),
                     disk[0] if disk else {})

    col_score, col_cpu, col_ram, col_disk, col_swap = st.columns([1.4, 1, 1, 1, 1])

    with col_score:
        stars_filled = "★" * health["stars"] + "☆" * (5 - health["stars"])
        st.markdown(f"""
        <div style="text-align:center;background:#0d1420;border-radius:14px;
                    padding:1.3rem 0.8rem;border:1px solid #1a2535;height:100%;">
            <div style="color:#6b7c93;font-size:0.65rem;letter-spacing:1.5px;
                        text-transform:uppercase;margin-bottom:0.3rem;">Health Score</div>
            <div style="color:{health['color']};font-size:3.2rem;
                        font-weight:800;line-height:1.0;">{health['score']}</div>
            <div style="color:#f6ad55;font-size:1.1rem;
                        margin:4px 0 2px;">{stars_filled}</div>
            <div style="color:{health['color']};font-size:0.78rem;
                        font-weight:600;">{health['status']}</div>
        </div>
        """, unsafe_allow_html=True)

    with col_cpu:
        st.markdown(render_gauge("CPU", cpu['percent']), unsafe_allow_html=True)

    with col_ram:
        st.markdown(
            render_gauge("RAM", ram['percent'],
                         subtitle=f"{ram['used_gb']}G/{ram['total_gb']}G"),
            unsafe_allow_html=True)

    with col_disk:
        st.markdown(
            render_gauge("Disk", root_disk.get('percent', 0),
                         subtitle=f"{root_disk.get('used_gb', 0)}GB used"),
            unsafe_allow_html=True)

    with col_swap:
        st.markdown(render_gauge("Swap", ram['swap_percent']),
                    unsafe_allow_html=True)

    st.markdown("---")

    # ── Four Pillar Gauges ────────────────────────────────────────────────
    st.markdown('<div class="section-header">HEALTH BREAKDOWN</div>',
                unsafe_allow_html=True)
    pillars = health["pillars"]
    p_cols = st.columns(4)
    for i, (key, p) in enumerate(pillars.items()):
        pct = int((p["score"] / p["max"]) * 100)
        with p_cols[i]:
            st.markdown(
                render_gauge(p["label"], pct,
                             subtitle=f"{p['score']}/{p['max']}",
                             reverse=True),
                unsafe_allow_html=True)

    if health.get("deductions"):
        with st.expander("📋 Score breakdown — why points were lost"):
            for d in health["deductions"]:
                st.markdown(f"- {d}")

    st.markdown("---")

    # ── System Info + Security ────────────────────────────────────────────
    col_sys, col_sec = st.columns(2)
    with col_sys:
        st.markdown('<div class="section-header">SYSTEM INFO</div>',
                    unsafe_allow_html=True)
        st.markdown(f"""
        <div class="info-card">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem 1rem;">
            <div><span style="color:#6b7c93;font-size:0.7rem;">HOST</span><br>
              <span style="color:#e2e8f0;font-size:0.82rem;font-family:monospace;">
              {sys_info['hostname']}</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">OS</span><br>
              <span style="color:#e2e8f0;font-size:0.82rem;font-family:monospace;">
              {sys_info['os']}</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">UPTIME</span><br>
              <span style="color:#00d4aa;font-size:0.82rem;font-family:monospace;">
              {sys_info['uptime']}</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">ARCH</span><br>
              <span style="color:#e2e8f0;font-size:0.82rem;font-family:monospace;">
              {sys_info['architecture']}</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">BOOT</span><br>
              <span style="color:#e2e8f0;font-size:0.82rem;font-family:monospace;">
              {sys_info['boot_time']}</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">PYTHON</span><br>
              <span style="color:#e2e8f0;font-size:0.82rem;font-family:monospace;">
              {sys_info['python_version']}</span></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with col_sec:
        st.markdown('<div class="section-header">SECURITY SNAPSHOT</div>',
                    unsafe_allow_html=True)
        fw = quick_security["firewall"]
        aa = quick_security["apparmor"]
        fw_dot = ("#48bb78" if fw["status"] == "active" else
                  "#e53e3e" if fw["status"] == "inactive" else "#ed8936")
        aa_dot = "#48bb78" if aa["enabled"] else "#ed8936"
        zb_dot = "#e53e3e" if procs['total_zombie'] > 0 else "#48bb78"
        st.markdown(f"""
        <div class="info-card">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem 1rem;">
            <div><span style="color:#6b7c93;font-size:0.7rem;">FIREWALL</span><br>
              <span style="color:{fw_dot};font-size:0.82rem;font-weight:700;">
              ● {fw['label']}</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">APPARMOR</span><br>
              <span style="color:{aa_dot};font-size:0.82rem;font-weight:700;">
              ● {aa['label']}</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">PROCESSES</span><br>
              <span style="color:#e2e8f0;font-size:0.82rem;">
              {procs['total_count']} running</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">ZOMBIES</span><br>
              <span style="color:{zb_dot};font-size:0.82rem;font-weight:700;">
              ● {procs['total_zombie']}</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">CONNECTIONS</span><br>
              <span style="color:#e2e8f0;font-size:0.82rem;">
              {net['total_connections']}</span></div>
            <div><span style="color:#6b7c93;font-size:0.7rem;">OPEN PORTS</span><br>
              <span style="color:#e2e8f0;font-size:0.82rem;">
              {len(net['listening_ports'])}</span></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")

    # ── Processes (user processes only, clickable) ────────────────────────
    col_p1, col_p2 = st.columns(2)

    with col_p1:
        st.markdown('<div class="section-header">TOP CPU — USER PROCESSES</div>',
                    unsafe_allow_html=True)
        cpu_procs = [p for p in procs["by_cpu"] if (p.get("cpu_percent") or 0) >= 0][:6]
        if cpu_procs:
            for p in cpu_procs:
                pct = p.get("cpu_percent") or 0
                name = p.get("name", "?")
                pid = p.get("pid", "?")
                uptime = p.get("uptime_hours", 0)
                col_a, col_b = st.columns([3, 1])
                with col_a:
                    st.markdown(f"{risk_icon(pct)} `{name}` (PID {pid})")
                    st.caption(f"CPU: {pct:.1f}% | Running: {uptime}h")
                with col_b:
                    if st.button("⚙️", key=f"proc_cpu_{pid}",
                                 help=f"Details for {name}"):
                        st.session_state.selected_proc = p
        else:
            st.info("No user processes with significant CPU usage.")

    with col_p2:
        st.markdown('<div class="section-header">TOP MEMORY — USER PROCESSES</div>',
                    unsafe_allow_html=True)
        mem_procs = [p for p in procs["by_mem"] if (p.get("memory_percent") or 0) > 0][:6]
        if mem_procs:
            for p in mem_procs:
                pct = p.get("memory_percent") or 0
                name = p.get("name", "?")
                pid = p.get("pid", "?")
                uptime = p.get("uptime_hours", 0)
                col_a, col_b = st.columns([3, 1])
                with col_a:
                    st.markdown(f"{risk_icon(pct * 1.2)} `{name}` (PID {pid})")
                    st.caption(f"RAM: {pct:.1f}% | Running: {uptime}h")
                with col_b:
                    if st.button("⚙️", key=f"proc_mem_{pid}",
                                 help=f"Details for {name}"):
                        st.session_state.selected_proc = p
        else:
            st.info("No significant memory usage by user processes.")

    # Process detail panel
    if st.session_state.selected_proc:
        p = st.session_state.selected_proc
        name = p.get("name", "?")
        pid = p.get("pid", "?")
        with st.expander(f"📋 Process Detail — {name} (PID {pid})", expanded=True):
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("CPU", f"{p.get('cpu_percent', 0):.1f}%")
            c2.metric("RAM", f"{p.get('memory_percent', 0):.1f}%")
            c3.metric("Status", p.get("status", "?"))
            c4.metric("Running", f"{p.get('uptime_hours', 0)}h")
            st.caption(f"User: {p.get('username', '?')} | PID: {pid}")

            col_kill, col_close = st.columns([1, 4])
            with col_kill:
                if st.button(f"⚠️ Kill PID {pid}", key=f"kill_from_dash_{pid}",
                             type="primary"):
                    ok, msg = kill_process(int(pid))
                    log_action(f"Kill {name} PID {pid}: {msg}", ok)
                    st.session_state.selected_proc = None
                    st.rerun()
            with col_close:
                if st.button("✖ Close", key=f"close_proc_{pid}"):
                    st.session_state.selected_proc = None
                    st.rerun()

    # ── Boot Analysis ─────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown('<div class="section-header">BOOT ANALYSIS</div>',
                unsafe_allow_html=True)

    if st.button("🔍 Analyze Boot Time", key="btn_boot"):
        with st.spinner("Analyzing boot sequence..."):
            boot = get_boot_analysis()
        if boot["available"]:
            st.success(f"📋 {boot['summary']}")
            if boot["slow_units"]:
                st.markdown("**Slowest startup units:**")
                for unit in boot["slow_units"][:8]:
                    st.markdown(f"⏱️ `{unit['time']}` — `{unit['unit']}`")
        else:
            st.info(f"Boot analysis: {boot['summary']}")

    if auto_refresh:
        time.sleep(5)
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK
# ══════════════════════════════════════════════════════════════════════════════
elif active == "Network":
    st.markdown('<div class="section-header">NETWORK OVERVIEW</div>',
                unsafe_allow_html=True)

    net = get_network_info()

    # ── Traffic Metrics ───────────────────────────────────────────────────
    nc1, nc2, nc3, nc4 = st.columns(4)
    nc1.metric("📤 Sent", f"{net['bytes_sent_mb']} MB")
    nc2.metric("📥 Received", f"{net['bytes_recv_mb']} MB")
    nc3.metric("🔗 Connections", net['total_connections'])
    nc4.metric("🚪 Listening Ports", len(net['listening_ports']))

    st.markdown("---")

    # ── Listening Ports (clickable, with risk) ────────────────────────────
    risky_ports = {
        21: ("FTP", "high", "FTP sends data unencrypted. Use SFTP instead."),
        23: ("Telnet", "high", "Telnet is unencrypted. Use SSH instead."),
        25: ("SMTP", "medium", "Email server — ensure it is not an open relay."),
        53: ("DNS", "low", "DNS resolver — normal if running local DNS."),
        80: ("HTTP", "medium", "Unencrypted web server. Consider HTTPS."),
        110: ("POP3", "medium", "Email retrieval — ensure TLS is enabled."),
        139: ("NetBIOS", "high", "Windows file sharing — risky on Linux."),
        445: ("SMB", "high", "Samba — risky if exposed to internet."),
        3306: ("MySQL", "medium", "Database — should not be internet-facing."),
        3389: ("RDP", "high", "Remote desktop — common attack target."),
        5900: ("VNC", "high", "Screen sharing — often unencrypted."),
        8501: ("Streamlit", "low", "SysGuard AI itself — expected."),
        11434: ("Ollama", "low", "Ollama AI server — expected if running."),
    }

    st.markdown('<div class="section-header">LISTENING PORTS</div>',
                unsafe_allow_html=True)

    if net['listening_ports']:
        for port_info in net['listening_ports']:
            port = port_info["port"]
            proc = port_info["process"]
            pid = port_info["pid"]
            known = risky_ports.get(port)

            if known:
                label, risk, explanation = known
                css_class = f"risk-{risk}"
                risk_badge = {"high": "🔴 HIGH", "medium": "🟡 MEDIUM", "low": "🟢 LOW"}[risk]
            else:
                label, risk, explanation = "Unknown", "medium", "Unrecognized port — investigate."
                css_class = "risk-medium"
                risk_badge = "🟡 REVIEW"

            with st.expander(f"Port `{port}` — `{proc}` — {risk_badge}"):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Process:** `{proc}` (PID {pid})")
                    st.markdown(f"**Service:** {label}")
                with c2:
                    st.markdown(f"**Risk:** {risk_badge}")
                    st.markdown(f"**Note:** {explanation}")
    else:
        st.success("No listening ports detected.")

    st.markdown("---")

    # ── Active Connections ────────────────────────────────────────────────
    st.markdown('<div class="section-header">ACTIVE CONNECTIONS</div>',
                unsafe_allow_html=True)

    active = net.get("active_connections", [])
    if active:
        for conn in active[:10]:
            st.markdown(
                f"🔗 `{conn['process']}` → `{conn['remote_ip']}:{conn['remote_port']}` "
                f"(local :{conn['local_port']})"
            )
    else:
        st.info("No established connections at the moment.")

    st.markdown("---")

    # ── Packet Analysis (tshark) ────────────────────────────────────────────
    st.markdown('<div class="section-header">🔬 PACKET ANALYSIS</div>',
                unsafe_allow_html=True)
    st.caption("Captures live traffic and checks for port scans, ARP spoofing, "
               "DNS tunneling, and cleartext credentials. Requires tshark + "
               "capture permissions — see setup notes below.")

    interfaces, net_diag = list_interfaces_with_diagnostics()
    if not interfaces:
        st.warning("No usable network interfaces found.")

        with st.expander("🔍 Why — actual diagnostic output", expanded=True):
            st.markdown(f"**Command run:** `{net_diag['command']}`")
            st.markdown(f"**tshark found on system:** "
                       f"{'✅ Yes' if net_diag['tshark_found'] else '❌ No'}")
            st.markdown(f"**Command succeeded:** "
                       f"{'✅ Yes' if net_diag['returncode_ok'] else '❌ No'}")
            if net_diag.get("stderr"):
                st.markdown("**tshark said (stderr):**")
                st.code(net_diag["stderr"], language=None)
            if net_diag.get("stdout"):
                st.markdown("**Raw stdout:**")
                st.code(net_diag["stdout"], language=None)
            if net_diag.get("note"):
                st.caption(net_diag["note"])

        with st.expander("⚙️ Setup needed"):
            st.markdown("""
            ```bash
            sudo apt install tshark
            sudo usermod -aG wireshark $USER
            sudo dpkg-reconfigure wireshark-common
            ```
            Answer **Yes** when asked about non-superuser capture, then **log out and back in
            completely** (close the terminal/session entirely — group membership only applies
            to brand-new sessions, restarting Streamlit in the same terminal is not enough).

            Verify it actually took effect before retrying:
            ```bash
            groups          # should list 'wireshark'
            tshark -D       # should list real interfaces, no permission errors
            ```
            """)
    else:
        col_iface, col_dur = st.columns(2)
        with col_iface:
            selected_iface = st.selectbox("Interface", interfaces, key="net_iface")
        with col_dur:
            capture_duration = st.selectbox("Capture duration",
                                            [15, 30, 60, 120],
                                            format_func=lambda s: f"{s} seconds",
                                            index=1, key="net_duration")

        if st.button("📡 Capture & Analyze Traffic", key="btn_capture",
                     use_container_width=True, type="primary"):
            with st.spinner(f"Capturing on {selected_iface} for {capture_duration}s..."):
                net_report = analyze_network(selected_iface, capture_duration)
            st.session_state["network_analysis_result"] = net_report

        nr = st.session_state.get("network_analysis_result")
        if nr:
            if nr.get("error"):
                st.error(nr["error"])
            else:
                st.markdown(f"**{nr['verdict']}**")
                st.caption(f"Captured {nr.get('pcap_size_bytes', 0):,} bytes over "
                          f"{nr['duration_seconds']}s on `{nr['interface']}`")

                # Port scans
                scans = nr["port_scans"].get("scans_detected", [])
                if scans:
                    for s in scans:
                        st.markdown(f"""
                        <div class="risk-card risk-{s['severity']}">
                            🔴 <strong>Possible port scan</strong><br>
                            Source: <code>{s['source_ip']}</code> hit
                            {s['distinct_ports_hit']} distinct ports<br>
                            <span style="color:#a0aec0;font-size:0.85rem;">
                            Sample ports: {', '.join(s['sample_ports'])}</span>
                        </div>
                        """, unsafe_allow_html=True)

                # ARP spoofing
                conflicts = nr["arp_spoofing"].get("conflicts", [])
                if conflicts:
                    for c in conflicts:
                        st.markdown(f"""
                        <div class="risk-card risk-high">
                            🔴 <strong>ARP spoofing suspected</strong><br>
                            {c['note']}<br>
                            <span style="color:#a0aec0;font-size:0.85rem;">
                            MACs seen: {', '.join(c['macs_seen'])}</span>
                        </div>
                        """, unsafe_allow_html=True)

                # DNS anomalies
                long_queries = nr["dns_anomalies"].get("long_queries", [])
                if long_queries:
                    for q in long_queries[:5]:
                        st.markdown(f"""
                        <div class="risk-card risk-{q['severity']}">
                            🟡 <strong>Unusually long DNS query</strong>
                            ({q['length']} chars)<br>
                            <code>{q['query'][:80]}</code><br>
                            <span style="color:#a0aec0;font-size:0.85rem;">
                            Possible DNS tunneling/exfiltration pattern.</span>
                        </div>
                        """, unsafe_allow_html=True)

                # Credentials
                creds = nr["credentials"]
                all_creds = creds.get("http_basic_auth", []) + creds.get("ftp_credentials", [])
                if all_creds:
                    for c in all_creds:
                        st.markdown(f"""
                        <div class="risk-card risk-high">
                            🔴 <strong>Cleartext credentials observed</strong><br>
                            <code>{c['src']}</code> → <code>{c['dst']}</code><br>
                            <span style="color:#a0aec0;font-size:0.85rem;">
                            Credentials crossed the wire unencrypted.</span>
                        </div>
                        """, unsafe_allow_html=True)

                if nr["findings_count"] == 0:
                    st.success("No port scans, ARP conflicts, DNS anomalies, "
                              "or cleartext credentials detected in this window.")

                # Conversations
                with st.expander("📊 Top conversations in this capture"):
                    convs = nr.get("top_conversations", [])
                    if convs:
                        for c in convs:
                            st.markdown(f"`{c['ip_a']}` ↔ `{c['ip_b']}` — "
                                       f"{c['frames_total']} frames, {c['bytes_total']}")
                    else:
                        st.caption("No conversation data captured.")

    st.caption("⚖️ Only capture traffic on networks you own or are explicitly "
              "authorized to monitor.")


# ══════════════════════════════════════════════════════════════════════════════
# ACTIONS
# ══════════════════════════════════════════════════════════════════════════════
elif active == "Actions":
    st.markdown('<div class="section-header">ACTION CENTER</div>',
                unsafe_allow_html=True)
    st.caption("All destructive actions require confirmation before running.")

    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("**🧹 Memory & Cache**")

        if st.button("🧠 Clear RAM Cache", key="btn_ram",
                     use_container_width=True,
                     help="Drops page cache. Requires sudo."):
            if st.session_state.confirm_action == "ram":
                ok, msg = clear_ram_cache()
                log_action(f"Clear RAM cache: {msg}", ok)
                st.session_state.confirm_action = None
                st.rerun()
            else:
                st.session_state.confirm_action = "ram"
                st.rerun()

        if st.session_state.confirm_action == "ram":
            st.warning("⚠️ This will drop page cache. Confirm?")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("✅ Confirm", key="confirm_ram"):
                    ok, msg = clear_ram_cache()
                    log_action(f"Clear RAM: {msg}", ok)
                    st.session_state.confirm_action = None
                    st.rerun()
            with c2:
                if st.button("❌ Cancel", key="cancel_ram"):
                    st.session_state.confirm_action = None
                    st.rerun()

        if st.button("🗑️ Clean /tmp", key="btn_tmp",
                     use_container_width=True):
            ok, msg = clean_temp_files()
            log_action(f"Clean /tmp: {msg}", ok)
            st.rerun()

        if st.button("📦 Clean APT Cache", key="btn_apt",
                     use_container_width=True):
            ok, msg = clean_apt_cache()
            log_action(f"APT clean: {msg}", ok)
            st.rerun()

        if st.button("📋 Clean Journal Logs (>3 days)", key="btn_journal",
                     use_container_width=True):
            ok, msg = clean_journal_logs()
            log_action(f"Journal: {msg}", ok)
            st.rerun()

        st.markdown("---")
        st.markdown("**🔍 Diagnostics**")
        if st.button("🧟 Check Zombie Processes", key="btn_zombie",
                     use_container_width=True):
            ok, msg = check_zombie_processes()
            log_action(f"Zombies: {msg}", ok)
            st.rerun()

        if st.button("⚙️ Check Failed Services", key="btn_svc",
                     use_container_width=True):
            ok, msg = get_failed_services()
            log_action(f"Services: {msg}", ok)
            st.rerun()

    with col_b:
        st.markdown("**💀 Kill Process by PID**")
        pid_input = st.number_input("PID", min_value=1, step=1, key="pid_input")
        if st.button("⚠️ Kill Process", key="btn_kill",
                     use_container_width=True, type="primary"):
            if st.session_state.confirm_action == f"kill_{pid_input}":
                ok, msg = kill_process(int(pid_input))
                log_action(f"Kill PID {pid_input}: {msg}", ok)
                st.session_state.confirm_action = None
                st.rerun()
            else:
                st.session_state.confirm_action = f"kill_{pid_input}"
                st.rerun()

        if st.session_state.confirm_action == f"kill_{pid_input}":
            st.warning(f"Kill PID {pid_input}? Cannot be undone.")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("✅ Confirm Kill", key="confirm_kill"):
                    ok, msg = kill_process(int(pid_input))
                    log_action(f"Kill {pid_input}: {msg}", ok)
                    st.session_state.confirm_action = None
                    st.rerun()
            with c2:
                if st.button("❌ Cancel", key="cancel_kill"):
                    st.session_state.confirm_action = None
                    st.rerun()

        st.markdown("---")
        st.markdown("**📜 Action Log**")
        if st.session_state.action_log:
            for entry in st.session_state.action_log[:10]:
                st.markdown(f"`{entry}`")
        else:
            st.caption("No actions yet.")

        if st.button("🗑️ Clear Log", key="btn_clear_log"):
            st.session_state.action_log = []
            st.rerun()

    # ── Generate Report ────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown('<div class="section-header">📄 GENERATE SYSTEM REPORT</div>',
                unsafe_allow_html=True)
    st.caption("Compiles current health, security findings, and history into "
               "a Markdown report. Saved on this machine and downloadable from your browser.")

    if st.button("📋 Generate Report Now", key="btn_gen_report",
                 use_container_width=True, type="primary"):
        with st.spinner("Compiling report..."):
            snap = get_full_snapshot()
            sec_for_report = st.session_state.security_data or run_security_audit()
            health_for_report = calculate_health_score(snap, sec_for_report)
            hist_stats = store.get_stats(hours=24)

            report_text = generate_report(snap, sec_for_report,
                                          health_for_report, hist_stats)
            saved_path = save_report(report_text)

        st.success(f"✅ Report saved to: `{saved_path}`")

        st.download_button(
            label="⬇️ Download Report (.md)",
            data=report_text,
            file_name=saved_path.split("/")[-1],
            mime="text/markdown",
            use_container_width=True
        )

        with st.expander("📖 Preview report"):
            st.markdown(report_text)


# ══════════════════════════════════════════════════════════════════════════════
# AI ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
elif active == "AI Analysis":
    st.markdown('<div class="section-header">AI SYSTEM ANALYSIS</div>',
                unsafe_allow_html=True)

    ollama_ok = is_ollama_running()
    available_models = get_available_models() if ollama_ok else []

    col_status, col_model = st.columns([1, 2])
    with col_status:
        if ollama_ok:
            st.success("🟢 Ollama running")
        else:
            st.error("🔴 Ollama offline")
            st.caption("Start: `ollama serve`")
    with col_model:
        if available_models:
            selected_model = st.selectbox("Model", available_models,
                                          key="analysis_model")
        else:
            selected_model = st.text_input("Model name", value="llama3.2:3b")

    # ── Consult External AI ───────────────────────────────────────────────
    st.markdown("---")
    st.markdown('<div class="section-header">CONSULT EXTERNAL AI</div>',
                unsafe_allow_html=True)
    st.caption("Opens your browser with your system summary pre-filled.")

    snap_quick = get_full_snapshot()
    cpu_q = snap_quick["cpu"]["percent"]
    ram_q = snap_quick["ram"]["percent"]
    disk_q = snap_quick.get("disk", [{}])
    disk_pct_q = disk_q[0].get("percent", 0) if disk_q else 0
    fw_q = check_firewall_status()
    z_q = snap_quick["processes"]["total_zombie"]
    h_q = calculate_health_score(snap_quick, {"firewall": fw_q,
          "apparmor": {"enabled": True}, "updates": {"count": 0},
          "suspicious_crons": [], "failed_ssh": {"count": 0}})

    system_summary = (
        f"My Ubuntu system (hostname: {snap_quick['system']['hostname']}, "
        f"uptime: {snap_quick['system']['uptime']}) has these stats: "
        f"CPU {cpu_q}%, RAM {ram_q}% ({snap_quick['ram']['used_gb']}GB / "
        f"{snap_quick['ram']['total_gb']}GB), Disk {disk_pct_q}%, "
        f"Firewall {'ON' if fw_q['status'] == 'active' else 'OFF'}, "
        f"{z_q} zombie processes, Health Score {h_q['score']}/100. "
        f"What should I do to improve my system?"
    )

    ai_cols = st.columns(3)
    ai_services = [
        ("Claude", "🟠"),
        ("ChatGPT", "🟢"),
        ("Gemini", "🔵"),
    ]
    for i, (service, icon) in enumerate(ai_services):
        with ai_cols[i]:
            url = build_ai_url(service, system_summary)
            st.markdown(
                f'<a href="{url}" target="_blank">'
                f'<button style="width:100%;padding:0.5rem;background:#1a1a2e;'
                f'color:#00d4aa;border:1px solid #00d4aa;border-radius:8px;'
                f'cursor:pointer;font-size:0.9rem;">'
                f'{icon} Ask {service}</button></a>',
                unsafe_allow_html=True
            )

    with st.expander("📋 View system summary being sent"):
        st.markdown(f"`{system_summary}`")

    # ── Local Ollama Analysis ─────────────────────────────────────────────
    st.markdown("---")
    st.markdown('<div class="section-header">LOCAL AI ANALYSIS (OLLAMA)</div>',
                unsafe_allow_html=True)

    if st.button("🔍 Analyze My System Now", key="btn_analyze",
                 disabled=not ollama_ok,
                 use_container_width=True, type="primary"):
        with st.spinner("Analyzing... (30-60s depending on model)"):
            snap = get_full_snapshot()
            st.session_state.ai_analysis = analyze_system(snap, selected_model)

    if st.session_state.ai_analysis:
        st.markdown("### 🤖 AI Assessment")
        st.markdown(st.session_state.ai_analysis)
    else:
        st.info("Click **Analyze My System Now** for an AI-powered health assessment.")
        st.caption("The AI will explain what your numbers mean and what to do — in plain English.")


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY
# ══════════════════════════════════════════════════════════════════════════════
elif active == "Security":
    st.markdown('<div class="section-header">SECURITY AUDIT</div>',
                unsafe_allow_html=True)

    if st.button("🔍 Run Full Security Audit", key="btn_sec_audit",
                 use_container_width=True, type="primary"):
        with st.spinner("Running security checks..."):
            st.session_state.security_data = run_security_audit()

    sec = st.session_state.security_data

    if sec:
        # ── Firewall (with risk + fix) ────────────────────────────────────
        fw = sec.get("firewall", {})
        fw_status = fw.get("status", "unknown")
        if fw_status == "inactive":
            st.markdown("""
            <div class="risk-card risk-high">
                <strong>🔴 Firewall — DISABLED</strong><br>
                <span style="color:#a0aec0;font-size:0.85rem;">
                Risk: HIGH — System is exposed to network attacks if any services are running.</span><br>
                Fix: <span class="fix-cmd">sudo ufw enable</span>
            </div>
            """, unsafe_allow_html=True)
            col_fw_btn, _ = st.columns([1, 3])
            with col_fw_btn:
                if st.button("🔧 Enable Firewall Now", key="btn_enable_fw"):
                    ok, msg = enable_firewall()
                    log_action(f"Enable firewall: {msg}", ok)
                    if ok:
                        st.session_state.security_data = None
                    st.rerun()
            st.caption("Requires NOPASSWD sudoers entry. See setup notes below if this fails.")
        elif fw_status == "active":
            st.markdown("""
            <div class="risk-card risk-low">
                <strong>🟢 Firewall — ACTIVE</strong><br>
                <span style="color:#a0aec0;font-size:0.85rem;">UFW is protecting your system.</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="risk-card risk-medium">
                <strong>🟡 Firewall — STATUS UNKNOWN</strong><br>
                Fix: <span class="fix-cmd">sudo apt install ufw && sudo ufw enable</span>
            </div>
            """, unsafe_allow_html=True)

        # ── AppArmor ──────────────────────────────────────────────────────
        aa = sec.get("apparmor", {})
        if aa.get("enabled"):
            st.markdown("""
            <div class="risk-card risk-low">
                <strong>🟢 AppArmor — ENABLED</strong><br>
                <span style="color:#a0aec0;font-size:0.85rem;">
                Mandatory access control is active.</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="risk-card risk-medium">
                <strong>🟡 AppArmor — DISABLED</strong><br>
                <span style="color:#a0aec0;font-size:0.85rem;">
                Risk: MEDIUM — Applications run without mandatory access controls.</span><br>
                Fix: <span class="fix-cmd">sudo systemctl enable apparmor && sudo systemctl start apparmor</span>
            </div>
            """, unsafe_allow_html=True)

        # ── Pending Updates ───────────────────────────────────────────────
        upd = sec.get("updates", {})
        upd_count = upd.get("count", 0)
        if upd_count > 5:
            st.markdown(f"""
            <div class="risk-card risk-medium">
                <strong>🟡 Updates — {upd_count} PACKAGES PENDING</strong><br>
                <span style="color:#a0aec0;font-size:0.85rem;">
                Risk: MEDIUM — Outdated packages may contain security vulnerabilities.</span><br>
                Fix: <span class="fix-cmd">sudo apt update && sudo apt upgrade -y</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="risk-card risk-low">
                <strong>🟢 Updates — SYSTEM UP TO DATE</strong>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        # ── Open Ports ────────────────────────────────────────────────────
        ports = sec.get("open_ports", [])
        high_risk = [p for p in ports if p.get("risk") == "high"]

        st.markdown(f'<div class="section-header">OPEN PORTS ({len(ports)} found, '
                    f'{len(high_risk)} high risk)</div>', unsafe_allow_html=True)

        for p in ports:
            risk = p.get("risk", "low")
            label = p.get("label", "")
            css = f"risk-{risk}"
            icon = "🔴" if risk == "high" else "🟡" if risk == "medium" else "🟢"
            label_str = f" — **{label}**" if label else ""
            st.markdown(f"""
            <div class="risk-card {css}">
                {icon} Port <strong>{p['port']}</strong>{label_str}
                — Process: <code>{p['process']}</code> (PID {p['pid']})
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        # ── SSH Failed Logins ─────────────────────────────────────────────
        ssh = sec.get("failed_ssh", {})
        ssh_count = ssh.get("count", 0)
        st.markdown(f'<div class="section-header">FAILED SSH LOGINS</div>',
                    unsafe_allow_html=True)
        if ssh_count > 0:
            st.markdown(f"""
            <div class="risk-card risk-{'high' if ssh_count > 100 else 'medium'}">
                <strong>{'🔴' if ssh_count > 100 else '🟡'} {ssh_count} FAILED SSH ATTEMPTS</strong><br>
                <span style="color:#a0aec0;font-size:0.85rem;">
                {"High volume — brute force attack likely." if ssh_count > 100 else "Monitor closely."}</span><br>
                Fix: <span class="fix-cmd">sudo apt install fail2ban</span>
            </div>
            """, unsafe_allow_html=True)
            if ssh.get("top_ips"):
                st.markdown("**Top attacker IPs:**")
                for ip, count in list(ssh["top_ips"].items())[:5]:
                    st.markdown(f"🔴 `{ip}` — {count} attempts | "
                                f"Block: `sudo ufw deny from {ip}`")
        else:
            st.success("🟢 No failed SSH login attempts found.")

        st.markdown("---")

        # ── Suspicious Crons ──────────────────────────────────────────────
        crons = sec.get("suspicious_crons", [])
        st.markdown('<div class="section-header">CRON SECURITY</div>',
                    unsafe_allow_html=True)
        if crons:
            for c in crons:
                risk = c.get("risk", "high")
                css = "risk-high" if risk == "high" else "risk-medium"
                icon = "🔴" if risk == "high" else "🟡"
                desc = c.get("description", "")
                st.markdown(f"""
                <div class="risk-card {css}">
                    {icon} <strong>Suspicious pattern: {c['keyword']}</strong><br>
                    File: <code>{c['file']}</code><br>
                    <span style="color:#a0aec0;font-size:0.85rem;">{desc}</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("🟢 No suspicious cron entries found.")
            st.caption("Checked using contextual pattern matching (YARA) + package "
                       "ownership verification — not naive keyword search, so legitimate "
                       "updaters (rkhunter, Chrome, etc.) won't trigger false alarms.")

        st.markdown("---")

        # ── Static File Analyzer ────────────────────────────────────────────
        st.markdown('<div class="section-header">📁 ANALYZE A SPECIFIC FILE</div>',
                    unsafe_allow_html=True)
        st.caption("Step-by-step static analysis: file type → hash → "
                   "package provenance → entropy → pattern matching. "
                   "Never executes the file.")

        file_path_input = st.text_input(
            "File path", placeholder="/etc/cron.daily/some-script",
            key="file_analyze_input"
        )
        if st.button("🔍 Analyze File", key="btn_analyze_file",
                     disabled=not file_path_input):
            with st.spinner("Running static analysis pipeline..."):
                file_report = analyze_file(file_path_input)
            st.session_state["file_analysis_result"] = file_report

        fr = st.session_state.get("file_analysis_result")
        if fr and fr.get("identity", {}).get("exists"):
            st.markdown(f"**{fr['verdict']}**  (Risk score: {fr['risk_score']}/100)")

            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**True type:** `{fr['identity']['true_type'][:70]}`")
                st.markdown(f"**Size:** {fr['identity']['size_bytes']:,} bytes")
                st.markdown(f"**SHA256:** `{fr['hashes']['sha256'][:32]}...`")
            with c2:
                prov = fr["provenance"]
                if prov.get("verified"):
                    st.markdown(f"**Package:** 🟢 `{prov['owned_by_package']}`")
                else:
                    st.markdown("**Package:** 🟡 Not owned by any installed package")
                st.markdown(f"**Entropy:** {fr['entropy']['entropy']} bits/byte "
                           f"({fr['entropy']['flag']})")

            if fr.get("reasons"):
                st.markdown("**Findings:**")
                for r in fr["reasons"]:
                    st.markdown(f"- {r}")

            with st.expander("📄 Sample strings extracted"):
                for s in fr.get("strings_sample", [])[:15]:
                    st.code(s, language=None)

            st.caption("To check this hash against known-malware databases, search the "
                      "SHA256 above on VirusTotal or MalwareBazaar manually — SysGuard AI "
                      "does not send hashes externally without your explicit action.")
        elif fr:
            st.warning(fr.get("error", "File not found."))

        st.markdown("---")

        # ── rkhunter Full System Scan ───────────────────────────────────────
        st.markdown('<div class="section-header">🛡️ ROOTKIT SCAN (rkhunter)</div>',
                    unsafe_allow_html=True)
        st.caption("Runs rkhunter's full non-interactive system check. "
                   "Requires: `sudo apt install rkhunter` + sudoers entry (see setup notes).")

        if st.button("🔍 Run Full Rootkit Scan", key="btn_rkhunter",
                     use_container_width=True):
            with st.spinner("Running rkhunter — this can take 1-3 minutes..."):
                rk_result = run_rkhunter_check()
            st.session_state["rkhunter_result"] = rk_result

        rk = st.session_state.get("rkhunter_result")
        if rk:
            if not rk["available"]:
                st.error(rk["summary"])
            elif rk["warnings"]:
                st.warning(rk["summary"])
                for w in rk["warnings"][:15]:
                    st.markdown(f"⚠️ `{w}`")
            else:
                st.success(f"🟢 {rk['summary']}")

    else:
        st.info("Click **Run Full Security Audit** to scan your system.")
        st.markdown("""
        **Audit covers:**
        - 🔥 Firewall status with risk level and fix commands
        - 🚪 Open ports with risk classification
        - 🔑 Failed SSH logins with attacker IPs
        - 📅 Suspicious cron jobs (context-aware, not naive keyword match)
        - 📦 Pending security updates
        - 🛡️ AppArmor status
        - 📁 On-demand static file analysis
        - 🛡️ Full rkhunter rootkit scan
        """)


# ══════════════════════════════════════════════════════════════════════════════
# HISTORY
# ══════════════════════════════════════════════════════════════════════════════
elif active == "History":
    st.markdown('<div class="section-header">SYSTEM HISTORY & TRENDS</div>',
                unsafe_allow_html=True)

    record_count = store.get_record_count()
    db_size      = store.get_db_size()

    col_info1, col_info2, col_info3 = st.columns(3)
    col_info1.metric("📦 Records saved", record_count)
    col_info2.metric("💾 Database size", db_size)
    col_info3.metric("🔄 Save interval", "30 seconds")

    if record_count < 5:
        st.info("⏳ Building history... SysGuard AI saves a snapshot every 30 seconds. "
                "Come back after a few minutes to see trends.")
        st.caption(f"Currently {record_count} records. Need at least 5 to show charts.")
    else:
        # ── Time range selector ─────────────────────────────────────────
        hours = st.selectbox("Time range",
                             [1, 3, 6, 12, 24, 48, 168],
                             format_func=lambda h: (
                                 f"Last {h} hour" if h == 1 else
                                 f"Last {h} hours" if h < 24 else
                                 f"Last {h//24} day{'s' if h > 24 else ''}"
                             ),
                             index=2, key="history_hours")

        # ── Stats bar ────────────────────────────────────────────────────
        stats = store.get_stats(hours=hours)
        if stats.get("samples", 0) > 0:
            st.markdown('<div class="section-header">PERIOD STATS</div>',
                        unsafe_allow_html=True)
            sc1, sc2, sc3, sc4 = st.columns(4)
            sc1.metric("CPU avg / peak",
                       f"{stats.get('cpu_avg', 0)}%",
                       delta=f"peak {stats.get('cpu_max', 0)}%")
            sc2.metric("RAM avg / peak",
                       f"{stats.get('ram_avg', 0)}%",
                       delta=f"peak {stats.get('ram_max', 0)}%")
            sc3.metric("Health avg / low",
                       f"{int(stats.get('score_avg', 0))}",
                       delta=f"low {int(stats.get('score_min', 0))}")
            sc4.metric("Zombie events",
                       int(stats.get("zombie_total", 0)))

        st.markdown("---")

        # ── Trend charts with plotly ──────────────────────────────────────
        try:
            import plotly.graph_objects as go
            from plotly.subplots import make_subplots

            cpu_trend  = store.get_trend("cpu_percent",  hours=hours)
            ram_trend  = store.get_trend("ram_percent",  hours=hours)
            disk_trend = store.get_trend("disk_percent", hours=hours)
            score_trend = store.get_trend("health_score", hours=hours)

            if cpu_trend["timestamps"]:
                # CPU + RAM chart
                fig1 = go.Figure()
                fig1.add_trace(go.Scatter(
                    x=cpu_trend["timestamps"], y=cpu_trend["values"],
                    name="CPU %", line=dict(color="#00d4aa", width=2),
                    fill="tozeroy", fillcolor="rgba(0,212,170,0.1)"
                ))
                fig1.add_trace(go.Scatter(
                    x=ram_trend["timestamps"], y=ram_trend["values"],
                    name="RAM %", line=dict(color="#fc8181", width=2),
                    fill="tozeroy", fillcolor="rgba(252,129,129,0.1)"
                ))
                fig1.update_layout(
                    title="CPU & RAM Over Time",
                    paper_bgcolor="#1a1a2e",
                    plot_bgcolor="#0d1117",
                    font=dict(color="#a0aec0"),
                    yaxis=dict(range=[0, 100], gridcolor="#2d3748"),
                    xaxis=dict(gridcolor="#2d3748"),
                    legend=dict(bgcolor="#1a1a2e"),
                    height=300,
                    margin=dict(t=40, b=20, l=20, r=20)
                )
                st.plotly_chart(fig1, use_container_width=True)

                # Health score + Disk
                fig2 = make_subplots(specs=[[{"secondary_y": True}]])
                fig2.add_trace(go.Scatter(
                    x=score_trend["timestamps"], y=score_trend["values"],
                    name="Health Score", line=dict(color="#68d391", width=2)
                ), secondary_y=False)
                fig2.add_trace(go.Scatter(
                    x=disk_trend["timestamps"], y=disk_trend["values"],
                    name="Disk %", line=dict(color="#f6ad55", width=2,
                                             dash="dot")
                ), secondary_y=True)
                fig2.update_layout(
                    title="Health Score & Disk Usage",
                    paper_bgcolor="#1a1a2e",
                    plot_bgcolor="#0d1117",
                    font=dict(color="#a0aec0"),
                    height=300,
                    margin=dict(t=40, b=20, l=20, r=20)
                )
                st.plotly_chart(fig2, use_container_width=True)

        except ImportError:
            st.warning("Install plotly for charts: `pip install plotly`")

        st.markdown("---")

        # ── Disk Prediction ───────────────────────────────────────────────
        st.markdown('<div class="section-header">DISK PREDICTION</div>',
                    unsafe_allow_html=True)
        pred = store.predict_disk_full()
        if pred["available"]:
            if pred.get("days_until_full"):
                days = pred["days_until_full"]
                risk_css = ("risk-high" if days < 7
                            else "risk-medium" if days < 30
                            else "risk-low")
                st.markdown(f"""
                <div class="risk-card {risk_css}">
                    <strong>Disk Prediction</strong><br>
                    Current: {pred['current_percent']}% used<br>
                    Growth: {pred['growth_gb_per_day']}% per day<br>
                    {pred['message']}<br>
                    <span style="color:#4a5568;font-size:0.75rem;">
                    Confidence: {pred['confidence']} ({record_count} data points)</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.success(f"✅ {pred['message']}")
        else:
            st.info(pred["message"])

        st.markdown("---")

        # ── Anomaly Check ──────────────────────────────────────────────────
        st.markdown('<div class="section-header">ANOMALY DETECTION</div>',
                    unsafe_allow_html=True)
        col_an1, col_an2 = st.columns(2)
        with col_an1:
            ram_anom = store.detect_anomalies("ram_percent", hours=1)
            st.markdown(f"**RAM:** {ram_anom['message']}")
            if ram_anom.get("z_score"):
                st.caption(f"Z-score: {ram_anom['z_score']} | "
                           f"Baseline avg: {ram_anom['baseline_avg']}%")
        with col_an2:
            cpu_anom = store.detect_anomalies("cpu_percent", hours=1)
            st.markdown(f"**CPU:** {cpu_anom['message']}")
            if cpu_anom.get("z_score"):
                st.caption(f"Z-score: {cpu_anom['z_score']} | "
                           f"Baseline avg: {cpu_anom['baseline_avg']}%")

        st.markdown("---")
        if st.button("🗑️ Clean old data (keep 7 days)", key="btn_cleanup"):
            store.cleanup_old_data(keep_days=7)
            st.success("Old data cleaned.")
            st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# AI CHAT
# ══════════════════════════════════════════════════════════════════════════════
elif active == "AI Chat":
    st.markdown('<div class="section-header">AI SYSTEM CHAT</div>',
                unsafe_allow_html=True)
    st.caption("Ask anything. The AI has live access to your system stats.")

    ollama_ok = is_ollama_running()
    available_models = get_available_models() if ollama_ok else []

    if not ollama_ok:
        st.error("🔴 Ollama not running — start with: `ollama serve`")

    col_m, col_clr = st.columns([3, 1])
    with col_m:
        if available_models:
            chat_model = st.selectbox("Model", available_models, key="chat_model")
        else:
            chat_model = st.text_input("Model", value="llama3.2:3b",
                                       key="chat_model_input")
    with col_clr:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.chat_history = []
            st.rerun()

    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input(
        "Ask about your system... e.g. 'Why is my RAM high?'",
        disabled=not ollama_ok
    ):
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                snap = get_full_snapshot()
                history_for_ollama = [
                    {"role": m["role"], "content": m["content"]}
                    for m in st.session_state.chat_history[:-1]
                ]
                response = chat_with_system(prompt, snap, history_for_ollama,
                                            chat_model)
            st.markdown(response)
            st.session_state.chat_history.append(
                {"role": "assistant", "content": response})

    if not st.session_state.chat_history:
        st.markdown("""
        **Try asking:**
        - *Why is my RAM so high?*
        - *Which process should I kill first?*
        - *Is my system under attack?*
        - *How do I free up disk space?*
        - *Why is my system slow?*
        """)

# ─── Footer ──────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#4a5568;font-size:0.75rem;'>"
    "SysGuard AI v0.2 — Streamlit + psutil + Ollama | Security + AI by Arzoo"
    "</div>",
    unsafe_allow_html=True
)
