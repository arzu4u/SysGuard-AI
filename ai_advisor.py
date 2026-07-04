"""
SysGuard AI — AI Advisor Module
Ollama integration for intelligent system analysis and chat
"""

import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_CHAT_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "llama3.2:3b"


def is_ollama_running():
    """Check if Ollama service is available"""
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def get_available_models():
    """Return list of models installed in Ollama"""
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            data = r.json()
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        pass
    return []


def analyze_system(snapshot: dict, model: str = DEFAULT_MODEL) -> str:
    if not is_ollama_running():
        return "Ollama is not running. Start it with: ollama serve"

    cpu = snapshot.get("cpu", {})
    ram = snapshot.get("ram", {})
    disk = snapshot.get("disk", [{}])
    procs = snapshot.get("processes", {})
    net = snapshot.get("network", {})

    disk_info = ""
    for d in disk[:3]:
        disk_info += f"\n  - {d.get('mountpoint')}: {d.get('percent')}% used ({d.get('used_gb')}GB / {d.get('total_gb')}GB)"

    top_cpu_procs = procs.get("by_cpu", [])[:3]
    top_mem_procs = procs.get("by_mem", [])[:3]
    top_cpu_str = ", ".join([f"{p['name']}({p['cpu_percent']:.1f}%)" for p in top_cpu_procs if p.get('cpu_percent')])
    top_mem_str = ", ".join([f"{p['name']}({p['memory_percent']:.1f}%)" for p in top_mem_procs if p.get('memory_percent')])

    prompt = f"""You are a Linux system expert analyzing an Ubuntu system.
Speak directly to the user. Be specific, human, and practical.
Never just repeat numbers - explain what they MEAN and what to DO.

CURRENT SYSTEM STATE:
- CPU: {cpu.get('percent')}% used | {cpu.get('count_logical')} cores | {cpu.get('freq_current')} MHz
- RAM: {ram.get('percent')}% used | {ram.get('used_gb')}GB used of {ram.get('total_gb')}GB | {ram.get('available_gb')}GB free
- Swap: {ram.get('swap_percent')}% | {ram.get('swap_used_gb')}GB of {ram.get('swap_total_gb')}GB
- Disk:{disk_info}
- Processes: {procs.get('total_count')} total | {procs.get('total_zombie')} zombie(s)
- Top CPU consumers: {top_cpu_str or 'None significant'}
- Top RAM consumers: {top_mem_str or 'None significant'}
- Network: {net.get('total_connections')} connections | Listening ports: {net.get('listening_ports')}

Give a clear, honest, human-language system health assessment.
Structure your response in these sections:
1. Overall Status (one sentence verdict)
2. What needs attention right now (if anything)
3. What looks healthy
4. Top 2-3 specific recommendations

Keep it under 200 words. Be like a trusted sysadmin friend."""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": 400}
            },
            timeout=60
        )
        if response.status_code == 200:
            return response.json().get("response", "No response from model.")
        return f"Ollama error: HTTP {response.status_code}"
    except requests.exceptions.Timeout:
        return "Analysis timed out. Try a lighter model like llama3.2:3b"
    except Exception as e:
        return f"Could not reach Ollama: {str(e)}"


def chat_with_system(user_message: str, snapshot: dict, history: list, model: str = DEFAULT_MODEL) -> str:
    if not is_ollama_running():
        return "Ollama is not running. Start it with: ollama serve"

    cpu = snapshot.get("cpu", {})
    ram = snapshot.get("ram", {})
    disk = snapshot.get("disk", [{}])
    procs = snapshot.get("processes", {})
    net = snapshot.get("network", {})
    sys_info = snapshot.get("system", {})

    disk_str = " | ".join([f"{d.get('mountpoint')} {d.get('percent')}%" for d in disk[:2]])

    system_context = f"""You are SysGuard AI, an intelligent Ubuntu system assistant.
You have live access to the user's system. Answer using only this real data.
Be specific, helpful, and honest. Never make up numbers.

LIVE SYSTEM DATA:
- Hostname: {sys_info.get('hostname')} | Uptime: {sys_info.get('uptime')}
- CPU: {cpu.get('percent')}% | Cores: {cpu.get('count_logical')} | Freq: {cpu.get('freq_current')} MHz
- RAM: {ram.get('used_gb')}GB / {ram.get('total_gb')}GB ({ram.get('percent')}%) | Free: {ram.get('available_gb')}GB
- Swap: {ram.get('swap_used_gb')}GB / {ram.get('swap_total_gb')}GB ({ram.get('swap_percent')}%)
- Disk: {disk_str}
- Processes: {procs.get('total_count')} | Zombies: {procs.get('total_zombie')}
- Connections: {net.get('total_connections')} | Ports: {net.get('listening_ports')}

Answer conversationally. Provide exact Ubuntu commands when asked."""

    messages = [{"role": "system", "content": system_context}]
    messages += history[-8:]
    messages.append({"role": "user", "content": user_message})

    try:
        response = requests.post(
            OLLAMA_CHAT_URL,
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": 0.4, "num_predict": 500}
            },
            timeout=90
        )
        if response.status_code == 200:
            return response.json().get("message", {}).get("content", "No response.")
        return f"Ollama error: HTTP {response.status_code}"
    except requests.exceptions.Timeout:
        return "Response timed out. Try asking something shorter."
    except Exception as e:
        return f"Chat error: {str(e)}"
