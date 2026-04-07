#!/usr/bin/env python3
"""
ClaudeOS Security Daemon
AI-powered real-time security monitoring: file integrity, port scanning,
privilege escalation detection, and threat analysis.
"""

import os
import sys
import json
import time
import hashlib
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    import requests
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

OLLAMA_URL = os.environ.get("CLAUDEOS_OLLAMA_URL", "http://localhost:11434")
MODEL      = os.environ.get("CLAUDEOS_MODEL", "llama3")
WATCH_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]
INTEGRITY_DB = Path.home() / ".claudeos" / "integrity.json"
REPORT_DIR   = Path.home() / ".claudeos" / "security"
log = logging.getLogger("claudeos.security")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ─── System checks ─────────────────────────────────────────────────────────────

def run(cmd: str) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f"[error: {e}]"

def collect_security_data() -> dict:
    return {
        "open_ports":    run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"),
        "suid_files":    run("find / -perm /4000 -type f 2>/dev/null | head -30"),
        "world_writable":run("find /etc /usr /bin /sbin -perm /o+w -type f 2>/dev/null | head -20"),
        "sudoers":       run("cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'"),
        "auth_log":      run("tail -30 /var/log/auth.log 2>/dev/null || journalctl _COMM=sudo -n30 2>/dev/null"),
        "users":         run("cat /etc/passwd | grep -v nologin | grep -v false"),
        "ssh_config":    run("cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'"),
        "cron_jobs":     run("ls -la /etc/cron* 2>/dev/null && crontab -l 2>/dev/null"),
        "processes":     run("ps aux --sort=-%cpu 2>/dev/null | head -20"),
        "kernel_params": run("sysctl -a 2>/dev/null | grep -E 'net.ipv4.ip_forward|randomize_va_space|kernel.dmesg_restrict'"),
        "failed_logins": run("lastb 2>/dev/null | head -15 || journalctl _COMM=sshd --since='24h ago' 2>/dev/null | grep Failed | tail -15"),
    }

# ─── File integrity ────────────────────────────────────────────────────────────

def hash_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def build_integrity_baseline(directories: list[str] = WATCH_DIRS) -> dict:
    log.info("Building integrity baseline...")
    baseline = {}
    for d in directories:
        for path in Path(d).rglob("*"):
            if path.is_file() and not path.is_symlink():
                h = hash_file(str(path))
                if h:
                    baseline[str(path)] = {
                        "hash": h,
                        "mtime": path.stat().st_mtime,
                        "size": path.stat().st_size,
                    }
    log.info(f"Baseline: {len(baseline)} files indexed")
    return baseline

def check_integrity(baseline: dict) -> list[dict]:
    changes = []
    for path_str, info in baseline.items():
        path = Path(path_str)
        if not path.exists():
            changes.append({"file": path_str, "change": "DELETED"})
            continue
        current_hash = hash_file(path_str)
        if current_hash and current_hash != info["hash"]:
            changes.append({
                "file": path_str,
                "change": "MODIFIED",
                "old_hash": info["hash"][:12],
                "new_hash": current_hash[:12],
            })
    return changes

# ─── AI threat analysis ────────────────────────────────────────────────────────

SECURITY_SYSTEM = """You are a Linux security expert. Analyze the provided system security data and output JSON:
{
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "findings": [{"severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL", "description": "...", "fix": "..."}],
  "hardening_commands": ["exact commands to improve security"],
  "summary": "2-3 sentence overview"
}
Focus on real threats. Avoid false positives. Be specific and actionable."""

def analyze_security(data: dict, integrity_changes: list) -> dict:
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        if r.status_code != 200:
            raise ConnectionError("Ollama offline")
    except Exception:
        log.warning("Ollama offline — skipping AI security analysis")
        return {
            "threat_level": "UNKNOWN",
            "findings": [{"severity": "INFO", "description": "AI offline — manual review required", "fix": "Start Ollama: ollama serve"}],
            "hardening_commands": [],
            "summary": "AI unavailable. Manual security review recommended."
        }

    integrity_summary = ""
    if integrity_changes:
        integrity_summary = f"\n\nFile integrity violations ({len(integrity_changes)}):\n"
        integrity_summary += "\n".join(f"  {c['change']}: {c['file']}" for c in integrity_changes[:10])

    prompt = f"""Security audit for Linux system:

Open ports and services:
{data['open_ports'][:1000]}

SUID binaries:
{data['suid_files'][:500]}

World-writable system files:
{data['world_writable'][:300]}

SSH configuration:
{data['ssh_config'][:500]}

Recent authentication log:
{data['auth_log'][:800]}

Active users (non-system):
{data['users'][:300]}

Kernel security params:
{data['kernel_params'][:300]}

Failed login attempts:
{data['failed_logins'][:500]}

Cron jobs:
{data['cron_jobs'][:400]}
{integrity_summary}

Respond with JSON only."""

    try:
        r = requests.post(f"{OLLAMA_URL}/api/generate", json={
            "model": MODEL,
            "prompt": prompt,
            "system": SECURITY_SYSTEM,
            "stream": False,
            "format": "json",
        }, timeout=120)
        r.raise_for_status()
        return json.loads(r.json().get("response", "{}"))
    except Exception as e:
        log.error(f"Security AI failed: {e}")
        return {"threat_level": "UNKNOWN", "findings": [], "hardening_commands": [], "summary": str(e)}

# ─── Reporting ─────────────────────────────────────────────────────────────────

def print_security_report(analysis: dict, changes: list):
    level = analysis.get("threat_level", "UNKNOWN")
    color = {"LOW": "\033[32m","MEDIUM": "\033[33m","HIGH": "\033[31m","CRITICAL": "\033[35m"}.get(level, "")
    reset = "\033[0m"

    print(f"\n{'═'*60}")
    print(f"  ClaudeOS Security Report — {color}{level}{reset}")
    print(f"{'═'*60}")

    if analysis.get("summary"):
        print(f"\n  {analysis['summary']}\n")

    for f in analysis.get("findings", []):
        sev = f.get("severity", "INFO")
        sc  = {"CRITICAL":"\033[35m","HIGH":"\033[31m","MEDIUM":"\033[33m","LOW":"\033[32m"}.get(sev,"")
        print(f"  {sc}[{sev}]{reset} {f.get('description','')}")
        if f.get("fix"):
            print(f"        Fix: {f['fix']}")

    if changes:
        print(f"\n  ⚠  File integrity: {len(changes)} change(s) detected")
        for c in changes[:5]:
            print(f"     {c['change']}: {c['file']}")

    cmds = analysis.get("hardening_commands", [])
    if cmds:
        print(f"\n  Hardening commands:")
        for cmd in cmds[:5]:
            print(f"    $ {cmd}")

    print(f"\n{'═'*60}\n")

def run_security_check():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    log.info("Running security audit…")

    data = collect_security_data()

    # Integrity check
    changes = []
    if INTEGRITY_DB.exists():
        baseline = json.loads(INTEGRITY_DB.read_text())
        changes  = check_integrity(baseline)
    else:
        log.info("No baseline found — run with --baseline to create one")

    analysis = analyze_security(data, changes)
    print_security_report(analysis, changes)

    ts   = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = REPORT_DIR / f"security-{ts}.json"
    path.write_text(json.dumps({
        "timestamp": ts,
        "threat_level": analysis.get("threat_level"),
        "findings": analysis.get("findings", []),
        "hardening_commands": analysis.get("hardening_commands", []),
        "integrity_changes": changes,
        "summary": analysis.get("summary", ""),
    }, indent=2))
    log.info(f"Report saved: {path}")

if __name__ == "__main__":
    if "--baseline" in sys.argv:
        baseline = build_integrity_baseline()
        INTEGRITY_DB.parent.mkdir(parents=True, exist_ok=True)
        INTEGRITY_DB.write_text(json.dumps(baseline, indent=2))
        print(f"Baseline saved: {INTEGRITY_DB} ({len(baseline)} files)")
    elif "--daemon" in sys.argv:
        interval = int(os.environ.get("CLAUDEOS_SEC_INTERVAL", "3600"))
        log.info(f"Security daemon started (scan every {interval}s)")
        while True:
            run_security_check()
            time.sleep(interval)
    else:
        run_security_check()
