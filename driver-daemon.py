#!/usr/bin/env python3
"""
ClaudeOS Driver AI Daemon
Continuously monitors hardware, detects driver issues, and provides
AI-powered diagnostics and automatic repair suggestions.
"""

import os
import sys
import json
import time
import logging
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional

try:
    import requests
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

# ─── Config ───────────────────────────────────────────────────────────────────

OLLAMA_URL    = os.environ.get("CLAUDEOS_OLLAMA_URL", "http://localhost:11434")
MODEL         = os.environ.get("CLAUDEOS_MODEL", "llama3")
SCAN_INTERVAL = int(os.environ.get("CLAUDEOS_SCAN_INTERVAL", "300"))  # seconds
LOG_DIR       = Path("/var/log/claudeos")
REPORT_DIR    = Path.home() / ".claudeos" / "reports"
DAEMON_SOCKET = Path("/tmp/claudeos-driver-daemon.sock")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger("claudeos.drivers")

# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class DeviceInfo:
    pci_id: str
    name: str
    driver: Optional[str]
    modules: list[str]
    status: str          # "ok" | "no-driver" | "error" | "firmware-needed"
    firmware_missing: list[str]
    kernel_messages: list[str]

@dataclass
class DriverReport:
    timestamp: str
    kernel: str
    distro: str
    devices: list[DeviceInfo]
    health_score: str    # "GOOD" | "NEEDS ATTENTION" | "CRITICAL"
    issues: list[str]
    fix_commands: list[str]
    ai_summary: str

# ─── Hardware scanner ──────────────────────────────────────────────────────────

class HardwareScanner:
    """Enumerate PCI/USB devices and their driver states."""

    def run(self, cmd: str, timeout: int = 10) -> str:
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return (r.stdout + r.stderr).strip()
        except Exception as e:
            return f"[error: {e}]"

    def get_pci_devices(self) -> list[dict]:
        raw = self.run("lspci -nnkmm 2>/dev/null")
        devices = []
        current = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                if current:
                    devices.append(current)
                    current = {}
                continue
            if ":" in line:
                key, _, val = line.partition(":")
                current[key.strip()] = val.strip()
        if current:
            devices.append(current)
        return devices

    def get_driver_for_device(self, slot: str) -> tuple[str, list[str]]:
        """Return (driver_name, [modules]) for a PCI slot."""
        out = self.run(f"lspci -ks {slot} 2>/dev/null")
        driver, modules = "", []
        for line in out.splitlines():
            if "Kernel driver in use" in line:
                driver = line.split(":")[-1].strip()
            if "Kernel modules" in line:
                modules = [m.strip() for m in line.split(":")[-1].split(",")]
        return driver, modules

    def get_dmesg_errors(self) -> list[str]:
        out = self.run("dmesg --level=err,warn --since='1 hour ago' 2>/dev/null | tail -50")
        return [l for l in out.splitlines() if l.strip()]

    def get_firmware_errors(self) -> list[str]:
        out = self.run("dmesg 2>/dev/null | grep -i 'firmware.*failed\\|failed.*firmware\\|direct firmware load' | tail -30")
        return [l.strip() for l in out.splitlines() if l.strip()]

    def get_missing_modules(self) -> list[str]:
        out = self.run("dmesg 2>/dev/null | grep -iE 'module.*not found|unknown symbol|disagrees about version' | tail -20")
        return [l.strip() for l in out.splitlines() if l.strip()]

    def get_system_info(self) -> tuple[str, str]:
        kernel = self.run("uname -r").strip()
        distro = self.run("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'").strip()
        return kernel, distro

    def scan(self) -> dict:
        """Full hardware scan — returns raw data dict."""
        log.info("Starting hardware scan…")
        devices     = self.get_pci_devices()
        dmesg_errs  = self.get_dmesg_errors()
        fw_errors   = self.get_firmware_errors()
        miss_mods   = self.get_missing_modules()
        kernel, distro = self.get_system_info()

        device_states = []
        for dev in devices[:30]:   # cap for AI context size
            slot   = dev.get("Slot", "")
            name   = dev.get("Device", dev.get("SDevice", "Unknown"))
            driver, modules = self.get_driver_for_device(slot) if slot else ("", [])

            # Check firmware errors for this device
            fw_missing = [e for e in fw_errors if slot.lower() in e.lower() or
                          any(m.lower() in e.lower() for m in modules)]

            status = "ok"
            if not driver and modules:
                status = "no-driver"
            elif fw_missing:
                status = "firmware-needed"

            device_states.append(DeviceInfo(
                pci_id=slot,
                name=name,
                driver=driver or None,
                modules=modules,
                status=status,
                firmware_missing=fw_missing,
                kernel_messages=[e for e in dmesg_errs if slot in e]
            ))

        return {
            "kernel": kernel,
            "distro": distro,
            "devices": device_states,
            "dmesg_errors": dmesg_errs,
            "firmware_errors": fw_errors,
            "missing_modules": miss_mods,
            "lspci_full": self.run("lspci -nnk 2>/dev/null | head -80"),
            "lsusb": self.run("lsusb 2>/dev/null"),
        }

# ─── AI Analyzer ──────────────────────────────────────────────────────────────

class DriverAIAnalyzer:
    """Feed hardware scan data to local LLM and parse structured response."""

    SYSTEM = """You are an expert Linux kernel and driver engineer embedded in an OS.
Analyze hardware scan data and output ONLY valid JSON matching this schema:
{
  "health_score": "GOOD|NEEDS ATTENTION|CRITICAL",
  "issues": ["list of issues found"],
  "fix_commands": ["exact shell commands to fix each issue"],
  "firmware_packages": ["package names needed"],
  "summary": "2-3 sentence plain English summary"
}
Be precise. Only include real, installable packages. Prefer distro package managers."""

    def analyze(self, scan_data: dict) -> dict:
        if not self._ollama_ok():
            log.warning("Ollama not available, skipping AI analysis")
            return self._fallback_analysis(scan_data)

        devices_summary = "\n".join(
            f"  [{d.status.upper()}] {d.name} | driver: {d.driver or 'NONE'} | modules: {','.join(d.modules) or 'none'}"
            for d in scan_data["devices"]
        )

        prompt = f"""Analyze this Linux system's driver health:

Kernel: {scan_data['kernel']}
Distro: {scan_data['distro']}

Devices ({len(scan_data['devices'])} total):
{devices_summary}

Firmware errors:
{chr(10).join(scan_data['firmware_errors'][:10]) or 'none'}

Kernel errors (dmesg):
{chr(10).join(scan_data['dmesg_errors'][:15]) or 'none'}

Missing modules:
{chr(10).join(scan_data['missing_modules'][:10]) or 'none'}

Full PCI list:
{scan_data['lspci_full'][:2000]}

Respond with JSON only."""

        try:
            r = requests.post(f"{OLLAMA_URL}/api/generate", json={
                "model": MODEL,
                "prompt": prompt,
                "system": self.SYSTEM,
                "stream": False,
                "format": "json",
            }, timeout=120)
            r.raise_for_status()
            raw = r.json().get("response", "{}")
            return json.loads(raw)
        except json.JSONDecodeError:
            log.error("AI returned invalid JSON")
            return self._fallback_analysis(scan_data)
        except Exception as e:
            log.error(f"AI analysis failed: {e}")
            return self._fallback_analysis(scan_data)

    def _ollama_ok(self) -> bool:
        try:
            return requests.get(f"{OLLAMA_URL}/api/tags", timeout=2).status_code == 200
        except Exception:
            return False

    def _fallback_analysis(self, scan_data: dict) -> dict:
        """Rule-based fallback when AI is unavailable."""
        issues, fixes = [], []
        no_driver = [d for d in scan_data["devices"] if d.status == "no-driver"]
        fw_needed  = [d for d in scan_data["devices"] if d.status == "firmware-needed"]

        for d in no_driver:
            issues.append(f"No driver for: {d.name} ({d.pci_id})")
            fixes.append(f"# Investigate: lspci -nnk -s {d.pci_id}")

        for d in fw_needed:
            issues.append(f"Firmware missing for: {d.name}")
            fixes.append("sudo apt install linux-firmware  # or: dnf install linux-firmware")

        if scan_data["missing_modules"]:
            issues.append("Missing kernel modules detected in dmesg")

        score = "GOOD" if not issues else ("CRITICAL" if len(issues) > 3 else "NEEDS ATTENTION")
        return {
            "health_score": score,
            "issues": issues or ["No obvious driver issues detected"],
            "fix_commands": fixes,
            "firmware_packages": [],
            "summary": f"Rule-based scan found {len(issues)} issue(s). AI offline."
        }

# ─── Report writer ─────────────────────────────────────────────────────────────

def save_report(scan_data: dict, analysis: dict):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = REPORT_DIR / f"driver-report-{ts}.json"

    report = {
        "timestamp": ts,
        "kernel": scan_data["kernel"],
        "distro": scan_data["distro"],
        "health_score": analysis.get("health_score", "UNKNOWN"),
        "issues": analysis.get("issues", []),
        "fix_commands": analysis.get("fix_commands", []),
        "firmware_packages": analysis.get("firmware_packages", []),
        "ai_summary": analysis.get("summary", ""),
        "device_count": len(scan_data["devices"]),
    }
    path.write_text(json.dumps(report, indent=2, default=str))
    log.info(f"Report saved: {path}")
    return path

def print_report(analysis: dict, scan_data: dict):
    """Pretty-print report to terminal."""
    score = analysis.get("health_score", "UNKNOWN")
    color = {"GOOD": "\033[32m", "NEEDS ATTENTION": "\033[33m", "CRITICAL": "\033[31m"}.get(score, "")
    reset = "\033[0m"

    print(f"\n{'─'*60}")
    print(f"  ClaudeOS Driver Health: {color}{score}{reset}")
    print(f"  Kernel: {scan_data['kernel']} | Distro: {scan_data['distro']}")
    print(f"{'─'*60}")

    if analysis.get("summary"):
        print(f"\n  Summary: {analysis['summary']}\n")

    issues = analysis.get("issues", [])
    if issues:
        print("  Issues found:")
        for i in issues:
            print(f"    ⚠  {i}")

    fixes = analysis.get("fix_commands", [])
    if fixes:
        print("\n  Suggested fixes:")
        for f in fixes:
            print(f"    $ {f}")

    fw = analysis.get("firmware_packages", [])
    if fw:
        print(f"\n  Firmware packages needed: {', '.join(fw)}")

    print(f"\n{'─'*60}\n")

# ─── Daemon loop ───────────────────────────────────────────────────────────────

def run_daemon():
    """Continuous monitoring loop."""
    scanner  = HardwareScanner()
    analyzer = DriverAIAnalyzer()

    log.info(f"ClaudeOS Driver Daemon started (scan every {SCAN_INTERVAL}s)")

    while True:
        try:
            scan_data = scanner.scan()
            analysis  = analyzer.analyze(scan_data)
            report_path = save_report(scan_data, analysis)
            print_report(analysis, scan_data)

            score = analysis.get("health_score", "")
            if score == "CRITICAL":
                log.critical("CRITICAL driver issues detected! See report for fixes.")
            elif score == "NEEDS ATTENTION":
                log.warning("Driver issues detected. Run `ai drivers` for details.")

        except Exception as e:
            log.error(f"Scan failed: {e}", exc_info=True)

        time.sleep(SCAN_INTERVAL)

def run_once():
    """Single scan for CLI use (called by claude-shell `ai drivers`)."""
    scanner  = HardwareScanner()
    analyzer = DriverAIAnalyzer()
    scan_data = scanner.scan()
    analysis  = analyzer.analyze(scan_data)
    save_report(scan_data, analysis)
    print_report(analysis, scan_data)

if __name__ == "__main__":
    if "--daemon" in sys.argv:
        run_daemon()
    else:
        run_once()
