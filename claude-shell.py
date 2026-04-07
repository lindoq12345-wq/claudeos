#!/usr/bin/env python3
"""
ClaudeOS AI Shell — Intelligent terminal with native AI integration.
Wraps bash/zsh and adds LLM-powered error recovery, command suggestion,
natural language execution, and driver diagnostics.
"""

import os
import sys
import subprocess
import readline
import json
import re
import signal
import time
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    print("[claudeos] Installing requests...")
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

# ─── Config ───────────────────────────────────────────────────────────────────

OLLAMA_URL     = os.environ.get("CLAUDEOS_OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL  = os.environ.get("CLAUDEOS_MODEL", "llama3")
HISTORY_FILE   = Path.home() / ".claudeos_history"
CONFIG_FILE    = Path.home() / ".claudeos_config.json"
AI_PREFIX      = "ai"        # trigger: `ai explain why nginx failed`
MAX_HISTORY    = 500

COLORS = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "purple":  "\033[38;5;141m",
    "blue":    "\033[38;5;75m",
    "green":   "\033[38;5;114m",
    "yellow":  "\033[38;5;221m",
    "red":     "\033[38;5;203m",
    "gray":    "\033[38;5;245m",
    "white":   "\033[38;5;255m",
}

def c(color, text): return f"{COLORS.get(color,'')}{text}{COLORS['reset']}"

# ─── Ollama client ─────────────────────────────────────────────────────────────

def ollama_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False

def ask_ai(prompt: str, system: str = "", model: str = DEFAULT_MODEL) -> str:
    """Send a prompt to local Ollama instance and stream the response."""
    payload = {
        "model": model,
        "prompt": prompt,
        "system": system or SYSTEM_PROMPT,
        "stream": True,
    }
    try:
        with requests.post(f"{OLLAMA_URL}/api/generate", json=payload, stream=True, timeout=60) as r:
            r.raise_for_status()
            result = []
            for line in r.iter_lines():
                if line:
                    data = json.loads(line)
                    token = data.get("response", "")
                    result.append(token)
                    print(token, end="", flush=True)
                    if data.get("done"):
                        break
            print()
            return "".join(result)
    except requests.exceptions.ConnectionError:
        return "[error] Ollama not reachable. Run: ollama serve"
    except Exception as e:
        return f"[error] {e}"

SYSTEM_PROMPT = """You are ClaudeOS Shell AI, a helpful assistant integrated into a Linux terminal.
You are concise, technically accurate, and security-conscious.
When explaining errors: give root cause first, then the fix command.
When suggesting commands: always show the exact command in a code block.
When analyzing drivers: check for known issues, firmware needs, and kernel compatibility.
Never run destructive commands without explicit user confirmation.
Respond in the same language the user writes in."""

# ─── Command execution ─────────────────────────────────────────────────────────

def run_command(cmd: str) -> tuple[int, str, str]:
    """Run a shell command, return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, text=True,
            capture_output=True, timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out after 30s"
    except Exception as e:
        return 1, "", str(e)

def handle_error(cmd: str, stderr: str, returncode: int):
    """When a command fails, ask AI to explain and suggest a fix."""
    print(c("yellow", f"\n● AI analyzing error (exit {returncode})…\n"))
    prompt = f"""The user ran this command:
  $ {cmd}

It failed with exit code {returncode} and this error:
  {stderr.strip()}

1. Explain the root cause in 1-2 sentences.
2. Provide the exact fix command(s).
3. If it's a permission or security issue, warn the user."""
    ask_ai(prompt)
    print()

# ─── AI subcommands ────────────────────────────────────────────────────────────

def ai_natural_language(query: str):
    """Convert natural language to shell command."""
    print(c("purple", "\n● Translating to command…\n"))
    prompt = f"""Convert this natural language request to a shell command for Linux:
"{query}"

Reply ONLY with:
1. The exact command (in a code block)
2. A one-line explanation of what it does
3. Any safety warnings if relevant

Do NOT execute the command, just show it."""
    ask_ai(prompt)
    print()

def ai_explain(target: str):
    """Explain a command, file, log, or concept."""
    # If target looks like a file, read it
    if os.path.isfile(target):
        try:
            content = Path(target).read_text(errors="replace")[:4000]
            prompt = f"Analyze this file ({target}) and explain what it does, any errors present, and suggested fixes:\n\n{content}"
        except Exception as e:
            prompt = f"Explain this: {target} (could not read file: {e})"
    else:
        prompt = f"Explain this Linux concept, command, or error message clearly and concisely:\n{target}"
    ask_ai(prompt)
    print()

def ai_fix(cmd: str):
    """Suggest a fix for a broken command."""
    print(c("purple", "\n● Looking for fixes…\n"))
    prompt = f"The command `{cmd}` is not working or has a mistake. Show the corrected version with explanation."
    ask_ai(prompt)
    print()

def ai_security_check(path: str = "."):
    """Run a quick AI-powered security check on a path."""
    print(c("yellow", f"\n● Security check on {path}…\n"))
    rc, out, err = run_command(f"ls -la {path} 2>&1 | head -40")
    rc2, out2, _ = run_command(f"find {path} -maxdepth 2 -perm /o+w 2>/dev/null | head -20")
    rc3, out3, _ = run_command("id && whoami && groups")
    prompt = f"""Perform a quick security assessment:

Directory listing of {path}:
{out}

World-writable files found:
{out2 or 'none'}

Current user context:
{out3}

Flag any security concerns: excessive permissions, suspicious files, privilege issues."""
    ask_ai(prompt)
    print()

# ─── Driver AI module ──────────────────────────────────────────────────────────

def ai_drivers(device: str = ""):
    """Analyze drivers with AI — detect issues, firmware needs, and compatibility."""
    print(c("blue", "\n● Scanning hardware and drivers…\n"))

    commands = {
        "lspci":     "lspci -nnk 2>/dev/null | head -60",
        "lsusb":     "lsusb 2>/dev/null",
        "dmesg":     "dmesg --level=err,warn 2>/dev/null | tail -30",
        "modules":   "lsmod 2>/dev/null | head -40",
        "firmware":  "journalctl -b -k --grep='firmware' 2>/dev/null | tail -20",
        "missing":   "dmesg 2>/dev/null | grep -i 'failed\\|not found\\|error\\|missing' | tail -20",
    }

    if device:
        commands["device"] = f"lspci -nnkv 2>/dev/null | grep -A8 -i '{device}'"

    results = {}
    for key, cmd in commands.items():
        rc, out, err = run_command(cmd)
        results[key] = out.strip() or "(no output)"

    print(c("gray", "  Hardware enumerated. Sending to AI…\n"))

    prompt = f"""You are a Linux driver and hardware expert. Analyze this system's driver state:

=== PCI Devices & Drivers ===
{results['lspci']}

=== USB Devices ===
{results['lsusb']}

=== Kernel Errors/Warnings (dmesg) ===
{results['dmesg']}

=== Loaded Modules ===
{results['modules']}

=== Firmware Messages ===
{results['firmware']}

=== Errors & Missing Drivers ===
{results['missing']}

{'=== Target Device ===' + chr(10) + results.get('device','') if device else ''}

Please:
1. List devices WITHOUT a proper driver (with fix commands)
2. List firmware that needs updating (with exact package names)
3. Flag any kernel module conflicts or errors
4. Score overall driver health: GOOD / NEEDS ATTENTION / CRITICAL
5. Provide the 3 most important commands to run for repairs"""

    ask_ai(prompt)
    print()

def ai_driver_install(device_description: str):
    """AI-guided driver installation for a specific device."""
    print(c("blue", f"\n● Finding driver for: {device_description}\n"))

    rc, distro_out, _ = run_command("cat /etc/os-release 2>/dev/null | head -5")
    rc2, kernel_out, _ = run_command("uname -r")

    prompt = f"""A user needs to install a driver for: {device_description}

System info:
{distro_out}
Kernel: {kernel_out.strip()}

Provide:
1. The exact package name to install
2. The install command for this distro
3. Whether a reboot is required
4. How to verify the driver loaded correctly
5. Any known issues or gotchas"""
    ask_ai(prompt)
    print()

# ─── Prompt display ────────────────────────────────────────────────────────────

def get_prompt() -> str:
    user   = os.environ.get("USER", "user")
    cwd    = os.getcwd().replace(str(Path.home()), "~")
    git    = ""
    rc, branch, _ = run_command("git branch --show-current 2>/dev/null")
    if rc == 0 and branch.strip():
        git = c("gray", f" ({branch.strip()})")
    ai_dot = c("purple", "●") if ollama_available() else c("gray", "○")
    return (
        f"\n{ai_dot} {c('purple','claudeos')} {c('gray','|')} "
        f"{c('blue', user)} {c('gray','in')} {c('green', cwd)}{git}\n"
        f"{c('purple','›')} "
    )

# ─── History ───────────────────────────────────────────────────────────────────

def setup_history():
    readline.set_history_length(MAX_HISTORY)
    if HISTORY_FILE.exists():
        readline.read_history_file(str(HISTORY_FILE))
    import atexit
    atexit.register(readline.write_history_file, str(HISTORY_FILE))

# ─── Main REPL ─────────────────────────────────────────────────────────────────

def handle_ai_command(parts: list[str]):
    """Route `ai <subcommand> <args>` to the right function."""
    if len(parts) < 2:
        print_ai_help()
        return

    sub  = parts[1].lower()
    args = " ".join(parts[2:])

    if sub in ("explain", "what", "why"):       ai_explain(args or parts[-1])
    elif sub in ("fix", "repair"):              ai_fix(args)
    elif sub in ("do", "run", "how"):           ai_natural_language(args)
    elif sub in ("drivers", "driver", "hw"):    ai_drivers(args)
    elif sub in ("install-driver",):            ai_driver_install(args)
    elif sub in ("security", "sec", "check"):   ai_security_check(args or ".")
    elif sub in ("ask", "chat"):                ask_ai(args)
    else:
        # treat entire thing as natural language
        ai_natural_language(" ".join(parts[1:]))

def print_ai_help():
    print(f"""
{c('purple','● ClaudeOS AI Shell commands')}

  {c('blue','ai explain')} <command|file|error>   Explain anything
  {c('blue','ai fix')} <broken-command>            Suggest corrections
  {c('blue','ai do')} <natural language>           Run via natural language
  {c('blue','ai drivers')} [device]                AI driver health check
  {c('blue','ai install-driver')} <device>         Find & install a driver
  {c('blue','ai security')} [path]                 Security audit
  {c('blue','ai ask')} <question>                  Free-form AI chat

{c('gray','All AI runs locally via Ollama. No data leaves your machine.')}
""")

def print_banner():
    print(f"""
{c('purple','  ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ ███████╗')}
{c('purple',' ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔════╝')}
{c('blue','  ██║     ██║     ███████║██║   ██║██║  ██║█████╗  ██║   ██║███████╗')}
{c('blue','  ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝  ██║   ██║╚════██║')}
{c('purple','  ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝███████║')}
{c('purple','   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝')}

  {c('gray','AI-native shell · drivers · security · open source')}
  {c('gray','Type')} {c('blue','ai help')} {c('gray','to get started or')} {c('blue','ai drivers')} {c('gray','for hardware diagnostics')}
  {c('gray','Ollama:')} {'🟢 ' + c('green','connected') if ollama_available() else '🔴 ' + c('red','offline — run: ollama serve')}
""")

def main():
    setup_history()
    print_banner()

    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda s, f: print(c("gray", "\n(Ctrl+C — type 'exit' to quit)")))

    while True:
        try:
            line = input(get_prompt()).strip()
        except EOFError:
            print(c("gray", "\nBye!"))
            break
        if not line:
            continue

        parts = line.split()
        cmd   = parts[0].lower()

        # Built-ins
        if cmd in ("exit", "quit", "q"):
            print(c("gray", "Bye! 👋"))
            break
        elif cmd == "clear":
            os.system("clear")
            continue
        elif cmd == "help":
            print_ai_help()
            continue
        elif cmd == AI_PREFIX:
            handle_ai_command(parts)
            continue

        # Regular shell command
        rc, stdout, stderr = run_command(line)
        if stdout: print(stdout, end="")
        if stderr: print(c("red", stderr), end="")

        # Auto-suggest fix on error
        if rc != 0 and stderr and ollama_available():
            print(c("gray", f"  exit {rc}  "), end="")
            ans = input(c("yellow", "→ ask AI to explain? [y/N] ")).strip().lower()
            if ans == "y":
                handle_error(line, stderr, rc)

if __name__ == "__main__":
    main()
