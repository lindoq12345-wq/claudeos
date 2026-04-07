# ClaudeOS

**AI-native Linux shell, driver diagnostics, and security monitoring — all running locally.**

```
  ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ ███████╗
 ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝██╔═══██╗██╔════╝
 ██║     ██║     ███████║██║   ██║██║  ██║█████╗  ██║   ██║███████╗
 ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝  ██║   ██║╚════██║
 ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗╚██████╔╝███████║
  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
```

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Ollama](https://img.shields.io/badge/AI-Ollama%20local-green.svg)](https://ollama.com)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Security](https://img.shields.io/badge/Security-AI%20monitored-red.svg)](#security-daemon)

---

## What is ClaudeOS?

ClaudeOS is a **modular AI layer for Linux** built on three pillars:

| Component | What it does |
|-----------|-------------|
| `claude-shell` | Intelligent terminal wrapper — explains errors, runs natural language commands, suggests fixes in real time |
| `claudeos-drivers` | AI-powered hardware scanner — detects missing drivers, firmware gaps, and kernel module conflicts |
| `claudeos-security` | Security daemon — file integrity, open port analysis, privilege escalation detection, AI threat scoring |

**All AI runs 100% locally via [Ollama](https://ollama.com). No data leaves your machine. No API keys. No subscriptions.**

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/claudeos
cd claudeos

# 2. Install (Debian/Ubuntu/Arch/Fedora)
bash install.sh

# 3. Start the AI shell
claude-shell

# 4. Try it
› ai drivers               # full hardware + driver health check
› ai security              # security audit with threat scoring
› ai explain /var/log/syslog  # explain any log file
› ai do list all open ports  # natural language → command
```

---

## Features

### AI Terminal (`claude-shell`)

The shell wraps your existing bash/zsh session and adds intelligence:

```bash
# When a command fails, AI explains and suggests the fix automatically
› systemctl start nginx
Failed to start nginx.service: Unit not found.
exit 1 → ask AI to explain? [y/N] y

● AI analyzing error (exit 1)…
  Cause: nginx is not installed on this system.
  Fix: sudo apt install nginx   # or: sudo dnf install nginx

# Natural language execution
› ai do find all .log files larger than 100MB modified in last 7 days
● Translating to command…
  find / -name "*.log" -size +100M -mtime -7 2>/dev/null

# Explain anything
› ai explain /etc/sudoers
› ai explain "what does 2>/dev/null mean"
› ai explain SIGSEGV

# Security audit
› ai security /etc
```

### Driver AI (`claudeos-drivers`)

```bash
# Full hardware scan with AI analysis
› ai drivers

● Scanning hardware and drivers…
  Hardware enumerated. Sending to AI…

  ClaudeOS Driver Health: NEEDS ATTENTION
  ─────────────────────────────────────────────────────────
  Summary: 1 device lacks a driver, 2 firmware files missing.
           RTL8822CE WiFi needs linux-firmware update.

  Issues:
    ⚠  No driver: Realtek RTL8822CE 802.11ac (0000:03:00.0)
    ⚠  Firmware missing: rtw88/rtw8822c_fw.bin
    ⚠  Firmware missing: rtw88/rtw8822c_bt_fw.bin

  Suggested fixes:
    $ sudo apt install linux-firmware firmware-realtek
    $ sudo modprobe rtw88_8822ce
    $ echo "rtw88_8822ce" | sudo tee /etc/modules-load.d/wifi.conf

# Scan specific device
› ai drivers "RTL8822"

# Find and install driver for a device
› ai install-driver "Realtek RTL8822CE WiFi"
```

Run as a background daemon that monitors driver health and alerts on issues:

```bash
systemctl --user enable --now claudeos-drivers
```

### Security Daemon (`claudeos-security`)

```bash
# One-time security audit
claudeos-security

# Build integrity baseline first
claudeos-security --baseline

# Run as continuous daemon (hourly scans)
systemctl --user enable --now claudeos-security
```

Output example:

```
══════════════════════════════════════════════════════════
  ClaudeOS Security Report — MEDIUM
══════════════════════════════════════════════════════════

  One SUID binary and weak SSH config detected.
  Failed login attempts suggest brute-force activity.

  [HIGH] SSH allows root login — significant attack surface
        Fix: sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

  [MEDIUM] Password authentication enabled on SSH
        Fix: Set PasswordAuthentication no in /etc/ssh/sshd_config

  [LOW] 47 failed login attempts from 198.51.100.4 in last 24h
        Fix: sudo ufw deny from 198.51.100.4 && sudo apt install fail2ban

  Hardening commands:
    $ sudo ufw enable && sudo ufw default deny incoming
    $ sudo apt install fail2ban unattended-upgrades
    $ sudo sysctl -w kernel.randomize_va_space=2

══════════════════════════════════════════════════════════
```

---

## Architecture

```
claudeos/
├── shell/
│   └── claude-shell.py      # AI terminal wrapper (Python, readline)
├── drivers/
│   └── driver-daemon.py     # Hardware scanner + AI driver analysis
├── daemon/
│   └── security-daemon.py   # File integrity + security AI
├── docs/
│   └── architecture.md      # Deep dive into design decisions
├── install.sh               # One-command installer
└── README.md
```

**AI layer:** All intelligence routes through [Ollama](https://ollama.com), a local LLM runtime. Supported models:

| Model | RAM required | Best for |
|-------|-------------|----------|
| `llama3` (default) | 8 GB | Balanced quality + speed |
| `mistral` | 4 GB | Low-memory systems |
| `phi3` | 4 GB | Fast, good for driver/security |
| `llama3:70b` | 48 GB | Maximum quality |

Change model: `export CLAUDEOS_MODEL=mistral`

**IPC:** Driver and security daemons write JSON reports to `~/.claudeos/`. The shell daemon communicates via Unix sockets. All inter-process data is local.

---

## Requirements

- Linux (tested: Ubuntu 22.04+, Arch, Fedora 38+, Debian 12+)
- Python 3.10+
- [Ollama](https://ollama.com) with any supported model pulled
- `lspci`, `lsusb`, `dmesg` (standard on most distros)
- systemd (for daemon mode, optional)

---

## Configuration

All config via environment variables — no config files needed:

```bash
# Set in ~/.bashrc or ~/.zshrc
export CLAUDEOS_MODEL=mistral          # LLM to use (default: llama3)
export CLAUDEOS_OLLAMA_URL=http://localhost:11434  # Ollama endpoint
export CLAUDEOS_SCAN_INTERVAL=300      # Driver scan interval in seconds
export CLAUDEOS_SEC_INTERVAL=3600      # Security scan interval in seconds
```

---

## Security & Privacy

- **Zero telemetry.** No analytics, no crash reports, no usage data.
- **Local AI only.** All inference runs on your hardware via Ollama.
- **No root required** for basic operation. Driver and security daemons run as your user.
- **Integrity baseline** hashes system binaries so you detect unauthorized changes.
- **AI never auto-executes** commands — it always shows them first and asks for confirmation.

---

## Roadmap

- [ ] GTK4 system tray integration with live driver/security status
- [ ] Wayland compositor patches (Hyprland fork with AI window manager)
- [ ] `dbus` API so any app can query the AI daemon
- [ ] Natural language package manager (`ai install a video editor`)
- [ ] Voice input support via `whisper.cpp`
- [ ] ARM64 / Raspberry Pi support
- [ ] Installable ISO (Arch-based)

---

## Contributing

Pull requests welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

Areas most needing help:
- **Rust rewrite** of `claude-shell` for better performance
- **Distro testing** — especially NixOS, openSUSE, Gentoo
- **Driver database** — mapping PCI IDs to known-good driver packages
- **GTK4 UI** for the system tray and notifications

---

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  Built with 💜 for the Linux community<br>
  AI runs locally. Always.
</p>
