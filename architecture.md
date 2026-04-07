# ClaudeOS — Architecture

## Overview

ClaudeOS is structured as **independent modules** that share a common AI backend (Ollama) and a JSON report format. Each module works standalone and can be installed separately.

```
┌─────────────────────────────────────────────────────────────────┐
│                        User interface                           │
│   claude-shell (terminal)   │   GTK4 tray (planned)            │
└──────────────┬──────────────┴───────────────────────────────────┘
               │ stdin/stdout / D-Bus (planned)
┌──────────────▼──────────────────────────────────────────────────┐
│                     AI Orchestration Layer                       │
│   ask_ai()  ─────────────────────────────────► Ollama HTTP API  │
│   (local Llama 3 / Mistral / Phi-3)                             │
└──────────────┬──────────────────────────────────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
┌───▼────────┐    ┌───────▼──────────┐
│  Driver    │    │  Security        │
│  Daemon    │    │  Daemon          │
│            │    │                  │
│  lspci     │    │  file integrity  │
│  lsusb     │    │  open ports      │
│  dmesg     │    │  SUID binaries   │
│  firmware  │    │  auth logs       │
└────────────┘    └──────────────────┘
       │                  │
       └────────┬─────────┘
                │ JSON reports
       ~/.claudeos/reports/
       ~/.claudeos/security/
```

## AI communication

Every AI call goes through `ask_ai()` in `claude-shell.py`:

```
User action
    │
    ▼
Build structured prompt
(command, error, hardware data, security data)
    │
    ▼
POST /api/generate → Ollama (localhost:11434)
    │
    ▼
Stream tokens back to terminal
    │
    ▼
Parse response (text or JSON depending on task)
```

For daemons that need structured output (driver health score, security threat level), the request uses `"format": "json"` and a system prompt that enforces a JSON schema. A rule-based fallback activates if Ollama is offline.

## Driver daemon design

```
HardwareScanner.scan()
    ├── lspci -nnkmm          # enumerate all PCI devices
    ├── per-device: lspci -ks # get driver and modules
    ├── dmesg --level=err     # kernel errors
    ├── firmware grep         # missing firmware files
    └── missing module grep

         │
         ▼
DriverAIAnalyzer.analyze(scan_data)
    ├── If Ollama available:
    │       POST structured prompt → JSON response
    │       Returns: health_score, issues[], fix_commands[]
    └── Else:
            Rule-based fallback (no-driver → suggest packages)
```

Reports saved to `~/.claudeos/reports/driver-report-YYYYMMDD-HHMMSS.json`.

## Security daemon design

The security model has two parts:

**Static analysis** — runs on demand:
- Open ports via `ss -tlnp`
- SUID/SGID binaries via `find -perm /4000`
- World-writable system files
- SSH config weakness detection
- Failed login analysis from auth.log / journald

**Integrity monitoring** — requires baseline:
1. `claudeos-security --baseline` hashes all files in `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` using SHA-256 and stores in `~/.claudeos/integrity.json`
2. Subsequent scans compare current hashes to baseline
3. Modified or deleted files are flagged and included in the AI analysis prompt

## Privacy model

| Data type | Where it goes |
|-----------|--------------|
| Shell commands | Sent to local Ollama only when error occurs AND user confirms |
| Hardware data | Sent to local Ollama during `ai drivers` scan |
| Security audit data | Sent to local Ollama during security scan |
| File contents (logs) | Sent to local Ollama when user runs `ai explain <file>` |
| Reports | Written to `~/.claudeos/` only |
| Anything external | **Never** |

## Future: D-Bus API

Planned interface for GUI integration:

```
org.claudeos.AI
  ├── Ask(string prompt) → string response
  ├── DriverHealth() → (string score, string[] issues)
  ├── SecurityStatus() → (string level, string[] findings)
  └── ExplainError(string cmd, string stderr) → string explanation

org.claudeos.Drivers
  ├── Scan() → DriverReport
  └── InstallDriver(string device) → string[] commands

org.claudeos.Security
  ├── Audit() → SecurityReport
  └── Baseline() → bool success
```
