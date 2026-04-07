#!/usr/bin/env bash
# ClaudeOS Installer
# Installs claude-shell, driver daemon, and security daemon.
# Supports: Debian/Ubuntu, Arch, Fedora/RHEL

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.local/bin"
SERVICE_DIR="$HOME/.config/systemd/user"
CONFIG_DIR="$HOME/.claudeos"

# ─── Colors ────────────────────────────────────────────────────────────────────
C_RESET="\033[0m"; C_PURPLE="\033[38;5;141m"; C_GREEN="\033[38;5;114m"
C_BLUE="\033[38;5;75m"; C_YELLOW="\033[38;5;221m"; C_RED="\033[38;5;203m"
p() { echo -e "${C_PURPLE}●${C_RESET} $*"; }
ok() { echo -e "${C_GREEN}✓${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}⚠${C_RESET} $*"; }
err() { echo -e "${C_RED}✗${C_RESET} $*"; }

# ─── Banner ────────────────────────────────────────────────────────────────────
echo -e """
${C_PURPLE}  ClaudeOS Installer${C_RESET}
  AI-native shell · driver diagnostics · security monitoring
  ─────────────────────────────────────────────────────────
"""

# ─── Detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
    if command -v apt &>/dev/null;   then echo "debian"
    elif command -v pacman &>/dev/null; then echo "arch"
    elif command -v dnf &>/dev/null; then echo "fedora"
    else echo "unknown"; fi
}
DISTRO=$(detect_distro)
p "Detected distro family: $DISTRO"

# ─── Python check ─────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    err "Python 3 required but not found."
    case $DISTRO in
        debian) echo "  Run: sudo apt install python3 python3-pip" ;;
        arch)   echo "  Run: sudo pacman -S python" ;;
        fedora) echo "  Run: sudo dnf install python3 python3-pip" ;;
    esac
    exit 1
fi
ok "Python $(python3 --version)"

# ─── pip dependencies ─────────────────────────────────────────────────────────
p "Installing Python dependencies..."
python3 -m pip install --user requests &>/dev/null && ok "requests installed"

# ─── Ollama check ─────────────────────────────────────────────────────────────
if ! command -v ollama &>/dev/null; then
    warn "Ollama not found — AI features require it."
    echo ""
    echo "  Install Ollama:"
    echo "    curl -fsSL https://ollama.com/install.sh | sh"
    echo "    ollama pull llama3"
    echo ""
    read -rp "  Install Ollama now? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        curl -fsSL https://ollama.com/install.sh | sh
        ok "Ollama installed"
        p "Pulling llama3 model (this may take a while)..."
        ollama pull llama3
    else
        warn "Skipping Ollama — AI features will be disabled until you install it"
    fi
else
    ok "Ollama $(ollama --version 2>/dev/null || echo 'found')"
fi

# ─── Create directories ────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR" "$SERVICE_DIR" "$CONFIG_DIR/reports" "$CONFIG_DIR/security"
ok "Created config dirs in $CONFIG_DIR"

# ─── Install binaries ─────────────────────────────────────────────────────────
p "Installing claude-shell..."
cp "$REPO_DIR/shell/claude-shell.py" "$INSTALL_DIR/claude-shell"
chmod +x "$INSTALL_DIR/claude-shell"
ok "claude-shell → $INSTALL_DIR/claude-shell"

cp "$REPO_DIR/drivers/driver-daemon.py" "$INSTALL_DIR/claudeos-drivers"
chmod +x "$INSTALL_DIR/claudeos-drivers"
ok "claudeos-drivers → $INSTALL_DIR/claudeos-drivers"

cp "$REPO_DIR/daemon/security-daemon.py" "$INSTALL_DIR/claudeos-security"
chmod +x "$INSTALL_DIR/claudeos-security"
ok "claudeos-security → $INSTALL_DIR/claudeos-security"

# ─── Systemd user services ────────────────────────────────────────────────────
p "Installing systemd user services..."

cat > "$SERVICE_DIR/claudeos-drivers.service" <<EOF
[Unit]
Description=ClaudeOS Driver AI Daemon
After=network.target ollama.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/claudeos-drivers --daemon
Restart=on-failure
RestartSec=30
Environment=CLAUDEOS_MODEL=llama3
Environment=CLAUDEOS_SCAN_INTERVAL=300

[Install]
WantedBy=default.target
EOF

cat > "$SERVICE_DIR/claudeos-security.service" <<EOF
[Unit]
Description=ClaudeOS Security AI Daemon
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/claudeos-security --daemon
Restart=on-failure
RestartSec=60
Environment=CLAUDEOS_MODEL=llama3
Environment=CLAUDEOS_SEC_INTERVAL=3600

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload 2>/dev/null && ok "Systemd services registered"

# ─── Shell aliases ────────────────────────────────────────────────────────────
SHELL_RC=""
[[ -f "$HOME/.zshrc" ]] && SHELL_RC="$HOME/.zshrc"
[[ -f "$HOME/.bashrc" ]] && SHELL_RC="$HOME/.bashrc"

if [[ -n "$SHELL_RC" ]]; then
    if ! grep -q "claudeos" "$SHELL_RC" 2>/dev/null; then
        cat >> "$SHELL_RC" <<'EOF'

# ─── ClaudeOS ─────────────────────────────────────────────────────────────────
export PATH="$HOME/.local/bin:$PATH"
alias csh="claude-shell"
alias aidrv="claudeos-drivers"
alias aisec="claudeos-security"
EOF
        ok "Shell aliases added to $SHELL_RC"
    fi
fi

# ─── PATH reminder ────────────────────────────────────────────────────────────
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# ─── Integrity baseline ────────────────────────────────────────────────────────
p "Building initial security baseline (this takes ~30s)..."
python3 "$REPO_DIR/daemon/security-daemon.py" --baseline 2>/dev/null && ok "Security baseline created" || warn "Baseline skipped (needs root for some paths)"

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${C_PURPLE}  ─────────────────────────────────────────────────────${C_RESET}"
echo -e "${C_GREEN}  ✓ ClaudeOS installed successfully!${C_RESET}"
echo ""
echo "  Commands:"
echo "    claude-shell          Start AI terminal"
echo "    ai drivers            Scan hardware & drivers"
echo "    ai security           Run security audit"
echo ""
echo "  Enable background daemons:"
echo "    systemctl --user enable --now claudeos-drivers"
echo "    systemctl --user enable --now claudeos-security"
echo ""
echo -e "${C_PURPLE}  ─────────────────────────────────────────────────────${C_RESET}"
echo ""
