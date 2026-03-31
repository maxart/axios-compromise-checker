#!/usr/bin/env bash
#
# Axios supply chain attack detection & response script
# Works on WSL (checks both Linux + Windows), standalone Linux, and macOS
#
# Usage:
#   ./respond.sh              # interactive - prompts before actions
#   ./respond.sh --scan-only  # report only, no changes
#   ./respond.sh --auto-clean # fix everything without prompting

set -euo pipefail

# --- Args ----------------------------------------------------------------

SCAN_ONLY=false
AUTO_CLEAN=false
for arg in "$@"; do
    case "$arg" in
        --scan-only)  SCAN_ONLY=true ;;
        --auto-clean) AUTO_CLEAN=true ;;
    esac
done

# --- Constants -----------------------------------------------------------

C2_DOMAIN="sfrclak.com"
C2_IP="142.11.206.73"
LINUX_PAYLOAD="/tmp/ld.py"
MAC_PAYLOAD="/Library/Caches/com.apple.act.mond"
WIN_PAYLOAD_REL="ProgramData/wt.exe"
MALICIOUS_PKG="plain-crypto-js"
BAD_VERSIONS=("1.14.1" "0.30.4")

FINDINGS=()
DANGER_COUNT=0  # tracks actual infection indicators vs low-severity warnings

# --- Platform detection --------------------------------------------------

IS_WSL=false
IS_MACOS=false
IS_LINUX=false
PLATFORM_LABEL="Linux"

if [[ "$(uname)" == "Darwin" ]]; then
    IS_MACOS=true
    PLATFORM_LABEL="macOS"
elif grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null; then
    IS_WSL=true
    PLATFORM_LABEL="WSL"
else
    IS_LINUX=true
    PLATFORM_LABEL="Linux"
fi

# --- Helpers -------------------------------------------------------------

banner()  { printf '\n\033[36m%s\n  %s\n%s\033[0m\n' "$(printf -- '-%.0s' {1..60})" "$1" "$(printf -- '-%.0s' {1..60})"; }
ok()      { printf '  \033[32m[OK]   \033[0m %s\n' "$1"; }
warn()    { printf '  \033[33m[WARN] \033[0m %s\n' "$1"; FINDINGS+=("$1"); }
danger()  { printf '  \033[31m[!!]   \033[0m %s\n' "$1"; FINDINGS+=("$1"); DANGER_COUNT=$((DANGER_COUNT + 1)); }

prompt_action() {
    $AUTO_CLEAN && return 0
    $SCAN_ONLY && return 1
    read -rp "  $1 (y/N) " reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

# Resolve Windows paths (only relevant on WSL)
WIN_ROOT=""
WIN_USER_MOUNT=""
if $IS_WSL; then
    for candidate in /mnt/c /mnt/d; do
        if [[ -d "$candidate/Windows" ]]; then
            WIN_ROOT="$candidate"
            break
        fi
    done

    if [[ -n "$WIN_ROOT" ]] && command -v powershell.exe &>/dev/null; then
        _win_profile=$(powershell.exe -NoProfile -Command 'Write-Host $env:USERPROFILE' 2>/dev/null | tr -d '\r' || true)
        if [[ -n "$_win_profile" ]]; then
            WIN_USER_MOUNT=$(wslpath -u "$_win_profile" 2>/dev/null || echo "")
        fi
    fi
fi

# --- 1. Linux payload ----------------------------------------------------

banner "Checking for Linux RAT payload"

if [[ -f "$LINUX_PAYLOAD" ]]; then
    danger "FOUND dropped payload: $LINUX_PAYLOAD"
    # Check if a python process is running it
    if pgrep -f "$LINUX_PAYLOAD" > /dev/null 2>&1; then
        danger "Payload is RUNNING"
        if prompt_action "Kill the process?"; then
            pkill -f "$LINUX_PAYLOAD" && ok "Process killed"
        fi
    fi
    if prompt_action "Delete $LINUX_PAYLOAD?"; then
        rm -f "$LINUX_PAYLOAD" && ok "Payload deleted"
    fi
else
    ok "No Linux payload at $LINUX_PAYLOAD"
fi

# --- 2. macOS payload -----------------------------------------------------

banner "Checking for macOS RAT payload"

if [[ -f "$MAC_PAYLOAD" ]]; then
    danger "FOUND dropped payload: $MAC_PAYLOAD"
    if pgrep -f "com.apple.act.mond" > /dev/null 2>&1; then
        danger "Payload is RUNNING"
        if prompt_action "Kill the process?"; then
            pkill -f "com.apple.act.mond" && ok "Process killed"
        fi
    fi
    if prompt_action "Delete $MAC_PAYLOAD?"; then
        rm -f "$MAC_PAYLOAD" && ok "Payload deleted"
    fi
elif [[ "$(uname)" == "Darwin" ]]; then
    ok "No macOS payload at $MAC_PAYLOAD"
else
    ok "Not macOS - skipping macOS payload check"
fi

# --- 3. Windows payload (WSL only) ---------------------------------------

if $IS_WSL; then
    banner "Checking for Windows RAT payload"

    if [[ -n "$WIN_ROOT" ]]; then
        WIN_PAYLOAD="$WIN_ROOT/$WIN_PAYLOAD_REL"
        if [[ -f "$WIN_PAYLOAD" ]]; then
            danger "FOUND dropped payload: $WIN_PAYLOAD"

            # Try to check if running on Windows side
            if command -v powershell.exe &>/dev/null; then
                running=$(powershell.exe -NoProfile -Command "Get-Process -Name wt -ErrorAction SilentlyContinue | Where-Object { \$_.Path -eq \"$( echo 'C:\ProgramData\wt.exe' )\" } | Select-Object -ExpandProperty Id" 2>/dev/null || true)
                if [[ -n "$running" ]]; then
                    danger "Payload is RUNNING on Windows (PID $running)"
                    if prompt_action "Kill the Windows process?"; then
                        powershell.exe -NoProfile -Command "Stop-Process -Id $running -Force" 2>/dev/null && ok "Windows process killed"
                    fi
                fi
            fi

            if prompt_action "Delete $WIN_PAYLOAD?"; then
                rm -f "$WIN_PAYLOAD" && ok "Payload deleted"
            fi
        else
            ok "No Windows payload at $WIN_PAYLOAD"
        fi

        # Windows temp dropper files (self-delete, but check anyway)
        if [[ -n "$WIN_USER_MOUNT" ]]; then
            WIN_TEMP=$(wslpath -u "$(powershell.exe -NoProfile -Command 'Write-Host $env:TEMP' 2>/dev/null | tr -d '\r')" 2>/dev/null || echo "")
            if [[ -n "$WIN_TEMP" && -d "$WIN_TEMP" ]]; then
                for dropper in "6202033.vbs" "6202033.ps1"; do
                    dropper_path="$WIN_TEMP/$dropper"
                    if [[ -f "$dropper_path" ]]; then
                        danger "FOUND dropper artifact: $dropper_path"
                        if prompt_action "Delete $dropper_path?"; then
                            rm -f "$dropper_path" && ok "Deleted $dropper"
                        fi
                    else
                        ok "No dropper at $dropper_path"
                    fi
                done
            fi
        fi
    else
        warn "Could not find Windows drive mount - skipping Windows payload check"
    fi
fi

# --- 4. Network indicators -----------------------------------------------

banner "Checking network indicators"

# Active connections (Linux side)
if ss -tnp 2>/dev/null | grep -q "$C2_IP"; then
    danger "Active Linux connection to C2 IP $C2_IP"
    ss -tnp 2>/dev/null | grep "$C2_IP"
else
    ok "No active Linux connections to C2 IP"
fi

# DNS resolution test (does the domain resolve in public DNS?)
if resolved_ip=$(dig +short "$C2_DOMAIN" 2>/dev/null | grep -E '^[0-9]+\.' | head -1) && [[ -n "$resolved_ip" ]]; then
    if [[ "$resolved_ip" == "0.0.0.0" || "$resolved_ip" == "127.0.0.1" ]]; then
        ok "C2 domain sinkholed in DNS (resolves to $resolved_ip)"
    else
        warn "C2 domain $C2_DOMAIN resolves to $resolved_ip in public DNS"
    fi
else
    ok "C2 domain does not resolve (dead or sinkholed)"
fi

# Windows side connections (WSL only)
if $IS_WSL && command -v powershell.exe &>/dev/null; then
    win_conn=$(powershell.exe -NoProfile -Command "Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { \$_.RemoteAddress -eq '$C2_IP' } | Select-Object -ExpandProperty RemotePort" 2>/dev/null || true)
    if [[ -n "$win_conn" ]]; then
        danger "Active Windows connection to C2 IP $C2_IP (ports: $win_conn)"
    else
        ok "No active Windows connections to C2 IP"
    fi
fi

# --- 5. Hosts file blocking -----------------------------------------------

banner "Checking hosts file blocks"

# Linux /etc/hosts
if grep -q "$C2_DOMAIN" /etc/hosts 2>/dev/null; then
    ok "C2 domain blocked in /etc/hosts"
else
    warn "C2 domain NOT blocked in /etc/hosts"
    if prompt_action "Add block to /etc/hosts? (requires sudo)"; then
        echo -e "\n# Axios supply chain attack C2 block\n0.0.0.0 $C2_DOMAIN" | sudo tee -a /etc/hosts > /dev/null
        ok "/etc/hosts updated"
    fi
fi

# Windows hosts file (WSL only)
if $IS_WSL && [[ -n "$WIN_ROOT" ]]; then
    WIN_HOSTS="$WIN_ROOT/Windows/System32/drivers/etc/hosts"
    if grep -q "$C2_DOMAIN" "$WIN_HOSTS" 2>/dev/null; then
        ok "C2 domain blocked in Windows hosts file"
    else
        warn "C2 domain NOT blocked in Windows hosts file"
        if prompt_action "Add block to Windows hosts file?"; then
            # Needs to go through powershell for write access
            if command -v powershell.exe &>/dev/null; then
                powershell.exe -NoProfile -Command "Add-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Value \"\`n# Axios supply chain attack C2 block\`n0.0.0.0 $C2_DOMAIN\"" 2>/dev/null && ok "Windows hosts file updated" || warn "Failed — run PowerShell as Administrator"
            else
                warn "powershell.exe not available — edit Windows hosts file manually"
            fi
        fi
    fi
fi

# --- 6. Scan for compromised packages ------------------------------------

banner "Scanning for compromised npm packages"

COMPROMISED_DIRS=()

scan_lockfile() {
    local lf="$1"
    local dir
    dir=$(dirname "$lf")
    local found=false

    if grep -q "$MALICIOUS_PKG" "$lf" 2>/dev/null; then
        danger "plain-crypto-js found in $lf"
        found=true
    fi

    for v in "${BAD_VERSIONS[@]}"; do
        if grep -qE "axios.*${v}" "$lf" 2>/dev/null; then
            danger "axios@$v found in $lf"
            found=true
        fi
    done

    if $found; then
        COMPROMISED_DIRS+=("$dir")
    fi
}

# Search from home directory with enough depth to find nested projects.
# Exclude node_modules and .cache to avoid false positives and slowness.
SEARCH_ROOT="$HOME"
LOCKFILE_COUNT=0

echo "  Scanning $SEARCH_ROOT (recursive) ..."
while IFS= read -r -d '' lockfile; do
    echo "    Checking $(dirname "$lockfile") ..."
    scan_lockfile "$lockfile"
    LOCKFILE_COUNT=$((LOCKFILE_COUNT + 1))
done < <(find "$SEARCH_ROOT" -maxdepth 8 \
    \( -name "node_modules" -o -name ".cache" -o -name ".nvm" -o -name ".npm" \) -prune \
    -o \( -name "package-lock.json" -o -name "pnpm-lock.yaml" -o -name "yarn.lock" \) -print0 \
    2>/dev/null)

echo "  Scanned $LOCKFILE_COUNT lockfile(s) under $SEARCH_ROOT"

# Also check Windows-side projects (WSL only)
if $IS_WSL && [[ -n "$WIN_USER_MOUNT" && -d "$WIN_USER_MOUNT" ]]; then
    WIN_LOCKFILE_COUNT=0
    echo "  Scanning (Windows) $WIN_USER_MOUNT (recursive) ..."
    while IFS= read -r -d '' lockfile; do
        echo "    Checking $(dirname "$lockfile") ..."
        scan_lockfile "$lockfile"
        WIN_LOCKFILE_COUNT=$((WIN_LOCKFILE_COUNT + 1))
    done < <(find "$WIN_USER_MOUNT" -maxdepth 8 \
        \( -name "node_modules" -o -name ".cache" -o -name "AppData" \) -prune \
        -o \( -name "package-lock.json" -o -name "pnpm-lock.yaml" -o -name "yarn.lock" \) -print0 \
        2>/dev/null)
    echo "  Scanned $WIN_LOCKFILE_COUNT lockfile(s) under $WIN_USER_MOUNT"
fi

if [[ ${#COMPROMISED_DIRS[@]} -eq 0 ]]; then
    ok "No compromised axios versions found"
fi

# --- 7. Clean compromised projects ---------------------------------------

if [[ ${#COMPROMISED_DIRS[@]} -gt 0 ]] && ! $SCAN_ONLY; then
    banner "Cleaning compromised projects"

    # Deduplicate
    COMPROMISED_DIRS=($(printf '%s\n' "${COMPROMISED_DIRS[@]}" | sort -u))

    for dir in "${COMPROMISED_DIRS[@]}"; do
        echo ""
        echo "  Project: $dir"

        if prompt_action "Clean this project? (rm node_modules, reinstall with --ignore-scripts)"; then
            # Remove phantom dependency
            pcj="$dir/node_modules/$MALICIOUS_PKG"
            if [[ -d "$pcj" ]]; then
                rm -rf "$pcj"
                ok "Removed $MALICIOUS_PKG"
            fi

            rm -rf "$dir/node_modules"
            ok "Removed node_modules"

            (cd "$dir" && npm install axios@1.14.0 --save 2>/dev/null && npm ci --ignore-scripts 2>/dev/null)
            ok "Reinstalled with --ignore-scripts"
        fi
    done
fi

# --- 8. npmrc hardening ---------------------------------------------------

banner "Checking npmrc hardening"

harden_npmrc() {
    local rc="$1"
    local label="$2"
    local needs_write=false
    local additions=""

    if [[ -f "$rc" ]]; then
        if ! grep -q "ignore-scripts=true" "$rc" 2>/dev/null; then
            warn "$label: ignore-scripts is not set"
            additions+="ignore-scripts=true\n"
            needs_write=true
        else
            ok "$label: ignore-scripts=true is set"
        fi
        if ! grep -q "min-release-age" "$rc" 2>/dev/null; then
            warn "$label: min-release-age is not set"
            additions+="min-release-age=7\n"
            needs_write=true
        else
            ok "$label: min-release-age is set"
        fi
    else
        warn "$label: .npmrc does not exist"
        additions="ignore-scripts=true\nmin-release-age=7\n"
        needs_write=true
    fi

    if $needs_write && prompt_action "Harden $label .npmrc?"; then
        printf "\n# Axios incident hardening (%s)\n%b" "$(date +%Y-%m-%d)" "$additions" >> "$rc"
        ok "$label .npmrc updated"
    fi
}

harden_npmrc "$HOME/.npmrc" "$PLATFORM_LABEL"

# Windows-side npmrc (WSL only)
if $IS_WSL && [[ -n "$WIN_ROOT" && -n "${WIN_USER_MOUNT:-}" ]]; then
    harden_npmrc "$WIN_USER_MOUNT/.npmrc" "Windows"
fi

# --- 9. Summary -----------------------------------------------------------

banner "Summary"

if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    echo ""
    ok "No indicators of compromise found."
    ok "Your environment appears clean."
else
    echo ""
    echo "  ${#FINDINGS[@]} finding(s):"
    echo ""
    for i in "${!FINDINGS[@]}"; do
        echo "  $((i+1)). ${FINDINGS[$i]}"
    done

    if [[ $DANGER_COUNT -gt 0 ]]; then
        # Actual infection indicators found - show full credential rotation warning
        echo ""
        danger "ACTION REQUIRED: Rotate all credentials accessible from this machine"
        echo ""
        echo "  Rotate these immediately:"
        echo "    - npm tokens          (npm token revoke / regenerate)"
        echo "    - SSH keys            (regenerate, remove old pubkeys from GitHub/servers)"
        echo "    - Cloud credentials   (AWS, GCP, Azure)"
        echo "    - CI/CD secrets       (GitHub Actions, GitLab CI, etc.)"
        echo "    - Database passwords"
        echo "    - API keys / service tokens"
        echo "    - Browser-stored passwords (if RAT persisted)"
        if $IS_WSL; then
            echo ""
            echo "  If wt.exe was found and running, consider a full OS reinstall."
        fi
    else
        # Only low-severity warnings (hardening suggestions, not infection)
        echo ""
        ok "No signs of active infection found."
        echo "  The warnings above are hardening recommendations, not indicators of compromise."
    fi
fi

echo ""
