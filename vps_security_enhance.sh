#!/bin/bash
# ════════════════════════════════════════════════════════════
#  secure-vps — VPS Security Enhancement Scripts
#  Supported OS: Ubuntu / Debian / CentOS / AlmaLinux / Rocky
#  Run as: root
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts (MIT)
# ════════════════════════════════════════════════════════════

# ── [base] Colors and global identifiers ────────────────────────────────────
C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'
APP_VER="v2.0.0"
UPSTREAM_URL="https://raw.githubusercontent.com/0x10debug/vps-security-enhancement-scripts/main/vps_security_enhance.sh"

# ── [base] Environment detection ──────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${C_FAIL}Insufficient privileges: please run as root.${C_RST}"
    exit 1
fi

# /usr/sbin Add admin tools under /usr/sbin to search path
command -v sshd >/dev/null 2>&1 || PATH="$PATH:/usr/sbin:/usr/local/sbin"

DISTRO=""
DISTRO_VER=""
DISTRO_MAJOR=""
PKG_UPGRADE=""
PKG_INSTALL=""
FW_KIND=""

if [ -f /etc/os-release ]; then
# shellcheck disable=SC1091 # system file sourced by design
    . /etc/os-release
    DISTRO=$ID
    DISTRO_VER=$VERSION_ID
    DISTRO_MAJOR=$(echo "$VERSION_ID" | cut -d. -f1)
else
    echo -e "${C_FAIL}Cannot identify OS (missing /etc/os-release).${C_RST}"
    exit 1
fi

case $DISTRO in
    ubuntu|debian)
        PKG_UPGRADE="apt-get update -y && apt-get upgrade -y"
        PKG_INSTALL="apt-get install -y"
        FW_KIND="ufw"
        ;;
    centos|rhel|almalinux|rocky)
        PKG_UPGRADE="yum update -y"
        PKG_INSTALL="yum install -y"
        FW_KIND="firewalld"
        ;;
    *)
        echo -e "${C_FAIL}Unsupported distribution (supports Ubuntu/Debian/CentOS/AlmaLinux/Rocky).${C_RST}"
        exit 1
        ;;
esac

# ── [util] Interactive helpers ──────────────────────────────────────────
wait_key() {
    echo ""
    read -n 1 -s -r -p "Press any key to return..."
}

ask_yes() {
    local prompt=$1 def=${2:-N} ans
    if [ "$def" = "Y" ]; then
        read -r -p "$prompt (Y/n): " ans
        [ -z "$ans" ] && return 0
    else
        read -r -p "$prompt (y/N): " ans
    fi
    [[ "$ans" =~ ^[Yy]$ ]]
}

# Take snapshot before modification, timestamp suffix avoids overwriting earlier snapshots
snapshot_file() {
    local f=$1
    if [ -f "$f" ]; then
        cp "$f" "${f}.orig-$(date +%Y%m%d%H%M%S)"
    fi
}

# ── [ssh] Config write and safe reload ─────────────────────────────────
# Read sshd effective port (sshd -T first, compatible with Include-expanded real values)
ssh_port_live() {
    local p
    p=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')
    [ -z "$p" ] && p=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
    [ -z "$p" ] && p=22
    echo "$p"
}

ssh_opt_write() {
    local key=$1 val=$2
    # Remove old same-key lines (including commented ones), then append the single effective line
    sed -i "/^#*$key /d" /etc/ssh/sshd_config
    echo "$key $val" >> /etc/ssh/sshd_config
}

# New directives unsupported by old sshd are only written when probe passes
ssh_opt_write_safe() {
    local key=$1 val=$2
    if sshd -o "${key}=${val}" -T >/dev/null 2>&1; then
        ssh_opt_write "$key" "$val"
        return 0
    fi
    return 1
}

# Restart only if validation passes; auto-rollback to latest snapshot on failure
ssh_apply_and_reload() {
    if sshd -t 2>/dev/null; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh
        return 0
    fi
    echo -e "${C_FAIL}sshd config validation failed, auto-rolling back to latest snapshot...${C_RST}"
    ssh_config_rewind "auto"
    return 1
}

ssh_config_rewind() {
    local mode=$1 latest
    latest=""
    local orig_f
    for orig_f in /etc/ssh/sshd_config.orig-*; do [ -e "$orig_f" ] && latest=$orig_f; done
    if [ -z "$latest" ]; then
        echo -e "${C_FAIL}No available config snapshot, cannot rollback.${C_RST}"
        return 1
    fi
    [ "$mode" != "auto" ] && echo -e "${C_WARN}Snapshot in use: $latest${C_RST}"
    cp "$latest" /etc/ssh/sshd_config
    if sshd -t 2>/dev/null; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh
        # Port may change after rollback, sync Fail2Ban ban port to avoid mismatch
        if [ -f /etc/fail2ban/jail.local ] && command -v fail2ban-client >/dev/null 2>&1; then
            local back_port
            back_port=$(ssh_port_live)
            sed -i -E "/^\[sshd\]/,/^\[/ s/^port[[:space:]]*=.*/port = $back_port/" /etc/fail2ban/jail.local
            systemctl restart fail2ban 2>/dev/null
        fi
        echo -e "${C_OK}Snapshot restored and sshd restarted.${C_RST}"
        return 0
    fi
    echo -e "${C_FAIL}Snapshot content also failed validation, please manually check /etc/ssh/sshd_config${C_RST}"
    return 1
}

# ── [ui] Percentage gauge ──────────────────────────────────────────────
gauge() {
    local name=$1 pct=$2 tone i
    if   [ "$pct" -lt 50 ]; then tone=$C_OK
    elif [ "$pct" -lt 80 ]; then tone=$C_WARN
    else tone=$C_FAIL; fi
    local width=20
    local fill=$(( pct * width / 100 ))
    local blank=$(( width - fill ))
    printf "  %-10s ${C_INFO}│" "$name"
    for ((i=0; i<fill; i++)); do printf "%s▮%s" "${tone}" "${C_RST}"; done
    for ((i=0; i<blank; i++)); do printf "▯"; done
    printf "${C_INFO}│${tone} %s%%${C_RST}\n" "$pct"
}

# ── [fw] Port grant wrapper for modules ────────────────────────────────
fw_grant_tcp() {
    local port=$1
    if [ "$FW_KIND" = "ufw" ]; then
        ufw allow "${port}/tcp"
    else
        firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
}

# ── [self] Global command alias ──────────────────────────────────────
secure_vps_alias_on() {
    if [ -L /usr/local/bin/secure-vps ] || [ -f /usr/local/bin/secure-vps ]; then
        echo -e "${C_WARN}Existing secure-vps command detected, rebuilding symlink...${C_RST}"
        rm -f /usr/local/bin/secure-vps
    fi
    echo -e "${C_INFO}Installing global command secure-vps (symlink method)...${C_RST}"
    ln -sf "$(readlink -f "$0")" /usr/local/bin/secure-vps
    chmod +x /usr/local/bin/secure-vps
    if [ -x /usr/local/bin/secure-vps ]; then
        echo -e "${C_OK}Done. Type secure-vps from any directory to launch this tool.${C_RST}"
        echo -e "${C_WARN}Note: Symlink follows source file, command auto-syncs after script update.${C_RST}"
    else
        echo -e "${C_FAIL}Failed to write to /usr/local/bin, please check permissions.${C_RST}"
    fi
    wait_key
}

secure_vps_alias_off() {
    if [ ! -e /usr/local/bin/secure-vps ]; then
        echo -e "${C_WARN}secure-vps global command not found.${C_RST}"
        wait_key; return
    fi
    if ask_yes "Confirm removing global command secure-vps?"; then
        rm -f /usr/local/bin/secure-vps
        echo -e "${C_OK}Removed. Script body remains in current directory.${C_RST}"
    fi
    wait_key
}

# ── [self] Self-update (validate before overwrite, never let a bad file replace itself) ───────
secure_vps_self_update() {
    echo -e "${C_INFO}Querying upstream version...${C_RST}"
    local tmp remote_ver
    tmp=$(mktemp /tmp/secure-vps.XXXXXX)
    if ! curl -fsSL --max-time 30 "$UPSTREAM_URL" -o "$tmp" 2>/dev/null; then
        echo -e "${C_FAIL}Failed to connect to GitHub or download error, aborting update.${C_RST}"
        rm -f "$tmp"; wait_key; return
    fi
    remote_ver=$(grep -m1 'APP_VER=' "$tmp" | cut -d '"' -f 2)
    if [ -z "$remote_ver" ]; then
        echo -e "${C_FAIL}Downloaded content missing version identifier, aborting update.${C_RST}"
        rm -f "$tmp"; wait_key; return
    fi
    if [ "$APP_VER" = "$remote_ver" ]; then
        echo -e "${C_OK}Already up to date ($APP_VER).${C_RST}"
        rm -f "$tmp"; wait_key; return
    fi
    echo -e "${C_WARN}New version found: $remote_ver (current $APP_VER)${C_RST}"
    if ask_yes "Upgrade now?"; then
        if ! bash -n "$tmp"; then
            echo -e "${C_FAIL}Downloaded script failed syntax validation, aborting overwrite.${C_RST}"
            rm -f "$tmp"; wait_key; return
        fi
        local self
        self=$(readlink -f "$0")
        if cp "$tmp" "$self" && chmod +x "$self"; then
            rm -f "$tmp"
            echo -e "${C_OK}Upgrade complete, restarting tool...${C_RST}"
            sleep 2
            exec bash "$0"
        fi
        echo -e "${C_FAIL}Failed to overwrite script, please check disk and permissions.${C_RST}"
        rm -f "$tmp"
    else
        rm -f "$tmp"
    fi
    wait_key
}

# ════════════════════════════════════════════════════════════
#  Module: SSH and Login
# ════════════════════════════════════════════════════════════

pkg_upgrade_all() {
    echo -e "${C_INFO}Upgrading system packages, this may take a while...${C_RST}"
# shellcheck disable=SC2086 # intentionally unquoted: PKG_UPGRADE is a composite command executed by eval
    eval $PKG_UPGRADE
    echo -e "${C_OK}System package upgrade complete.${C_RST}"
    wait_key
}

ssh_port_shift() {
    local new_port
    read -r -p "Enter new SSH port (recommended 20000-60000): " new_port
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${C_FAIL}Port must be a number between 1-65535.${C_RST}"
        wait_key; return
    fi
    if [ "$new_port" = "$(ssh_port_live)" ]; then
        echo -e "${C_WARN}Same as current port, no change needed.${C_RST}"
        wait_key; return
    fi
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${new_port}$"; then
        echo -e "${C_FAIL}Port $new_port is already in use, please choose another.${C_RST}"
        wait_key; return
    fi

    echo -e "${C_INFO}Preparing to switch SSH port...${C_RST}"

    # Allow new port before modifying config to avoid self-lockout
    if [ "$FW_KIND" = "ufw" ]; then
        eval "$PKG_INSTALL ufw > /dev/null 2>&1"
        ufw allow "$new_port/tcp"
    else
        eval "$PKG_INSTALL firewalld > /dev/null 2>&1"
        systemctl start firewalld
        firewall-cmd --permanent --add-port="$new_port/tcp"
        firewall-cmd --reload
    fi

    # When SELinux is Enforcing, must register ssh_port_t or sshd cannot listen on new port
    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
        if ! command -v semanage >/dev/null 2>&1; then
            echo -e "${C_INFO}SELinux Enforcing detected, installing semanage...${C_RST}"
            eval "$PKG_INSTALL policycoreutils-python-utils >/dev/null 2>&1" || \
            eval "$PKG_INSTALL policycoreutils-python >/dev/null 2>&1"
        fi
        if command -v semanage >/dev/null 2>&1; then
            semanage port -a -t ssh_port_t -p tcp "$new_port" 2>/dev/null || \
            semanage port -m -t ssh_port_t -p tcp "$new_port" 2>/dev/null
            echo -e "${C_OK}Port $new_port registered with SELinux.${C_RST}"
        else
            echo -e "${C_WARN}SELinux enabled but semanage unavailable, manual intervention needed if restart fails.${C_RST}"
        fi
    fi

    snapshot_file /etc/ssh/sshd_config
    ssh_opt_write "Port" "$new_port"

    if ssh_apply_and_reload; then
        # Verify sshd is actually listening
        sleep 2
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${new_port}$"; then
            echo -e "${C_OK}Confirmed sshd listening on new port $new_port.${C_RST}"
        else
            echo -e "${C_FAIL}No listener detected on $new_port, keep current session open and troubleshoot via old port!${C_RST}"
        fi
        # Fail2Ban ban port must follow, otherwise all ban actions miss
        if [ -f /etc/fail2ban/jail.local ] && command -v fail2ban-client >/dev/null 2>&1; then
            sed -i -E "/^\[sshd\]/,/^\[/ s/^port[[:space:]]*=.*/port = $new_port/" /etc/fail2ban/jail.local
            systemctl restart fail2ban 2>/dev/null
            echo -e "${C_OK}Fail2Ban ban port synced to $new_port.${C_RST}"
        fi
        echo -e "${C_OK}SSH port switched to $new_port.${C_RST}"
        echo -e "${C_WARN}Do NOT close this session, open a new terminal to verify connectivity before finishing!${C_RST}"
        echo -e "${C_WARN}Note: Old port allow rules are temporarily kept, remove them after verification.${C_RST}"
        echo -e "${C_WARN}Note: Cloud provider security groups must also allow $new_port.${C_RST}"
    fi
    wait_key
}

ssh_keys_from_github() {
    local gh_user keys
    read -r -p "Enter GitHub username: " gh_user
    if [ -z "$gh_user" ]; then
        echo -e "${C_FAIL}Username cannot be empty.${C_RST}"; wait_key; return
    fi
    echo -e "${C_INFO}Fetching public keys for $gh_user...${C_RST}"
    keys=$(curl -sL --max-time 20 "https://github.com/${gh_user}.keys")
    if [[ "$keys" == "Not Found" ]] || [[ -z "$keys" ]] || [[ "$keys" == *"<h1>"* ]]; then
        echo -e "${C_FAIL}No public keys retrieved, please verify username and GitHub key settings.${C_RST}"
        wait_key; return
    fi
    mkdir -p ~/.ssh && chmod 700 ~/.ssh
    echo "$keys" >> ~/.ssh/authorized_keys
    sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    echo -e "${C_OK}Public key import complete.${C_RST}"

    read -r -p "Disable password login and keep key-only now? (y/N, recommend verifying key access in a new terminal first): " shut_pw
    if [[ "$shut_pw" =~ ^[Yy]$ ]]; then
        snapshot_file /etc/ssh/sshd_config
        ssh_opt_write "PasswordAuthentication" "no"
        ssh_opt_write "PubkeyAuthentication" "yes"
        ssh_opt_write_safe "KbdInteractiveAuthentication" "no"
        ssh_opt_write_safe "ChallengeResponseAuthentication" "no"
        if ssh_apply_and_reload; then
            echo -e "${C_OK}Password login disabled.${C_RST}"
            echo -e "${C_WARN}Please open a new terminal to confirm key login works before closing this window!${C_RST}"
        fi
    else
        echo -e "${C_INFO}Password login policy unchanged.${C_RST}"
    fi
    wait_key
}

ssh_baseline_pack() {
    echo -e "${C_INFO}The following baseline parameters will be applied:${C_RST}"
    echo "  · MaxAuthTries 3           Max 3 auth attempts per connection"
    echo "  · LoginGraceTime 30        Disconnect if login not complete in 30 seconds"
    echo "  · ClientAliveInterval 120  Probe client every 2 minutes"
    echo "  · ClientAliveCountMax 3    Disconnect after 3 consecutive no-responses"
    echo "  · X11Forwarding no         Disable X11 forwarding"
    echo "  · UseDNS no                Skip reverse DNS, speed up handshake"
    echo "  · PermitEmptyPasswords no  Reject empty passwords"
    echo "  · StrictModes yes          Verify key file ownership and permissions"
    echo "  · GSSAPIAuthentication no  Disable GSSAPI"
    if ! ask_yes "Confirm apply?"; then wait_key; return; fi

    snapshot_file /etc/ssh/sshd_config
    ssh_opt_write "MaxAuthTries" "3"
    ssh_opt_write "LoginGraceTime" "30"
    ssh_opt_write "ClientAliveInterval" "120"
    ssh_opt_write "ClientAliveCountMax" "3"
    ssh_opt_write "X11Forwarding" "no"
    ssh_opt_write_safe "UseDNS" "no"
    ssh_opt_write "PermitEmptyPasswords" "no"
    ssh_opt_write "StrictModes" "yes"
    ssh_opt_write_safe "GSSAPIAuthentication" "no"

    if ssh_apply_and_reload; then
        echo -e "${C_OK}SSH baseline parameters applied.${C_RST}"
        echo -e "${C_WARN}Note: ClientAlive only affects server-side session keepalive, does not impact tunnel services.${C_RST}"
    fi
    wait_key
}

ssh_lock_root_passwd() {
    echo -e "${C_INFO}Setting PermitRootLogin prohibit-password:${C_RST}"
    echo -e "${C_INFO}root can still use key login, only loses password login capability, balancing security and usability.${C_RST}"
    if [ ! -s /root/.ssh/authorized_keys ]; then
        echo -e "${C_FAIL}Warning: root has no public keys!${C_RST}"
        echo -e "${C_FAIL}Disabling password login now means losing root access, recommend importing public keys first.${C_RST}"
        if ! ask_yes "Continue anyway?"; then wait_key; return; fi
    fi
    snapshot_file /etc/ssh/sshd_config
    ssh_opt_write "PermitRootLogin" "prohibit-password"
    if ssh_apply_and_reload; then
        echo -e "${C_OK}root password login disabled (keys unaffected).${C_RST}"
        echo -e "${C_WARN}Please open a new terminal to verify key access before closing this window!${C_RST}"
    fi
    wait_key
}

ssh_gate_users() {
    echo -e "${C_WARN}>>> SSH login whitelist (AllowUsers) <<<${C_RST}"
    local current input u bad
    current=$(sshd -T 2>/dev/null | awk '/^allowusers /{$1=""; print}' | sed 's/^ //')
    if [ -n "$current" ]; then
        echo -e "${C_INFO}Current whitelist: $current${C_RST}"
    else
        echo -e "${C_INFO}No whitelist set (all valid users can attempt login).${C_RST}"
    fi
    read -r -p "Enter allowed users (space-separated, Enter=clear whitelist): " input

    snapshot_file /etc/ssh/sshd_config
    if [ -z "$input" ]; then
        sed -i '/^AllowUsers /d' /etc/ssh/sshd_config
        if ssh_apply_and_reload; then
            echo -e "${C_OK}Whitelist cleared, default policy restored.${C_RST}"
        fi
        wait_key; return
    fi

    # Verify users exist first, cancel on typo to prevent total lockout
    bad=""
    for u in $input; do
        id "$u" >/dev/null 2>&1 || bad="$bad $u"
    done
    if [ -n "$bad" ]; then
        echo -e "${C_FAIL}The following users do not exist:${bad} , Cancelled (to prevent accidental lockout).${C_RST}"
        wait_key; return
    fi

    sed -i '/^AllowUsers /d' /etc/ssh/sshd_config
    echo "AllowUsers $input" >> /etc/ssh/sshd_config
    if ssh_apply_and_reload; then
        echo -e "${C_OK}Whitelist active: only $input can login.${C_RST}"
        echo -e "${C_WARN}Please open a new terminal to verify target user can login before closing this window!${C_RST}"
    fi
    wait_key
}

# ════════════════════════════════════════════════════════════
#  Module: Firewall
# ════════════════════════════════════════════════════════════

fw_init() {
    echo -e "${C_INFO}Deploying firewall and allowing basic ports (SSH/80/443)...${C_RST}"
    local p; p=$(ssh_port_live)
    if [ "$FW_KIND" = "ufw" ]; then
        eval "$PKG_INSTALL ufw"
        ufw allow "$p/tcp"
        ufw allow 80/tcp
        ufw allow 443/tcp
        echo "y" | ufw enable
    else
        eval "$PKG_INSTALL firewalld"
        systemctl enable firewalld
        systemctl start firewalld
        firewall-cmd --permanent --add-port="$p/tcp"
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
    fi
    echo -e "${C_OK}Firewall deployed.${C_RST}"
    wait_key
}

fw_report() {
    echo -e "${C_WARN}>>> Firewall current status and rules <<<${C_RST}"
    if [ "$FW_KIND" = "ufw" ]; then
        ufw status verbose
    else
        firewall-cmd --list-all
    fi
    wait_key
}

fw_open() {
    local port
    read -r -p "Enter port to allow (e.g. 8888 or 8888/tcp): " port
    [ -z "$port" ] && return
    [[ "$port" != *"/"* ]] && port="$port/tcp"
    echo -e "${C_INFO}Allowing $port ...${C_RST}"
    if [ "$FW_KIND" = "ufw" ]; then
        ufw allow "$port"
    else
        firewall-cmd --permanent --add-port="$port"
        firewall-cmd --reload
    fi
    echo -e "${C_OK}$port allowed.${C_RST}"
    wait_key
}

fw_reload() {
    if [ "$FW_KIND" = "ufw" ]; then ufw reload; else firewall-cmd --reload; fi
    echo -e "${C_OK}Rules reloaded.${C_RST}"
    wait_key
}

# ════════════════════════════════════════════════════════════
#  Module: Fail2Ban
# ════════════════════════════════════════════════════════════

f2b_deploy() {
    echo -e "${C_INFO}Deploying Fail2Ban for brute-force protection...${C_RST}"
    # RHEL family requires EPEL repository first
    if [[ "$DISTRO" =~ ^(centos|rhel|almalinux|rocky)$ ]]; then
        eval "$PKG_INSTALL epel-release > /dev/null 2>&1"
    fi
    # Debian/Ubuntu systemd journal backend dependency
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        eval "$PKG_INSTALL python3-systemd > /dev/null 2>&1"
    fi
    if ! eval "$PKG_INSTALL fail2ban"; then
        echo -e "${C_FAIL}Installation failed, please check package repositories.${C_RST}"
        wait_key; return
    fi

    local p; p=$(ssh_port_live)

    # Ubuntu minimal systems lack rsyslog/auth.log, Debian/Ubuntu explicitly use systemd backend
    # (CentOS 7 old fail2ban does not support this backend, defaults to /var/log/secure)
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = $p
backend = systemd
EOF
    else
        cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = $p
EOF
    fi

    systemctl enable fail2ban
    systemctl restart fail2ban
    sleep 2
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        echo -e "${C_OK}Fail2Ban ready: 5 failed attempts bans for 24 hours.${C_RST}"
    else
        echo -e "${C_FAIL}Fail2Ban startup error, recent logs:${C_RST}"
        journalctl -u fail2ban --no-pager -n 5 2>/dev/null
        echo -e "${C_WARN}Use 'fail2ban-client -d' for further troubleshooting.${C_RST}"
    fi
    wait_key
}

f2b_report() {
    echo -e "${C_WARN}>>> Fail2Ban running status <<<${C_RST}"
    systemctl status fail2ban --no-pager | grep Active
    echo ""
    echo -e "${C_WARN}>>> SSH jail current ban list <<<${C_RST}"
    fail2ban-client status sshd 2>/dev/null || echo -e "${C_FAIL}Cannot get status, may not be deployed yet.${C_RST}"
    wait_key
}

f2b_log_tail() {
    echo -e "${C_WARN}>>> Recent interception logs <<<${C_RST}"
    tail -n 15 /var/log/fail2ban.log 2>/dev/null || echo "No log file, may not be deployed yet."
    wait_key
}

# ════════════════════════════════════════════════════════════
#  Module: Performance (BBR / Swap)
# ════════════════════════════════════════════════════════════

net_bbr_enable() {
    echo -e "${C_INFO}Checking BBR...${C_RST}"
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        echo -e "${C_OK}BBR already running, no reconfiguration needed.${C_RST}"
        wait_key; return
    fi
    # BBR requires kernel 4.9+
    if ! uname -r | awk -F. '{exit !($1>4 || ($1==4 && $2>=9))}'; then
        echo -e "${C_FAIL}Kernel $(uname -r) too old (requires 4.9+).${C_RST}"
        echo -e "${C_WARN}CentOS 7 defaults to 3.10, please install ELRepo new kernel first.${C_RST}"
        wait_key; return
    fi
    modprobe tcp_bbr 2>/dev/null
    if ! grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        echo -e "${C_FAIL}Kernel failed to load BBR module, aborting configuration.${C_RST}"
        wait_key; return
    fi
    # Standalone config file to avoid polluting main sysctl.conf
    cat > /etc/sysctl.d/99-secure-vps-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl -p /etc/sysctl.d/99-secure-vps-bbr.conf >/dev/null 2>&1
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        echo -e "${C_OK}BBR enabled.${C_RST}"
    else
        echo -e "${C_FAIL}Parameters written but not effective, please check kernel module status.${C_RST}"
    fi
    wait_key
}

mem_swap_build() {
    if swapon --show 2>/dev/null | grep -q "/"; then
        echo -e "${C_WARN}System already has Swap, skipping. Current status:${C_RST}"
        swapon --show
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Create Swap (prevent sudden memory exhaustion) <<<${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} 512 MB"
    echo -e "  ${C_WARN}2.${C_RST} 1 GB ${C_OK}(recommended)${C_RST}"
    echo -e "  ${C_WARN}3.${C_RST} 2 GB"
    echo -e "  ${C_WARN}4.${C_RST} 4 GB"
    echo -e "  ${C_WARN}5.${C_RST} Custom (MB)"
    local choice mb
    read -r -p "❯ Select size [2]: " choice
    choice=${choice:-2}
    case $choice in
        1) mb=512 ;;
        2) mb=1024 ;;
        3) mb=2048 ;;
        4) mb=4096 ;;
        5)
            read -r -p "Enter size (MB): " mb
            if ! [[ "$mb" =~ ^[0-9]+$ ]] || [ "$mb" -lt 128 ] || [ "$mb" -gt 32768 ]; then
                echo -e "${C_FAIL}Size must be between 128-32768 MB.${C_RST}"
                wait_key; return
            fi
            ;;
        *) echo -e "${C_FAIL}Invalid choice.${C_RST}"; wait_key; return ;;
    esac

    # Disk space check: reserve 30% margin
    local avail_kb need_kb
    avail_kb=$(df / | awk 'NR==2{print $4}')
    need_kb=$(( mb * 1024 ))
    if [ "$avail_kb" -lt $(( need_kb * 13 / 10 )) ]; then
        echo -e "${C_FAIL}Insufficient disk space (needs ${mb}MB), please clean up first.${C_RST}"
        wait_key; return
    fi

    echo -e "${C_INFO}Creating ${mb}MB swap file...${C_RST}"
    fallocate -l "${mb}M" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count="$mb" status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    if ! swapon /swapfile; then
        echo -e "${C_FAIL}swapon failed (some virtualization platforms don't support file swap), cleaned up temporary file.${C_RST}"
        rm -f /swapfile
        wait_key; return
    fi
    grep -q "^/swapfile" /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    # Reduce swap tendency, prioritize physical RAM
    printf 'vm.swappiness = 10\n' > /etc/sysctl.d/99-secure-vps-swap.conf
    sysctl -p /etc/sysctl.d/99-secure-vps-swap.conf >/dev/null 2>&1
    echo -e "${C_OK}Swap ${mb}MB created and added to fstab (swappiness=10).${C_RST}"
    wait_key
}

mem_swap_drop() {
    if ! swapon --show 2>/dev/null | grep -q "/swapfile"; then
        echo -e "${C_WARN}No /swapfile created by this tool found.${C_RST}"
        wait_key; return
    fi
    if ! ask_yes "Confirm deleting /swapfile?"; then wait_key; return; fi
    swapoff /swapfile
    sed -i '\|^/swapfile|d' /etc/fstab
    rm -f /swapfile
    rm -f /etc/sysctl.d/99-secure-vps-swap.conf
    sysctl -w vm.swappiness=60 >/dev/null 2>&1
    echo -e "${C_OK}Swap deleted, fstab and swappiness restored.${C_RST}"
    wait_key
}

# ════════════════════════════════════════════════════════════
#  Module: Users
# ════════════════════════════════════════════════════════════

user_add_admin() {
    echo -e "${C_WARN}>>> Create regular user with sudo privileges <<<${C_RST}"
    local name
    read -r -p "Enter new username: " name
    if [ -z "$name" ]; then
        echo -e "${C_FAIL}Username cannot be empty.${C_RST}"; wait_key; return
    fi
    if id "$name" &>/dev/null; then
        echo -e "${C_WARN}User $name already exists.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}Creating user $name ...${C_RST}"
    if ! useradd -m -s /bin/bash "$name"; then
        echo -e "${C_FAIL}Creation failed, please check system logs.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}Set login password for $name:${C_RST}"
    passwd "$name"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        usermod -aG sudo "$name"
    else
        usermod -aG wheel "$name"
    fi
    echo -e "${C_OK}User $name created with sudo privileges.${C_RST}"
    echo -e "${C_WARN}Recommend daily login as this user, use sudo when needed.${C_RST}"
    wait_key
}

user_roster() {
    echo -e "${C_INFO}Regular users on this system:${C_RST}"
    awk -F: '($3>=1000 && $1!="nobody") {print $1}' /etc/passwd
    wait_key
}

user_drop() {
    local name
    read -r -p "Enter username to delete: " name
    if [ -z "$name" ]; then
        echo -e "${C_FAIL}Username cannot be empty.${C_RST}"; wait_key; return
    fi
    if ! id "$name" &>/dev/null; then
        echo -e "${C_FAIL}User $name does not exist.${C_RST}"; wait_key; return
    fi
    if [ "$name" = "root" ]; then
        echo -e "${C_FAIL}root cannot be deleted.${C_RST}"; wait_key; return
    fi
    echo -e "${C_WARN}Will delete user $name and home directory, irreversible!${C_RST}"
    read -r -p "Confirm? (y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        userdel -r "$name"
        echo -e "${C_OK}User $name deleted.${C_RST}"
    else
        echo -e "${C_INFO}Cancelled.${C_RST}"
    fi
    wait_key
}

# ════════════════════════════════════════════════════════════
#  Module: Toolbox
# ════════════════════════════════════════════════════════════

sys_identity() {
    clear
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_INFO}        🖥  Host Profile           ${C_RST}"
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_OK}▸ Basic Info:${C_RST}"
    echo "  OS:       ${PRETTY_NAME:-$DISTRO $DISTRO_VER}"
    echo "  Kernel:   $(uname -r)"
    echo "  Arch:     $(uname -m)"
    echo "  CPU:      $(lscpu 2>/dev/null | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}') ($(/usr/bin/nproc 2>/dev/null || echo ?) cores)"
    local virt; virt=$(systemd-detect-virt 2>/dev/null)
    [ -z "$virt" ] && virt="Bare Metal/Unknown"
    echo "  Virt:     $virt"
    echo "  SSH Port: $(ssh_port_live)"
    echo "  Uptime:   $(uptime -p)"
    echo ""
    echo -e "${C_OK}▸ Resource Levels:${C_RST}"
    local cpu mem_t mem_u mem_p disk_p
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | awk '{printf "%.0f", $1}')
    gauge "CPU" "$cpu"
    mem_t=$(free | grep Mem | awk '{print $2}')
    mem_u=$(free | grep Mem | awk '{print $3}')
    mem_p=$(( mem_u * 100 / mem_t ))
    gauge "Memory" "$mem_p"
    disk_p=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    gauge "Disk" "$disk_p"
    echo ""
    echo -e "${C_OK}▸ Public IP:${C_RST}"
    local ipinfo
    ipinfo=$(curl -s --max-time 8 "http://ip-api.com/line?lang=zh-CN&fields=status,country,city,isp,query" 2>/dev/null)
    if [ "$(echo "$ipinfo" | head -n 1)" = "success" ]; then
        echo "$ipinfo" | tail -n 4 | awk 'NR==1{print "  Location: "$1} NR==2{print "  City:     "$1} NR==3{print "  ISP:      "$1} NR==4{print "  IP:       "$1}'
    else
        echo -e "  ${C_WARN}Query timeout or network restricted, try again later.${C_RST}"
    fi
    wait_key
}

sys_timezone() {
    echo -e "${C_WARN}>>> Timezone setting (current: $(timedatectl 2>/dev/null | grep 'Time zone' | awk '{print $3}')) <<<${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} Asia/Shanghai     (Shanghai UTC+8)"
    echo -e "  ${C_WARN}2.${C_RST} Asia/Hong_Kong    (Hong Kong UTC+8)"
    echo -e "  ${C_WARN}3.${C_RST} Asia/Tokyo        (Tokyo UTC+9)"
    echo -e "  ${C_WARN}4.${C_RST} Asia/Singapore    (Singapore UTC+8)"
    echo -e "  ${C_WARN}5.${C_RST} Europe/London     (London)"
    echo -e "  ${C_WARN}6.${C_RST} America/New_York  (New York)"
    echo -e "  ${C_WARN}7.${C_RST} UTC"
    echo -e "  ${C_WARN}8.${C_RST} Custom tz name"
    local pick tz
    read -r -p "❯ Select [1-8]: " pick
    case $pick in
        1) tz="Asia/Shanghai" ;;
        2) tz="Asia/Hong_Kong" ;;
        3) tz="Asia/Tokyo" ;;
        4) tz="Asia/Singapore" ;;
        5) tz="Europe/London" ;;
        6) tz="America/New_York" ;;
        7) tz="UTC" ;;
        8) read -r -p "Enter timezone name (e.g. Asia/Shanghai): " tz ;;
        *) echo -e "${C_FAIL}Invalid choice.${C_RST}"; wait_key; return ;;
    esac
    if ! timedatectl set-timezone "$tz" 2>/dev/null; then
        echo -e "${C_FAIL}Setting failed, please verify timezone name is valid.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_OK}Timezone switched to $tz, current time $(date '+%Y-%m-%d %H:%M:%S').${C_RST}"
    wait_key
}

sys_clock_sync() {
    echo -e "${C_INFO}Enabling NTP time sync...${C_RST}"
    timedatectl set-ntp true 2>/dev/null
    sleep 1
    timedatectl | grep -E "Local time|Universal|Time zone|System clock|NTP"
    if timedatectl show -p NTP 2>/dev/null | grep -q '=yes'; then
        echo -e "${C_OK}Time sync service enabled.${C_RST}"
    else
        echo -e "${C_WARN}Built-in NTP not active, trying chrony...${C_RST}"
        eval "$PKG_INSTALL chrony > /dev/null 2>&1" && systemctl enable --now chronyd 2>/dev/null
        if command -v chronyd >/dev/null 2>&1; then
            echo -e "${C_OK}chrony installed and started.${C_RST}"
        else
            echo -e "${C_FAIL}chrony installation failed, please handle time sync manually.${C_RST}"
        fi
    fi
    wait_key
}

sys_dns_switch() {
    echo -e "${C_WARN}>>> Switch system DNS <<<${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} Cloudflare   1.1.1.1 / 1.0.0.1"
    echo -e "  ${C_WARN}2.${C_RST} Google       8.8.8.8 / 8.8.4.4"
    echo -e "  ${C_WARN}3.${C_RST} Quad9        9.9.9.9 / 149.112.112.112"
    echo -e "  ${C_WARN}4.${C_RST} Alibaba DNS  223.5.5.5 / 223.6.6.6"
    echo -e "  ${C_WARN}5.${C_RST} Tencent DNSPod 119.29.29.29 / 119.28.28.28"
    echo -e "  ${C_WARN}6.${C_RST} Custom (space-separated)"
    local pick servers ns
    read -r -p "❯ Select [1-6]: " pick
    case $pick in
        1) servers="1.1.1.1 1.0.0.1" ;;
        2) servers="8.8.8.8 8.8.4.4" ;;
        3) servers="9.9.9.9 149.112.112.112" ;;
        4) servers="223.5.5.5 223.6.6.6" ;;
        5) servers="119.29.29.29 119.28.28.28" ;;
        6) read -r -p "Enter DNS servers: " servers ;;
        *) echo -e "${C_FAIL}Invalid choice.${C_RST}"; wait_key; return ;;
    esac
    if [ -z "$servers" ]; then
        echo -e "${C_FAIL}DNS cannot be empty.${C_RST}"; wait_key; return
    fi

    # Modify upstream config for systemd-resolved; otherwise write resolv.conf directly
    if systemctl is-active --quiet systemd-resolved 2>/dev/null || [ -L /etc/resolv.conf ]; then
        echo -e "${C_INFO}systemd-resolved detected, modifying upstream DNS...${C_RST}"
        snapshot_file /etc/systemd/resolved.conf
        sed -i -E '/^#?DNS=.*/d' /etc/systemd/resolved.conf
        echo "DNS=$servers" >> /etc/systemd/resolved.conf
        systemctl restart systemd-resolved
        echo -e "${C_OK}Upstream DNS switched to: $servers${C_RST}"
        echo -e "${C_WARN}Local still queries via 127.0.0.53 proxy, upstream is effective.${C_RST}"
    else
        snapshot_file /etc/resolv.conf
        # May have been locked by this feature before, unlock then rewrite
        chattr -i /etc/resolv.conf 2>/dev/null
        : > /etc/resolv.conf
        for ns in $servers; do echo "nameserver $ns" >> /etc/resolv.conf; done
        echo -e "${C_OK}System DNS switched to: $servers${C_RST}"
        if ask_yes "Lock /etc/resolv.conf to prevent DHCP override? (This feature auto-unlocks on next change)"; then
            chattr +i /etc/resolv.conf
            echo -e "${C_OK}Locked.${C_RST}"
        fi
    fi
    wait_key
}

sys_root_key() {
    echo -e "${C_WARN}>>> Reset root password <<<${C_RST}"
    echo -e "${C_WARN}Recommend 16+ char random value; with key login, use as emergency backup only.${C_RST}"
    passwd root
    wait_key
}

net_tcp_ping() {
    local host port tmo
    read -r -p "Target IP or domain: " host
    read -r -p "Target port: " port
    read -r -p "Timeout seconds [3]: " tmo
    tmo=${tmo:-3}
    if [ -z "$host" ] || ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${C_FAIL}Invalid input.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}Probing ${host}:${port} (timeout ${tmo}s)...${C_RST}"
    if timeout "$tmo" bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "${C_OK}✔ Port open, connection successful.${C_RST}"
    else
        echo -e "${C_FAIL}✘ Cannot connect (port closed/service not running/blocked by firewall).${C_RST}"
    fi
    wait_key
}

sys_login_trail() {
    echo -e "${C_WARN}>>> Last 15 successful logins <<<${C_RST}"
    last -n 15 2>/dev/null | head -n 16 || echo -e "${C_FAIL}Cannot read login records.${C_RST}"
    echo ""
    echo -e "${C_WARN}>>> Last 15 failed attempts (brute-force traces) <<<${C_RST}"
    if lastb -n 15 2>/dev/null | head -n 16; then
        local total; total=$(lastb 2>/dev/null | grep -c "^[[:alnum:]_-]")
        echo ""
        echo -e "${C_INFO}Total failed logins: $total${C_RST}"
        [ "$total" -gt 100 ] && echo -e "${C_WARN}High failure count, recommend verifying Fail2Ban and key login are both in place.${C_RST}"
    else
        echo -e "${C_FAIL}Cannot read failure records (requires btmp permission).${C_RST}"
    fi
    wait_key
}

sys_sweep() {
    echo -e "${C_WARN}>>> System cleanup <<<${C_RST}"
    echo -e "${C_INFO}Disk before cleanup: $(df -h / | tail -1 | awk '{print "used "$3" / available "$4}')${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        apt-get clean
        echo -e "${C_OK}apt cache cleared.${C_RST}"
    else
        yum clean all >/dev/null 2>&1
        echo -e "${C_OK}yum cache cleared.${C_RST}"
    fi
    journalctl --vacuum-time=7d 2>/dev/null | tail -n 1
    if ask_yes "Run autoremove to clean orphaned dependencies and old kernel packages?"; then
        if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
            apt-get autoremove --purge -y >/dev/null 2>&1
        else
            yum autoremove -y >/dev/null 2>&1
        fi
        echo -e "${C_OK}Orphaned dependencies cleaned.${C_RST}"
    fi
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        if ask_yes "Docker detected, clean unused images/containers/cache? (Volumes untouched)"; then
            docker system prune -af 2>/dev/null | tail -n 1
        fi
    fi
    echo -e "${C_INFO}Disk after cleanup: $(df -h / | tail -1 | awk '{print "used "$3" / available "$4}')${C_RST}"
    wait_key
}

# ════════════════════════════════════════════════════════════
#  Module: Defense in Depth
# ════════════════════════════════════════════════════════════

KERNEL_CONF_FILE="/etc/sysctl.d/99-secure-vps-kernel.conf"

kernel_arm_core() {
    cat > "$KERNEL_CONF_FILE" <<EOF
# secure-vps kernel hardening (SYN Cookie / anti-spoofing / info reduction)
# Conservative subset from CIS baseline adapted for VPS scenarios
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 2
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
EOF
    sysctl -p "$KERNEL_CONF_FILE" >/dev/null 2>&1
    echo -e "${C_OK}Kernel hardening parameters written to $KERNEL_CONF_FILE and loaded.${C_RST}"
    echo -e "${C_WARN}Note: rp_filter uses loose mode(2), compatible with multi-IP/policy routing scenarios.${C_RST}"
    echo -e "${C_WARN}Note: ptrace_scope=1 restricts non-parent process debugging, normal user strace will be limited, expected behavior.${C_RST}"
}

kernel_arm() {
    echo -e "${C_WARN}>>> Kernel parameter hardening <<<${C_RST}"
    echo -e "${C_INFO}Contents: SYN Cookie, reject ICMP redirect and source routing, SYN backlog expansion, kernel info reduction.${C_RST}"
    echo -e "${C_INFO}All are conservative parameters, no impact on normal operations.${C_RST}"
    if [ -f "$KERNEL_CONF_FILE" ]; then
        echo -e "${C_WARN}Existing hardening config found, will overwrite.${C_RST}"
    fi
    if ask_yes "Confirm apply?"; then
        kernel_arm_core
    fi
    wait_key
}

kernel_disarm() {
    if [ ! -f "$KERNEL_CONF_FILE" ]; then
        echo -e "${C_WARN}No hardening config file, no need to revert.${C_RST}"
        wait_key; return
    fi
    if ask_yes "Confirm reverting hardening and restoring system default parameters?"; then
        rm -f "$KERNEL_CONF_FILE"
        sysctl --system >/dev/null 2>&1
        echo -e "${C_OK}Hardening file removed, kernel parameters reloaded from remaining configs.${C_RST}"
    fi
    wait_key
}

passwd_quality() {
    echo -e "${C_WARN}>>> Password Quality Policy (pwquality) <<<${C_RST}"
    echo -e "${C_INFO}New passwords must be at least 12 chars, with upper/lower/digit/symbol each present.${C_RST}"
    echo -e "${C_WARN}Only constrains future passwords, does not force changing existing ones.${C_RST}"
    if ! ask_yes "Confirm apply?"; then wait_key; return; fi
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        eval "$PKG_INSTALL libpam-pwquality" || { echo -e "${C_FAIL}Installation failed.${C_RST}"; wait_key; return; }
    else
        eval "$PKG_INSTALL libpwquality" || { echo -e "${C_FAIL}Installation failed.${C_RST}"; wait_key; return; }
    fi
    snapshot_file /etc/security/pwquality.conf
    cat > /etc/security/pwquality.conf <<EOF
# secure-vps password quality policy
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
usercheck = 1
enforcing = 1
EOF
    echo -e "${C_OK}Policy active: new passwords at least 12 chars, all four character types required.${C_RST}"
    wait_key
}

sudo_guard() {
    if ! command -v visudo >/dev/null 2>&1; then
        echo -e "${C_FAIL}No sudo environment (visudo missing), cannot configure.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> sudo audit <<<${C_RST}"
    echo -e "${C_INFO}Contents: log all sudo commands to /var/log/sudo.log, and enable use_pty.${C_RST}"
    if ! ask_yes "Confirm apply?"; then wait_key; return; fi
    cat > /etc/sudoers.d/95-secure-vps-audit <<EOF
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
EOF
    chmod 0440 /etc/sudoers.d/95-secure-vps-audit
    # Wrong sudoers can lock out entire privilege escalation, must validate before keeping
    if visudo -cf /etc/sudoers.d/95-secure-vps-audit >/dev/null 2>&1; then
        echo -e "${C_OK}sudo audit enabled (log at /var/log/sudo.log).${C_RST}"
    else
        rm -f /etc/sudoers.d/95-secure-vps-audit
        echo -e "${C_FAIL}Validation failed, write reverted to preserve sudo.${C_RST}"
    fi
    wait_key
}

rootkit_watch() {
    echo -e "${C_WARN}>>> Rkhunter Rootkit Defense <<<${C_RST}"
    if [[ "$DISTRO" =~ ^(centos|rhel|almalinux|rocky)$ ]]; then
        eval "$PKG_INSTALL epel-release > /dev/null 2>&1"
    fi
    if ! command -v rkhunter >/dev/null 2>&1; then
        echo -e "${C_INFO}Installing rkhunter...${C_RST}"
        eval "$PKG_INSTALL rkhunter" || { echo -e "${C_FAIL}Installation failed.${C_RST}"; wait_key; return; }
    fi
    rkhunter --update >/dev/null 2>&1
    # Build baseline from current file attributes, greatly reduces future false positives
    rkhunter --propupd >/dev/null 2>&1
    cat > /etc/cron.d/secure-vps-rkhunter <<EOF
# secure-vps: daily 00:00 rootkit scan
0 0 * * * root /usr/bin/rkhunter --check --sk --report-warnings-only >> /var/log/rkhunter-cron.log 2>&1
EOF
    chmod 644 /etc/cron.d/secure-vps-rkhunter
    echo -e "${C_OK}Ready: baseline built, daily 00:00 auto scan (log at /var/log/rkhunter-cron.log).${C_RST}"
    if ask_yes "Run initial scan now (approx 1-3 minutes)?"; then
        rkhunter --check --sk
    fi
    wait_key
}

integrity_seed() {
    echo -e "${C_WARN}>>> AIDE File Integrity Monitoring <<<${C_RST}"
    echo -e "${C_INFO}Principle: build system file digest baseline, compare daily, log any tampering immediately.${C_RST}"
    echo -e "${C_WARN}Initial baseline and post-upgrade rebuild take a few minutes, this is normal.${C_RST}"
    if ! ask_yes "Confirm install and build baseline?"; then wait_key; return; fi
    eval "$PKG_INSTALL aide" || { echo -e "${C_FAIL}Installation failed.${C_RST}"; wait_key; return; }
    echo -e "${C_INFO}Building initial baseline (do not install other software during this)...${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        aideinit -y -f >/dev/null 2>&1
    else
        aide --init >/dev/null 2>&1
        mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null
    fi
    cat > /etc/cron.d/secure-vps-aide <<EOF
# secure-vps: daily 03:00 integrity check
0 3 * * * root /usr/sbin/aide --check >> /var/log/aide-cron.log 2>&1
EOF
    chmod 644 /etc/cron.d/secure-vps-aide
    echo -e "${C_OK}Baseline ready, daily 03:00 auto check (log at /var/log/aide-cron.log).${C_RST}"
    echo -e "${C_WARN}Important: run 'Rebuild Baseline' after every system upgrade, otherwise false positives will flood.${C_RST}"
    wait_key
}

integrity_reseed() {
    if ! command -v aide >/dev/null 2>&1; then
        echo -e "${C_FAIL}AIDE not installed yet.${C_RST}"; wait_key; return
    fi
    echo -e "${C_INFO}Rebuilding baseline from current system state (required after system upgrade)...${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        aideinit -y -f >/dev/null 2>&1
    else
        aide --init >/dev/null 2>&1
        mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null
    fi
    echo -e "${C_OK}Baseline rebuilt.${C_RST}"
    wait_key
}

integrity_verify() {
    if ! command -v aide >/dev/null 2>&1; then
        echo -e "${C_FAIL}AIDE not installed yet.${C_RST}"; wait_key; return
    fi
    echo -e "${C_INFO}Running integrity check (may take several minutes)...${C_RST}"
    aide --check
    wait_key
}

auditd_install() {
    echo -e "${C_WARN}>>> auditd Audit Rules <<<${C_RST}"
    echo -e "${C_INFO}Covers: account files, sudoers, cron jobs, SSH and kernel configs — paths to privilege escalation and persistence.${C_RST}"
    if ! ask_yes "Confirm install and load rules?"; then wait_key; return; fi
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        eval "$PKG_INSTALL auditd" || { echo -e "${C_FAIL}Installation failed.${C_RST}"; wait_key; return; }
    else
        eval "$PKG_INSTALL audit" || { echo -e "${C_FAIL}Installation failed.${C_RST}"; wait_key; return; }
    fi
    cat > /etc/audit/rules.d/95-secure-vps.rules <<EOF
# secure-vps audit rules
# Accounts and permissions
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
# Cron jobs (persistence hotspot)
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
# SSH and kernel config
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
EOF
    augenrules --load >/dev/null 2>&1
    systemctl enable auditd >/dev/null 2>&1
    systemctl restart auditd 2>/dev/null
    echo -e "${C_OK}Rules loaded (5 categories: identity/sudoers/cron/sshd/sysctl).${C_RST}"
    echo -e "${C_INFO}Query example: ausearch -k sudoers | head -20${C_RST}"
    wait_key
}

services_trim() {
    echo -e "${C_WARN}>>> Reduce attack surface <<<${C_RST}"
    echo -e "${C_INFO}Targets: avahi(LAN discovery), cups(printing), bluetooth, ModemManager(modem).${C_RST}"
    echo -e "${C_INFO}Generally unnecessary for servers; cancel if you have special needs.${C_RST}"
    if ! ask_yes "Confirm disable and prevent auto-start?"; then wait_key; return; fi
    local s
    for s in avahi-daemon cups bluetooth ModemManager; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${s}.service"; then
            if systemctl disable --now "$s" >/dev/null 2>&1; then
                echo -e "${C_OK}Disabled $s.${C_RST}"
            else
                echo -e "${C_WARN}Failed to disable $s, may not be running.${C_RST}"
            fi
        else
            echo -e "${C_INFO}$s not installed, skipping.${C_RST}"
        fi
    done
    systemctl mask ctrl-alt-del.target >/dev/null 2>&1
    echo -e "${C_OK}ctrl-alt-del reboot shortcut disabled.${C_RST}"
    if ! grep -q "nospoof" /etc/host.conf 2>/dev/null; then
        snapshot_file /etc/host.conf
        echo "nospoof on" >> /etc/host.conf
        echo -e "${C_OK}/etc/host.conf nospoof enabled.${C_RST}"
    fi
    wait_key
}

# ── [scan] Baseline Check ──────────────────────────────────────────
SCAN_OK=0
SCAN_WARN=0
SCAN_FAIL=0
SCAN_REPORT=""

note_check() {
    local name=$1 status=$2 msg=$3 tone tag
    case $status in
        PASS) SCAN_OK=$((SCAN_OK+1));   tone=$C_OK;   tag="[PASS]" ;;
        WARN) SCAN_WARN=$((SCAN_WARN+1)); tone=$C_WARN; tag="[WARN]" ;;
        FAIL) SCAN_FAIL=$((SCAN_FAIL+1)); tone=$C_FAIL; tag="[FAIL]" ;;
    esac
    echo -e "${tone}${tag}${C_RST} ${name} ${tone}- $msg${C_RST}"
    echo "[$status] $name - $msg" >> "$SCAN_REPORT"
}

baseline_scan() {
    clear
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_INFO}        🩺 Baseline Check           ${C_RST}"
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_INFO}Entirely read-only, no config changes. SUID scan takes about 1-2 minutes...${C_RST}"
    echo ""

    SCAN_OK=0; SCAN_WARN=0; SCAN_FAIL=0
    SCAN_REPORT="/var/log/secure-vps-scan-$(date +%Y%m%d%H%M%S).txt"
    echo "secure-vps baseline check report - $(date)" > "$SCAN_REPORT"

    # SSH effective values (sshd -T expands all Include, more reliable than grep config file)
    local cfg val
    cfg=$(sshd -T 2>/dev/null)
    if [ -n "$cfg" ]; then
        val=$(echo "$cfg" | awk '/^permitrootlogin /{print $2}')
        case $val in
            no)  note_check "SSH root login" PASS "Fully prohibited" ;;
            prohibit-password|without-password) note_check "SSH root login" WARN "Only password disabled ($val), recommend PermitRootLogin no" ;;
            *)   note_check "SSH root login" FAIL "root login allowed ($val), high risk" ;;
        esac
        val=$(echo "$cfg" | awk '/^passwordauthentication /{print $2}')
        if [ "$val" = "no" ]; then
            note_check "SSH password auth" PASS "Disabled, key-only"
        else
            note_check "SSH password auth" FAIL "Still enabled, brute-force surface exposed"
        fi
        val=$(echo "$cfg" | awk '/^port /{print $2}')
        if [ "$val" = "22" ]; then
            note_check "SSH port" WARN "Still default 22, top scanner target"
        else
            note_check "SSH port" PASS "Non-default port $val"
        fi
        val=$(echo "$cfg" | awk '/^permitemptypasswords /{print $2}')
        if [ "$val" = "no" ]; then
            note_check "Empty password login" PASS "Prohibited"
        else
            note_check "Empty password login" FAIL "Empty passwords allowed!"
        fi
    else
        note_check "SSH config" WARN "sshd -T unavailable, skipping SSH checks"
    fi

    # Firewall
    if ufw status 2>/dev/null | grep -qw active; then
        note_check "Firewall" PASS "UFW active"
    elif firewall-cmd --state 2>/dev/null | grep -q running; then
        note_check "Firewall" PASS "Firewalld running"
    else
        note_check "Firewall" FAIL "No active firewall"
    fi

    # Fail2Ban and port alignment
    if command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active fail2ban >/dev/null 2>&1; then
        note_check "Fail2Ban" PASS "Running"
        local live_port jail_port
        live_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}'); live_port=${live_port:-22}
        jail_port=$(awk -F= '/^\[sshd\]/{f=1;next} /^\[/{f=0} f && $1 ~ /^port/ {gsub(/[ \t]/,"",$2); print $2; exit}' \
            /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.local 2>/dev/null)
        jail_port=${jail_port:-ssh}
        if [ "$jail_port" = "$live_port" ] || [ "$jail_port" = "0:65535" ] || \
           [[ "$jail_port" == *"$live_port"* ]] || { [ "$jail_port" = "ssh" ] && [ "$live_port" = "22" ]; }; then
            note_check "Fail2Ban port alignment" PASS "Ban port ($jail_port) covers actual port ($live_port)"
        else
            note_check "Fail2Ban port alignment" FAIL "jail bans $jail_port but SSH is on $live_port, ban is ineffective!"
        fi
    else
        note_check "Fail2Ban" FAIL "Not installed or not running"
    fi

    # Auto updates
    if dpkg -l 2>/dev/null | grep -q "unattended-upgrades" || \
       systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || \
       systemctl is-enabled yum-cron >/dev/null 2>&1; then
        note_check "Automatic security updates" PASS "Configured"
    else
        note_check "Automatic security updates" WARN "Not configured, will miss critical patches"
    fi

    # Pending upgrades
    local pend=0
    if command -v apt-get >/dev/null 2>&1; then
        pend=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')
    elif command -v yum >/dev/null 2>&1; then
        pend=$(yum -q check-update 2>/dev/null | grep -c '^[a-zA-Z0-9]')
    fi
    if [ "${pend:-0}" -eq 0 ] 2>/dev/null; then
        note_check "Patch status" PASS "All up to date"
    else
        note_check "Patch status" WARN "${pend} packages pending upgrade"
    fi

    # Reboot required
    if [ -f /var/run/reboot-required ]; then
        note_check "Reboot required" WARN "Updates pending reboot to take effect"
    elif command -v needs-restarting >/dev/null 2>&1 && ! needs-restarting -r >/dev/null 2>&1; then
        note_check "Reboot required" WARN "Kernel updates require reboot"
    else
        note_check "Reboot required" PASS "No reboot needed"
    fi

    # Externally exposed ports
    local ports
    ports=$(ss -tuln 2>/dev/null | grep LISTEN | grep -vc '127.0.0.1\|\[::1\]')
    if [ "$ports" -le 10 ]; then
        note_check "Exposed ports" PASS "$ports ports, manageable surface"
    elif [ "$ports" -le 20 ]; then
        note_check "Exposed ports" WARN "$ports ports, recommend checking each"
    else
        note_check "Exposed ports" FAIL "$ports ports, attack surface too large"
    fi

    # Running services count
    local svcs
    svcs=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c running)
    if [ "$svcs" -eq 0 ] 2>/dev/null && ! command -v systemctl >/dev/null 2>&1; then
        note_check "Running services" WARN "No systemd, cannot count"
    elif [ "$svcs" -lt 20 ]; then
        note_check "Running services" PASS "$svcs services"
    elif [ "$svcs" -lt 40 ]; then
        note_check "Running services" WARN "$svcs services, can be reduced"
    else
        note_check "Running services" FAIL "$svcs services, attack surface too large"
    fi

    # Failed logins
    local bad=0
    if command -v lastb >/dev/null 2>&1; then
        bad=$(lastb 2>/dev/null | grep -c "^[[:alnum:]_-]")
    elif command -v journalctl >/dev/null 2>&1; then
        bad=$(journalctl -u ssh -u sshd --since "24 hours ago" 2>/dev/null | grep -c "Failed password")
    fi
    if [ "$bad" -lt 10 ]; then
        note_check "Failed logins" PASS "Total $bad"
    elif [ "$bad" -lt 50 ]; then
        note_check "Failed logins" WARN "Total $bad, scanning signs detected"
    else
        note_check "Failed logins" FAIL "Total $bad, suspected continuous brute-force"
    fi

    # Account anomalies
    local empties
    empties=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | wc -l)
    if [ "$empties" -eq 0 ] 2>/dev/null; then
        note_check "Empty password accounts" PASS "None found"
    else
        note_check "Empty password accounts" FAIL "$empties accounts: $(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')"
    fi
    local roots
    roots=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null | wc -l)
    if [ "$roots" -eq 0 ] 2>/dev/null; then
        note_check "UID=0 accounts" PASS "Only root"
    else
        note_check "UID=0 accounts" FAIL "Beyond root: $(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd | tr '\n' ' ')"
    fi

    # Policy and configuration
    if grep -Eq '^\s*minlen\s*=\s*[0-9]+' /etc/security/pwquality.conf 2>/dev/null; then
        note_check "Password policy" PASS "minlen configured"
    else
        note_check "Password policy" WARN "Not configured, weak passwords accepted"
    fi
    if grep -rq "logfile" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        note_check "sudo audit" PASS "Enabled"
    else
        note_check "sudo audit" WARN "Not enabled, privilege escalation not traceable"
    fi
    if [ -f /etc/sysctl.d/99-secure-vps-kernel.conf ]; then
        note_check "Kernel hardening" PASS "secure-vps config applied"
    else
        note_check "Kernel hardening" WARN "Not applied"
    fi

    # Non-standard path SUID (root filesystem only, 90s timeout)
    local suid_list suid_n
    suid_list=$(timeout 90 find / -xdev -type f -perm -4000 2>/dev/null | grep -vE '^/(usr/)?(bin|sbin|lib|libexec|lib64)/')
    suid_n=$(echo "$suid_list" | grep -c .)
    if [ "$suid_n" -eq 0 ]; then
        note_check "SUID files" PASS "No non-standard path items"
    else
        note_check "SUID files" WARN "$suid_n non-standard paths, please verify manually"
        echo "---- Non-standard path SUID ----" >> "$SCAN_REPORT"
        echo "$suid_list" >> "$SCAN_REPORT"
    fi

    # Defense component status
    if command -v rkhunter >/dev/null 2>&1; then
        note_check "Rootkit defense" PASS "rkhunter present"
    else
        note_check "Rootkit defense" WARN "rkhunter missing"
    fi
    if command -v aide >/dev/null 2>&1; then
        note_check "Integrity monitoring" PASS "AIDE present"
    else
        note_check "Integrity monitoring" WARN "AIDE missing"
    fi

    echo ""
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "Check results: ${C_OK}PASS $SCAN_OK${C_RST} / ${C_WARN}WARN $SCAN_WARN${C_RST} / ${C_FAIL}FAIL $SCAN_FAIL${C_RST}"
    if [ "$SCAN_FAIL" -gt 0 ]; then
        echo -e "${C_FAIL}Failed items found, recommend prioritizing (most fixable in 'Defense in Depth' menu).${C_RST}"
    elif [ "$SCAN_WARN" -gt 0 ]; then
        echo -e "${C_WARN}No critical issues, room for improvement, address items per report.${C_RST}"
    else
        echo -e "${C_OK}Excellent status!${C_RST}"
    fi
    echo -e "${C_INFO}Report saved: $SCAN_REPORT${C_RST}"
    echo "==== Summary: PASS=$SCAN_OK WARN=$SCAN_WARN FAIL=$SCAN_FAIL ====" >> "$SCAN_REPORT"
    wait_key
}

# ════════════════════════════════════════════════════════════
#  Module: Apps and Containers
# ════════════════════════════════════════════════════════════

docker_engine_on() {
    if command -v docker >/dev/null 2>&1; then
        echo -e "${C_WARN}Docker already installed, skipping.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}>>> Running Docker official install script... <<<${C_RST}"
    curl -fsSL https://get.docker.com | bash -s docker
    systemctl enable docker
    systemctl start docker
    echo -e "${C_OK}>>> Docker installed and started.<<<${C_RST}"
    wait_key
}

docker_registry_tune() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}Please install Docker first.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Registry mirror and log rotation <<<${C_RST}"
    echo -e "${C_INFO}Public mirrors are time-sensitive, re-run this option to replace when expired.${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} docker.1ms.run"
    echo -e "  ${C_WARN}2.${C_RST} docker.m.daocloud.io"
    echo -e "  ${C_WARN}3.${C_RST} Use both"
    echo -e "  ${C_WARN}4.${C_RST} Custom (space-separated, with https://)"
    local pick mirrors m json
    read -r -p "❯ Select [1-4]: " pick
    case $pick in
        1) mirrors="https://docker.1ms.run" ;;
        2) mirrors="https://docker.m.daocloud.io" ;;
        3) mirrors="https://docker.1ms.run https://docker.m.daocloud.io" ;;
        4) read -r -p "Enter mirror URL: " mirrors ;;
        *) echo -e "${C_FAIL}Invalid choice.${C_RST}"; wait_key; return ;;
    esac
    if [ -z "$mirrors" ]; then
        echo -e "${C_FAIL}URL cannot be empty.${C_RST}"; wait_key; return
    fi
    json=""
    for m in $mirrors; do
        [ -n "$json" ] && json="$json, "
        json="$json\"$m\""
    done

    snapshot_file /etc/docker/daemon.json
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<EOF
{
  "registry-mirrors": [$json],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  }
}
EOF
    echo -e "${C_INFO}Restarting Docker to apply...${C_RST}"
    systemctl restart docker
    sleep 2
    if docker info >/dev/null 2>&1; then
        echo -e "${C_OK}Effective: mirror and log rotation (50m x 3 per file) applied.${C_RST}"
    else
        echo -e "${C_FAIL}Docker restart failed, rolling back daemon.json...${C_RST}"
        local bak="" orig_f
    for orig_f in /etc/docker/daemon.json.orig-*; do [ -e "$orig_f" ] && bak=$orig_f; done
        if [ -n "$bak" ]; then
            cp "$bak" /etc/docker/daemon.json
            systemctl restart docker
            echo -e "${C_WARN}Reverted to previous configuration.${C_RST}"
        fi
    fi
    wait_key
}

# Docker -p published ports write iptables directly, bypassing UFW and exposing to public.
# Fix: disable iptables management in daemon.json + inject docker0 egress NAT in before.rules.
docker_ufw_takeover() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}Please install Docker first.${C_RST}"
        wait_key; return
    fi
    if [ "$FW_KIND" != "ufw" ]; then
        echo -e "${C_WARN}This solution only covers UFW (Ubuntu/Debian), current system uses firewalld.${C_RST}"
        wait_key; return
    fi
    if grep -q '"iptables"[[:space:]]*:[[:space:]]*false' /etc/docker/daemon.json 2>/dev/null; then
        echo -e "${C_OK}Takeover already enabled.${C_RST}"
        if ask_yes "Revert takeover (restore Docker default iptables behavior)?"; then
            local bd bu
            bd="" bu=""
            local orig_f
            for orig_f in /etc/docker/daemon.json.orig-*; do [ -e "$orig_f" ] && bd=$orig_f; done
            for orig_f in /etc/ufw/before.rules.orig-*; do [ -e "$orig_f" ] && bu=$orig_f; done
            [ -n "$bd" ] && cp "$bd" /etc/docker/daemon.json
            [ -n "$bu" ] && cp "$bu" /etc/ufw/before.rules
            ufw reload >/dev/null 2>&1
            systemctl restart docker
            echo -e "${C_OK}Reverted.${C_RST}"
        fi
        wait_key; return
    fi

    echo -e "${C_WARN}>>> Docker UFW bypass fix <<<${C_RST}"
    echo -e "${C_INFO}Issue: -p published ports bypass UFW and expose to public, affects nearly all default installs.${C_RST}"
    echo -e "${C_INFO}Solution: Docker no longer manages iptables, ports controlled via UFW + docker0 egress NAT injected.${C_RST}"
    echo -e "${C_FAIL}Impact notice:${C_RST}"
    echo -e "${C_FAIL}  1. Published container ports immediately become unreachable, need individual ufw allow (this is the goal);${C_RST}"
    echo -e "${C_FAIL}  2. Custom bridge network egress requires manual NAT for corresponding subnet.${C_RST}"
    if ! ask_yes "Confirm takeover?"; then wait_key; return; fi

    snapshot_file /etc/docker/daemon.json
    mkdir -p /etc/docker
    if [ -s /etc/docker/daemon.json ]; then
        if command -v python3 >/dev/null 2>&1; then
            python3 - <<'PYEOF'
import json
p = "/etc/docker/daemon.json"
try:
    with open(p) as f:
        cfg = json.load(f)
except Exception:
    cfg = {}
cfg["iptables"] = False
with open(p, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PYEOF
        else
            sed -i '1s/{/{\n  "iptables": false,/' /etc/docker/daemon.json
        fi
    else
        printf '{\n  "iptables": false\n}\n' > /etc/docker/daemon.json
    fi

    snapshot_file /etc/ufw/before.rules
    if ! grep -q "SECURE_VPS_DOCKER_MASQ" /etc/ufw/before.rules; then
        sed -i "/^\*filter/i # secure-vps: docker0 egress NAT (with iptables:false)\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 172.17.0.0\/16 ! -o docker0 -j MASQUERADE\nCOMMIT\n" /etc/ufw/before.rules
    fi

    ufw reload >/dev/null 2>&1
    systemctl restart docker
    sleep 3
    if docker info >/dev/null 2>&1; then
        echo -e "${C_OK}Takeover successful, all container ports now controlled by UFW.${C_RST}"
        echo -e "${C_WARN}Allow example: ufw allow 8080/tcp${C_RST}"
        echo -e "${C_WARN}Egress note: default bridge (172.17.0.0/16) has NAT; custom networks need additional SECURE_VPS_DOCKER_MASQ lines in /etc/ufw/before.rules.${C_RST}"
    else
        echo -e "${C_FAIL}Docker restart failed, rolling back...${C_RST}"
        local bd bu
        bd="" bu=""
        local orig_f
        for orig_f in /etc/docker/daemon.json.orig-*; do [ -e "$orig_f" ] && bd=$orig_f; done
        for orig_f in /etc/ufw/before.rules.orig-*; do [ -e "$orig_f" ] && bu=$orig_f; done
        [ -n "$bd" ] && cp "$bd" /etc/docker/daemon.json
        [ -n "$bu" ] && cp "$bu" /etc/ufw/before.rules
        ufw reload >/dev/null 2>&1
        systemctl restart docker
        echo -e "${C_WARN}Reverted to pre-takeover state.${C_RST}"
    fi
    wait_key
}

docker_engine_off() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}Docker not found.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_FAIL}Warning: uninstall will stop and remove all containers!${C_RST}"
    read -r -p "Confirm complete Docker uninstall? (y/N): " ack
    if [[ ! "$ack" =~ ^[Yy]$ ]]; then
        echo -e "${C_INFO}Cancelled.${C_RST}"; wait_key; return
    fi
    echo -e "${C_INFO}Stopping Docker...${C_RST}"
    systemctl stop docker 2>/dev/null
    echo -e "${C_INFO}Removing components...${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
        apt-get autoremove -y --purge
    else
        yum remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
    fi
    read -r -p "Also delete all data (images/containers/volumes, including /var/lib/docker)? (y/N): " wipe
    if [[ "$wipe" =~ ^[Yy]$ ]]; then
        rm -rf /var/lib/docker /etc/docker
        echo -e "${C_OK}Docker and data completely removed.${C_RST}"
    else
        echo -e "${C_OK}Engine uninstalled, data retained.${C_RST}"
    fi
    wait_key
}

docker_up()      { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; }
docker_present() { docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; }

app_portainer_on() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}Please install Docker first.${C_RST}"; wait_key; return
    fi
    if docker_present portainer; then
        echo -e "${C_WARN}Portainer container already exists, uninstall first to reinstall.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}Deploying Portainer management panel...${C_RST}"
    docker volume create portainer_data >/dev/null
    docker run -d --name portainer --restart=always \
        -p 9000:9000 \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v portainer_data:/data \
        portainer/portainer-ce:latest >/dev/null
    if docker_up portainer; then
        echo -e "${C_OK}Ready: http://server-ip:9000 set up admin on first login.${C_RST}"
        ask_yes "Allow port 9000 in firewall?" && fw_grant_tcp 9000
    else
        echo -e "${C_FAIL}Start failed, check: docker logs portainer${C_RST}"
    fi
    wait_key
}

app_portainer_off() {
    if ! docker_present portainer; then
        echo -e "${C_WARN}No Portainer container found.${C_RST}"; wait_key; return
    fi
    docker rm -f portainer >/dev/null 2>&1
    if ask_yes "Also delete its data volume (panel config)?"; then
        docker volume rm portainer_data >/dev/null 2>&1
        echo -e "${C_OK}Container and data removed.${C_RST}"
    else
        echo -e "${C_OK}Container deleted, data volume retained.${C_RST}"
    fi
    wait_key
}

app_watch_on() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}Please install Docker first.${C_RST}"; wait_key; return
    fi
    # If exists, rebuild as new version: install and update combined
    if docker_present watchtower; then
        echo -e "${C_INFO}Watchtower exists, pulling and rebuilding...${C_RST}"
        docker rm -f watchtower >/dev/null 2>&1
    fi
    echo -e "${C_INFO}Deploying Watchtower auto-update (checks every 24h)...${C_RST}"
    docker run -d --name watchtower --restart unless-stopped \
        -v /var/run/docker.sock:/var/run/docker.sock \
        containrrr/watchtower --cleanup --interval 86400 >/dev/null
    if docker_up watchtower; then
        echo -e "${C_OK}Ready: other containers will auto-upgrade and clean old images.${C_RST}"
    else
        echo -e "${C_FAIL}Start failed, check: docker logs watchtower${C_RST}"
    fi
    wait_key
}

app_watch_off() {
    if ! docker_present watchtower; then
        echo -e "${C_WARN}No Watchtower container found.${C_RST}"; wait_key; return
    fi
    docker rm -f watchtower >/dev/null 2>&1
    echo -e "${C_OK}Removed, containers no longer auto-update.${C_RST}"
    wait_key
}

app_kuma_on() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}Please install Docker first.${C_RST}"; wait_key; return
    fi
    if docker_present uptime-kuma; then
        echo -e "${C_WARN}Uptime Kuma already exists.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}Deploying Uptime Kuma uptime monitoring panel...${C_RST}"
    docker run -d --restart=always --name uptime-kuma \
        -p 3001:3001 \
        -v uptime-kuma:/app/data \
        louislam/uptime-kuma:1 >/dev/null
    if docker_up uptime-kuma; then
        echo -e "${C_OK}Ready: http://server-ip:3001 initialize account.${C_RST}"
        ask_yes "Allow port 3001 in firewall?" && fw_grant_tcp 3001
    else
        echo -e "${C_FAIL}Start failed, check: docker logs uptime-kuma${C_RST}"
    fi
    wait_key
}

app_kuma_off() {
    if ! docker_present uptime-kuma; then
        echo -e "${C_WARN}No Uptime Kuma container found.${C_RST}"; wait_key; return
    fi
    docker rm -f uptime-kuma >/dev/null 2>&1
    if ask_yes "Also delete monitoring history data volume?"; then
        docker volume rm uptime-kuma >/dev/null 2>&1
        echo -e "${C_OK}Container and data removed.${C_RST}"
    else
        echo -e "${C_OK}Container deleted, data volume retained.${C_RST}"
    fi
    wait_key
}

app_1panel_on() {
    if command -v 1pctl >/dev/null 2>&1; then
        echo -e "${C_WARN}1Panel already detected, note potential duplicate install.${C_RST}"
    fi
    echo -e "${C_INFO}>>> Running 1Panel official quick install script... <<<${C_RST}"
    curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh && sudo bash quick_start.sh
    wait_key
}

app_1panel_off() {
    if ! command -v 1pctl >/dev/null 2>&1; then
        echo -e "${C_FAIL}1Panel not found (no 1pctl).${C_RST}"
        wait_key; return
    fi
    echo -e "${C_FAIL}Warning: uninstalling 1Panel will stop related containers.${C_RST}"
    read -r -p "Confirm uninstall? (y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        1pctl uninstall
        echo -e "${C_OK}Uninstall script executed.${C_RST}"
    else
        echo -e "${C_INFO}Cancelled.${C_RST}"
    fi
    wait_key
}

# ════════════════════════════════════════════════════════════
#  Module: Monitoring and Benchmarking
# ════════════════════════════════════════════════════════════

sys_pulse() {
    clear
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_INFO}      📊 Real-time Resource Dashboard         ${C_RST}"
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_OK}▸ Uptime: $(uptime -p)${C_RST}"
    echo ""
    echo -e "${C_OK}▸ Core Levels:${C_RST}"
    local cpu mem_t mem_u mem_p disk_p
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | awk '{printf "%.0f", $1}')
    gauge "CPU" "$cpu"
    mem_t=$(free | grep Mem | awk '{print $2}')
    mem_u=$(free | grep Mem | awk '{print $3}')
    mem_p=$(( mem_u * 100 / mem_t ))
    gauge "Memory" "$mem_p"
    disk_p=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    gauge "Disk" "$disk_p"
    echo ""
    echo -e "${C_OK}▸ Load Average: $(awk '{print $1" / "$2" / "$3}' /proc/loadavg)${C_RST}"
    echo ""
    echo -e "${C_OK}▸ Network Interfaces:${C_RST}"
    if command -v ip >/dev/null; then
        ip -4 -br addr | grep -v "127.0.0.1" | awk '{print "  " $1 ": " $3}'
    fi
    wait_key
}

bench_omni() {
    echo -e "${C_WARN}Warning: comprehensive benchmark is time-consuming and high-load.${C_RST}"
    read -r -p "Confirm? (y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        curl -L https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh -o ecs.sh && chmod +x ecs.sh && bash ecs.sh
    fi
    wait_key
}

bench_ip_score() {
    echo -e "${C_INFO}Running IP quality and risk scoring (IP.Check.Place)...${C_RST}"
    bash <(curl -Ls https://raw.githubusercontent.com/xykt/IPQuality/main/ip.sh)
    wait_key
}

bench_cpu_disk() {
    echo -e "${C_WARN}[High Load] YABS benchmark (incl. Geekbench) is hard on low-spec machines.${C_RST}"
    read -r -p "Confirm? (y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        curl -sL yabs.sh | bash
    fi
    wait_key
}

bench_speed() {
    echo -e "${C_WARN}[Bandwidth] Global speed test consumes significant bandwidth.${C_RST}"
    read -r -p "Confirm? (y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        curl -Lso- bench.sh | bash
    fi
    wait_key
}

bench_stream() {
    echo -e "${C_INFO}Running streaming unlock detection...${C_RST}"
    bash <(curl -L -s check.unlock.media)
    wait_key
}

bench_route() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Return Route      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} Trace to specific target"
        echo -e "  ${C_WARN}2.${C_RST} Quick triple-network return trace"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick target
        read -r -p "Select [0-2]: " pick
        case $pick in
            1)
                read -r -p "Target IP or domain (blank=auto): " target
                command -v nexttrace >/dev/null 2>&1 || { echo -e "${C_INFO}Installing NextTrace...${C_RST}"; curl nxtrace.org/nt | bash; }
                if [ -z "$target" ]; then nexttrace --ipv4; else nexttrace "$target"; fi
                wait_key
                ;;
            2)
                echo -e "${C_INFO}Running triple-network quick test...${C_RST}"
                command -v nexttrace >/dev/null 2>&1 || { echo -e "${C_INFO}Installing NextTrace...${C_RST}"; curl nxtrace.org/nt | bash; }
                nexttrace --fast-trace
                wait_key
                ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

# ════════════════════════════════════════════════════════════
#  Pages (Menus)
# ════════════════════════════════════════════════════════════

page_ssh() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     SSH and Login     ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} Upgrade system packages"
        echo -e "  ${C_WARN}2.${C_RST} Import GitHub public keys and disable password login"
        echo -e "  ${C_WARN}3.${C_RST} SSH baseline parameters (anti-brute-force)"
        echo -e "  ${C_WARN}4.${C_RST} Change SSH port"
        echo -e "  ${C_WARN}5.${C_RST} Disable root password login (keep keys)"
        echo -e "  ${C_WARN}6.${C_RST} Login whitelist (AllowUsers)"
        echo -e "  ${C_WARN}7.${C_RST} Rollback latest config snapshot"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-7]: " pick
        case $pick in
            1) pkg_upgrade_all ;;
            2) ssh_keys_from_github ;;
            3) ssh_baseline_pack ;;
            4) ssh_port_shift ;;
            5) ssh_lock_root_passwd ;;
            6) ssh_gate_users ;;
            7) ssh_config_rewind "manual"; wait_key ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_fw() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}       Firewall      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} Initialize and enable"
        echo -e "  ${C_WARN}2.${C_RST} View status and rules"
        echo -e "  ${C_WARN}3.${C_RST} Allow custom port"
        echo -e "  ${C_WARN}4.${C_RST} Reload rules"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-4]: " pick
        case $pick in
            1) fw_init ;;
            2) fw_report ;;
            3) fw_open ;;
            4) fw_reload ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_intrusion() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Intrusion Blocking       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🚫 Deploy Fail2Ban protection"
        echo -e "  ${C_WARN}2.${C_RST} 📋 Fail2Ban status and ban list"
        echo -e "  ${C_WARN}3.${C_RST} 📜 Fail2Ban interception logs"
        echo -e "  ${C_WARN}4.${C_RST} 🔄 Restart Fail2Ban"
        echo -e "  ${C_WARN}5.${C_RST} 🛡 CrowdSec complete deployment wizard"
        echo -e "  ${C_WARN}6.${C_RST} 📋 CrowdSec status"
        echo -e "  ${C_WARN}7.${C_RST} 🛡️ CrowdSec audit (read-only)"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-7]: " pick
        case $pick in
            1) f2b_deploy ;;
            2) f2b_report ;;
            3) f2b_log_tail ;;
            4) systemctl restart fail2ban; echo -e "${C_OK}Restarted.${C_RST}"; wait_key ;;
            5) crowdsec_setup_run ;;
            6) crowdsec_status ;;
            7) crowdsec_audit ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

crowdsec_setup_run() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local cs_script="$script_dir/scripts/crowdsec_setup.sh"
    [ ! -f "$cs_script" ] && cs_script="/usr/local/share/secure-vps/scripts/crowdsec_setup.sh"
    if [ ! -f "$cs_script" ]; then
        echo -e "${C_FAIL}Cannot find CrowdSec deployment script${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> CrowdSec complete deployment wizard <<<${C_RST}"
    echo -e "${C_INFO}Install + scenarios + bouncer + alerts, audit mode is read-only.${C_RST}"
    echo ""
    bash "$cs_script"
    wait_key
}

crowdsec_deploy() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local cs_script="$script_dir/scripts/crowdsec_setup.sh"
    [ ! -f "$cs_script" ] && cs_script="/usr/local/share/secure-vps/scripts/crowdsec_setup.sh"
    if [ ! -f "$cs_script" ]; then
        echo -e "${C_FAIL}Cannot find CrowdSec deployment script${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> CrowdSec deployment <<<${C_RST}"
    echo -e "${C_INFO}Running full deployment script (install mode)${C_RST}"
    echo ""
    bash "$cs_script" --install
    wait_key
}

crowdsec_status() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local cs_script="$script_dir/scripts/crowdsec_setup.sh"
    [ ! -f "$cs_script" ] && cs_script="/usr/local/share/secure-vps/scripts/crowdsec_setup.sh"
    if [ ! -f "$cs_script" ]; then
        echo -e "${C_FAIL}Cannot find CrowdSec deployment script${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> CrowdSec status <<<${C_RST}"
    echo ""
    bash "$cs_script" --status
    wait_key
}

crowdsec_audit() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local cs_script="$script_dir/scripts/crowdsec_setup.sh"
    [ ! -f "$cs_script" ] && cs_script="/usr/local/share/secure-vps/scripts/crowdsec_setup.sh"
    if [ ! -f "$cs_script" ]; then
        echo -e "${C_FAIL}Cannot find CrowdSec deployment script${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> CrowdSec read-only audit <<<${C_RST}"
    echo -e "${C_INFO}Audit mode does not modify any configuration, only checks and generates reports.${C_RST}"
    echo ""
    bash "$cs_script" --audit
    wait_key
}

page_tuning() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}    Performance Tuning        ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} Enable BBR"
        echo -e "  ${C_WARN}2.${C_RST} Create Swap (selectable size)"
        echo -e "  ${C_WARN}3.${C_RST} Delete Swap"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-3]: " pick
        case $pick in
            1) net_bbr_enable ;;
            2) mem_swap_build ;;
            3) mem_swap_drop ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_users() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     User Management      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} Create sudo user"
        echo -e "  ${C_WARN}2.${C_RST} View regular users"
        echo -e "  ${C_WARN}3.${C_RST} Delete regular user"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-3]: " pick
        case $pick in
            1) user_add_admin ;;
            2) user_roster ;;
            3) user_drop ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_toolbox() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}      Toolbox       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🖥  Host Profile (CPU/Virt/IP location)"
        echo -e "  ${C_WARN}2.${C_RST} 🕐  Timezone switch"
        echo -e "  ${C_WARN}3.${C_RST} ⏱  NTP time sync"
        echo -e "  ${C_WARN}4.${C_RST} 🌐  DNS switch"
        echo -e "  ${C_WARN}5.${C_RST} 🔐  root password reset"
        echo -e "  ${C_WARN}6.${C_RST} 🔗  Port connectivity test"
        echo -e "  ${C_WARN}7.${C_RST} 📜  Login trail (incl. brute-force records)"
        echo -e "  ${C_WARN}8.${C_RST} 🧹  System cleanup"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-8]: " pick
        case $pick in
            1) sys_identity ;;
            2) sys_timezone ;;
            3) sys_clock_sync ;;
            4) sys_dns_switch ;;
            5) sys_root_key ;;
            6) net_tcp_ping ;;
            7) sys_login_trail ;;
            8) sys_sweep ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_shield_baseline() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Baseline Check       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🩺 Baseline check (read-only, no system changes)"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-1]: " pick
        case $pick in
            1) baseline_scan ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_shield_kernel() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Kernel hardening       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🧱 Kernel parameter hardening"
        echo -e "  ${C_WARN}2.${C_RST} ♻  Revert kernel hardening"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-2]: " pick
        case $pick in
            1) kernel_arm ;;
            2) kernel_disarm ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_shield_audit() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   Audit and Integrity    ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🕵 Rkhunter defense"
        echo -e "  ${C_WARN}2.${C_RST} 🧬 AIDE Integrity"
        echo -e "  ${C_WARN}3.${C_RST} 📡 auditd audit"
        echo -e "  ${C_WARN}4.${C_RST} 🔌 Reduce attack surface"
        echo -e "  ${C_WARN}5.${C_RST} 🔍 Lynis audit"
        echo -e "  ${C_WARN}6.${C_RST} 📋 CIS compliance audit (Level 1)"
        echo -e "  ${C_WARN}7.${C_RST} 📋 CIS compliance audit (Level 2)"
        echo -e "  ${C_WARN}8.${C_RST} 📋 STIG compliance check"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-8]: " pick
        case $pick in
            1) rootkit_watch ;;
            2) page_integrity ;;
            3) auditd_install ;;
            4) services_trim ;;
            5) lynis_audit ;;
            6) cis_audit_run 1 ;;
            7) cis_audit_run 2 ;;
            8) stig_audit_run ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

cis_audit_run() {
    local level=$1
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local cis_script="$script_dir/scripts/cis_benchmark_audit.sh"
    if [ ! -f "$cis_script" ]; then
        # Fallback: try location relative to global command
        cis_script="/usr/local/share/secure-vps/scripts/cis_benchmark_audit.sh"
    fi
    if [ ! -f "$cis_script" ]; then
        echo -e "${C_FAIL}Cannot find cis_benchmark_audit.sh${C_RST}"
        echo -e "${C_INFO}Please run from repo, or ensure complete global installation.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> CIS Benchmark compliance audit (Level $level) <<<${C_RST}"
    echo -e "${C_INFO}Read-only mode, no system configuration is modified.${C_RST}"
    echo -e "${C_INFO}Report will be saved to /var/log/cis-audit/${C_RST}"
    echo ""
    bash "$cis_script" --level "$level"
    wait_key
}

stig_audit_run() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local stig_script="$script_dir/scripts/stig_compliance_check.sh"
    if [ ! -f "$stig_script" ]; then
        stig_script="/usr/local/share/secure-vps/scripts/stig_compliance_check.sh"
    fi
    if [ ! -f "$stig_script" ]; then
        echo -e "${C_FAIL}Cannot find stig_compliance_check.sh${C_RST}"
        echo -e "${C_INFO}Please run from repo, or ensure complete global installation.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> DISA STIG compliance check (Scanner mode) <<<${C_RST}"
    echo -e "${C_INFO}Read-only mode, no system configuration is modified.${C_RST}"
    echo -e "${C_INFO}Report will be saved to /var/log/stig-audit/${C_RST}"
    echo ""
    bash "$stig_script" --scanner
    wait_key
}

docker_audit_run() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}Docker not installed${C_RST}"
        wait_key; return
    fi
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local docker_script="$script_dir/scripts/docker_security_audit.sh"
    if [ ! -f "$docker_script" ]; then
        docker_script="/usr/local/share/secure-vps/scripts/docker_security_audit.sh"
    fi
    if [ ! -f "$docker_script" ]; then
        echo -e "${C_FAIL}Cannot find docker_security_audit.sh${C_RST}"
        echo -e "${C_INFO}Please run from repo, or ensure complete global installation.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> CIS Docker Benchmark compliance audit <<<${C_RST}"
    echo -e "${C_INFO}Read-only mode, no Docker config or containers modified.${C_RST}"
    echo -e "${C_INFO}Report will be saved to /var/log/docker-audit/${C_RST}"
    echo ""
    bash "$docker_script"
    wait_key
}

dockerfile_hardener_run() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local hardener_script="$script_dir/scripts/dockerfile_hardener.sh"
    if [ ! -f "$hardener_script" ]; then
        hardener_script="/usr/local/share/secure-vps/scripts/dockerfile_hardener.sh"
    fi
    if [ ! -f "$hardener_script" ]; then
        echo -e "${C_FAIL}Cannot find dockerfile_hardener.sh${C_RST}"
        echo -e "${C_INFO}Please run from repo, or ensure complete global installation.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Dockerfile security analysis and hardening <<<${C_RST}"
    echo -e "${C_INFO}Enter Dockerfile path to analyze (--fix enables auto-remediation).${C_RST}"
    echo ""
    read -r -p "Dockerfile path (or directory, -r recursive): " df_target
    [ -z "$df_target" ] && { echo -e "${C_FAIL}No path entered${C_RST}"; wait_key; return; }
    local df_fix=""
    if ask_yes "Enable auto-remediation mode (--fix)?"; then
        df_fix="--fix"
    fi
    echo ""
    bash "$hardener_script" $df_fix "$df_target"
    wait_key
}

k8s_audit_run() {
    if ! command -v kubectl >/dev/null 2>&1; then
        echo -e "${C_FAIL}kubectl not installed${C_RST}"
        echo -e "${C_INFO}Please install kubectl and configure kubeconfig first${C_RST}"
        wait_key; return
    fi
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local k8s_script="$script_dir/scripts/k8s_security_audit.sh"
    if [ ! -f "$k8s_script" ]; then
        k8s_script="/usr/local/share/secure-vps/scripts/k8s_security_audit.sh"
    fi
    if [ ! -f "$k8s_script" ]; then
        echo -e "${C_FAIL}Cannot find k8s_security_audit.sh${C_RST}"
        echo -e "${C_INFO}Please run from repo, or ensure complete global installation.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> CIS Kubernetes Benchmark compliance audit <<<${C_RST}"
    echo -e "${C_INFO}Read-only mode, no Kubernetes resources or node configs modified.${C_RST}"
    echo -e "${C_INFO}Report will be saved to /var/log/k8s-audit/${C_RST}"
    echo ""
    bash "$k8s_script"
    wait_key
}

runtime_security_run() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local rs_script="$script_dir/scripts/runtime_security_setup.sh"
    if [ ! -f "$rs_script" ]; then
        rs_script="/usr/local/share/secure-vps/scripts/runtime_security_setup.sh"
    fi
    if [ ! -f "$rs_script" ]; then
        echo -e "${C_FAIL}Cannot find runtime_security_setup.sh${C_RST}"
        echo -e "${C_INFO}Please run from repo, or ensure complete global installation.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Runtime security deployment (Falco + Tetragon) <<<${C_RST}"
    echo -e "${C_INFO}Generate local deployment config templates, does not install directly.${C_RST}"
    echo ""
    echo -e "  ${C_WARN}1.${C_RST} Interactive wizard (recommended)"
    echo -e "  ${C_WARN}2.${C_RST} Generate Falco config"
    echo -e "  ${C_WARN}3.${C_RST} Generate Tetragon config"
    echo -e "  ${C_WARN}4.${C_RST} Audit current runtime security status"
    echo -e "  ${C_WARN}5.${C_RST} View detection rules"
    echo -e "  ${C_WARN}0.${C_RST} Back"
    echo
    local pick
    read -r -p "Select [0-5]: " pick
    case $pick in
        1) bash "$rs_script" ;;
        2) bash "$rs_script" --falco ;;
        3) bash "$rs_script" --tetragon ;;
        4) bash "$rs_script" --audit ;;
        5) bash "$rs_script" --rules ;;
        0) return ;;
        *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
    esac
    wait_key
}

page_shield_access() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   Password and Permissions      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🔑 Password quality policy"
        echo -e "  ${C_WARN}2.${C_RST} 📝 sudo audit"
        echo -e "  ${C_WARN}3.${C_RST} 🔄 Automatic security updates"
        echo -e "  ${C_WARN}4.${C_RST} 👥 Create sudo user"
        echo -e "  ${C_WARN}5.${C_RST} 👥 View regular users"
        echo -e "  ${C_WARN}6.${C_RST} 👥 Delete regular user"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-6]: " pick
        case $pick in
            1) passwd_quality ;;
            2) sudo_guard ;;
            3) auto_updates_on ;;
            4) user_add_admin ;;
            5) user_roster ;;
            6) user_drop ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_emergency() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Emergency Check       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🚨 Quick security check (baseline scan)"
        echo -e "  ${C_WARN}2.${C_RST} 👥 Recent login records"
        echo -e "  ${C_WARN}3.${C_RST} ⏰ Suspicious cron jobs"
        echo -e "  ${C_WARN}4.${C_RST} 📖 See incident handbook (handbook/03-incident-response.md)"
        echo -e "  ${C_WARN}5.${C_RST} 🔍 Incident forensics collection (incident_triage.sh)"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-5]: " pick
        case $pick in
            1) baseline_scan ;;
            2) emergency_logins ;;
            3) emergency_cron ;;
            4) echo -e "${C_INFO}Please refer to handbook/03-incident-response.md${C_RST}"; wait_key ;;
            5) incident_triage_menu ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

emergency_logins() {
    echo -e "${C_WARN}>>> Recent login records <<<${C_RST}"
    echo -e "${C_INFO}── Successful logins (last 20) ──${C_RST}"
    last -20 2>/dev/null || echo -e "${C_WARN}last command unavailable${C_RST}"
    echo ""
    echo -e "${C_INFO}── Failed logins (last 20) ──${C_RST}"
    lastb -20 2>/dev/null || echo -e "${C_WARN}lastb command unavailable (requires root)${C_RST}"
    echo ""
    echo -e "${C_INFO}── Currently logged in users ──${C_RST}"
    who 2>/dev/null
    wait_key
}

emergency_cron() {
    echo -e "${C_WARN}>>> Suspicious cron job investigation <<<${C_RST}"
    echo -e "${C_INFO}── root crontab ──${C_RST}"
    crontab -l 2>/dev/null || echo -e "${C_WARN}No root crontab${C_RST}"
    echo ""
    echo -e "${C_INFO}── /etc/cron.d/ ──${C_RST}"
    ls -la /etc/cron.d/ 2>/dev/null
    echo ""
    echo -e "${C_INFO}── /etc/crontab ──${C_RST}"
    cat /etc/crontab 2>/dev/null || echo -e "${C_WARN}No /etc/crontab${C_RST}"
    echo ""
    echo -e "${C_INFO}── All user crontabs ──${C_RST}"
    while IFS= read -r user; do
        local cron
        cron=$(crontab -u "$user" -l 2>/dev/null) || continue
        [ -n "$cron" ] && echo -e "${C_WARN}$user:${C_RST}" && echo "$cron"
    done < <(cut -d: -f1 /etc/passwd 2>/dev/null)
    echo ""
    echo -e "${C_WARN}Check for: unknown script paths, suspicious download commands, non-standard schedule tasks${C_RST}"
    wait_key
}

incident_triage_menu() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   Incident forensics collection      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📦 Full collection (collect, read-only)"
        echo -e "  ${C_WARN}2.${C_RST} ⚡ Quick overview (quick)"
        echo -e "  ${C_WARN}3.${C_RST} 🛡️ Read-only audit (16 checks)"
        echo -e "  ${C_WARN}4.${C_RST} 🔍 Analyze archive (analyze)"
        echo -e "  ${C_WARN}5.${C_RST} 📋 Generate report (report)"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick sub
        read -r -p "Select [0-5]: " pick
        case $pick in
            1) incident_triage_run collect ;;
            2) incident_triage_run quick ;;
            3) incident_triage_run audit ;;
            4) read -r -p "Archive path: " sub; incident_triage_run analyze "$sub" ;;
            5) read -r -p "Archive path: " sub; incident_triage_run report "$sub" ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

incident_triage_run() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local triage_script="$script_dir/scripts/incident_triage.sh"
    [ ! -f "$triage_script" ] && triage_script="/usr/local/share/secure-vps/scripts/incident_triage.sh"
    if [ ! -f "$triage_script" ]; then
        echo -e "${C_FAIL}Cannot find incident_triage.sh${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Incident forensics collection <<<${C_RST}"
    echo -e "${C_INFO}Collection is read-only, no system modifications. Copy archives to offline trusted storage before analysis.${C_RST}"
    echo ""
    bash "$triage_script" "$@"
    wait_key
}

page_ops_docker() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Container Security       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        if command -v docker >/dev/null 2>&1; then
            echo -e "Status: ${C_OK}Installed${C_RST}"
        else
            echo -e "Status: ${C_FAIL}Not installed${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} 🐳 Docker engine (install/config/UFW fix)"
        echo -e "  ${C_WARN}2.${C_RST} 📦 Portainer (Web management panel)"
        echo -e "  ${C_WARN}3.${C_RST} 🔄 Watchtower (auto-update)"
        echo -e "  ${C_WARN}4.${C_RST} 🖥 1Panel (server panel)"
        echo -e "  ${C_WARN}5.${C_RST} 📋 Docker compliance audit (CIS Benchmark)"
        echo -e "  ${C_WARN}6.${C_RST} 🛠 Dockerfile hardening (analyze/fix)"
        echo -e "  ${C_WARN}7.${C_RST} ☸ K8s security audit (CIS Benchmark)"
        echo -e "  ${C_WARN}8.${C_RST} 🛡 Runtime security (Falco/Tetragon)"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-8]: " pick
        case $pick in
            1) page_docker ;;
            2) app_portainer_on ;;
            3) app_watch_on ;;
            4) page_1panel ;;
            5) docker_audit_run ;;
            6) dockerfile_hardener_run ;;
            7) k8s_audit_run ;;
            8) runtime_security_run ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_ops_monitor() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Security Monitoring       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📊 Uptime Kuma (uptime monitoring)"
        echo -e "  ${C_WARN}2.${C_RST} 📊 Real-time Resource Dashboard"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-2]: " pick
        case $pick in
            1) app_kuma_on ;;
            2) sys_pulse ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_ops_network() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Network Diagnostics       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🛰 Return route (NextTrace)"
        echo -e "  ${C_WARN}2.${C_RST} 🛡 IP quality score"
        echo -e "  ${C_WARN}3.${C_RST} 📺 Streaming unlock"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-3]: " pick
        case $pick in
            1) bench_route ;;
            2) bench_ip_score ;;
            3) bench_stream ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_ops_cloud() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Cloud Security           ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} ☁️ Cloud platform CIS baseline audit (auto-detect)"
        echo -e "  ${C_WARN}2.${C_RST} 📋 View detection rules"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-2]: " pick
        case $pick in
            1) cloud_cis_run ;;
            2) cloud_cis_rules ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

cloud_cis_run() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local cis_script="$script_dir/scripts/cloud_cis_baseline.sh"
    if [ ! -f "$cis_script" ]; then
        cis_script="/usr/local/share/secure-vps/scripts/cloud_cis_baseline.sh"
    fi
    if [ ! -f "$cis_script" ]; then
        echo -e "${C_FAIL}Cannot find cloud_cis_baseline.sh${C_RST}"
        echo -e "${C_INFO}Please run from repo, or ensure complete global installation.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Cloud platform CIS baseline audit <<<${C_RST}"
    echo -e "${C_INFO}Read-only mode, no cloud resources modified.${C_RST}"
    echo -e "${C_INFO}Auto-detect authenticated cloud CLIs (aws/gcloud/az).${C_RST}"
    echo -e "${C_INFO}Report will be saved to /var/log/cloud-cis-audit/${C_RST}"
    echo ""
    bash "$cis_script"
    wait_key
}

cloud_cis_rules() {
    echo -e "${C_WARN}>>> Cloud platform CIS detection rules <<<${C_RST}"
    echo ""
    echo -e "${C_INFO}── AWS CIS Foundations Benchmark ──${C_RST}"
    echo "  IAM:       12 checks (root keys, MFA, password policy, unused keys)"
    echo "  Network:   6 checks (SG open ports, VPC flow logs, default SG, NACLs)"
    echo "  Logging:   6 checks (CloudTrail, log validation, Config, S3 access logs)"
    echo "  Encryption: 4 checks (S3 SSE, EBS, RDS, KMS rotation)"
    echo ""
    echo -e "${C_INFO}── GCP CIS Foundation Benchmark ──${C_RST}"
    echo "  IAM:       4 checks (SA key age, user-managed keys, 2FA, owner role)"
    echo "  Network:   5 checks (firewall open ports, VPC flow logs, default network)"
    echo "  Logging:   3 checks (audit logs, admin read, data read)"
    echo "  Encryption: 3 checks (CMEK disks, Cloud SQL, GCS buckets)"
    echo ""
    echo -e "${C_INFO}── Azure CIS Foundation Benchmark ──${C_RST}"
    echo "  IAM:       4 checks (MFA privileged, guest accounts, custom owner, password)"
    echo "  Network:   4 checks (NSG open ports, Network Watcher)"
    echo "  Logging:   3 checks (activity log alerts, diagnostic settings)"
    echo "  Encryption: 3 checks (disk encryption, storage HTTPS, SQL TDE)"
    echo ""
    echo -e "${C_INFO}Run audit: secure-vps -> d5 -> 1${C_RST}"
    wait_key
}

page_ops_database() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Database Security       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🗄️ Database security audit (auto-detect)"
        echo -e "  ${C_WARN}2.${C_RST} 📋 Generate MySQL hardening config"
        echo -e "  ${C_WARN}3.${C_RST} 📋 Generate PostgreSQL hardening config"
        echo -e "  ${C_WARN}4.${C_RST} 📋 Generate Redis hardening config"
        echo -e "  ${C_WARN}5.${C_RST} 📋 Generate MongoDB hardening config"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-5]: " pick
        case $pick in
            1) db_hardening_run "--audit" ;;
            2) db_hardening_run "--mysql" ;;
            3) db_hardening_run "--postgres" ;;
            4) db_hardening_run "--redis" ;;
            5) db_hardening_run "--mongodb" ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

db_hardening_run() {
    local mode="$1"
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local db_script="$script_dir/scripts/database_hardening.sh"
    if [ ! -f "$db_script" ]; then
        db_script="/usr/local/share/secure-vps/scripts/database_hardening.sh"
    fi
    if [ ! -f "$db_script" ]; then
        echo -e "${C_FAIL}Cannot find database_hardening.sh${C_RST}"
        echo -e "${C_INFO}Please run from repo, or ensure complete global installation.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Database security hardening <<<${C_RST}"
    echo -e "${C_INFO}Audit mode is read-only, configuration generation does not directly modify running databases.${C_RST}"
    echo ""
    bash "$db_script" "$mode"
    wait_key
}

page_ops_bigdata() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Big data security       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📊 Big data security audit (Hadoop/Spark, read-only)"
        echo -e "  ${C_WARN}2.${C_RST} 🔐 Generate SSL certificates (CA + server + client)"
        echo -e "  ${C_WARN}3.${C_RST} 📋 Generate Hadoop SSL config"
        echo -e "  ${C_WARN}4.${C_RST} 📋 Generate Kafka SSL config"
        echo -e "  ${C_WARN}5.${C_RST} 📋 Generate HBase SSL config"
        echo -e "  ${C_WARN}6.${C_RST} 📋 Generate Cassandra SSL config"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-6]: " pick
        case $pick in
            1) bigdata_run "--audit" ;;
            2) bigdata_run "--generate" ;;
            3) bigdata_run "--hadoop" ;;
            4) bigdata_run "--kafka" ;;
            5) bigdata_run "--hbase" ;;
            6) bigdata_run "--cassandra" ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

bigdata_run() {
    local mode="$1"
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local bd_script
    if [ "$mode" = "--audit" ]; then
        bd_script="$script_dir/scripts/bigdata_security_audit.sh"
    else
        bd_script="$script_dir/scripts/bigdata_ssl_setup.sh"
    fi
    if [ ! -f "$bd_script" ]; then
        if [ "$mode" = "--audit" ]; then
            bd_script="/usr/local/share/secure-vps/scripts/bigdata_security_audit.sh"
        else
            bd_script="/usr/local/share/secure-vps/scripts/bigdata_ssl_setup.sh"
        fi
    fi
    if [ ! -f "$bd_script" ]; then
        echo -e "${C_FAIL}Cannot find big data security script${C_RST}"
        echo -e "${C_INFO}Please run from repo, or ensure complete global installation.${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Big data security <<<${C_RST}"
    echo -e "${C_INFO}Audit mode is read-only, configuration generation does not directly modify running services.${C_RST}"
    echo ""
    bash "$bd_script" "$mode"
    wait_key
}

page_ops_zerotrust() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}    Zero Trust Network       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🛡️ Audit zero trust config (read-only)"
        echo -e "  ${C_WARN}2.${C_RST} 📦 Install WireGuard"
        echo -e "  ${C_WARN}3.${C_RST} 📦 Install Headscale"
        echo -e "  ${C_WARN}4.${C_RST} 📋 Generate ACL config"
        echo -e "  ${C_WARN}5.${C_RST} 📋 Generate CrowdSec integration"
        echo -e "  ${C_WARN}6.${C_RST} 📋 Generate GeoIP filter"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-6]: " pick
        case $pick in
            1) zt_run "--audit" ;;
            2) zt_run "--install-wireguard" ;;
            3) zt_run "--install-headscale" ;;
            4) zt_run "--acl" ;;
            5) zt_run "--crowdsec" ;;
            6) zt_run "--geoip" ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

zt_run() {
    local mode="$1"
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local zt_script="$script_dir/scripts/zerotrust_setup.sh"
    [ ! -f "$zt_script" ] && zt_script="/usr/local/share/secure-vps/scripts/zerotrust_setup.sh"
    if [ ! -f "$zt_script" ]; then
        echo -e "${C_FAIL}Cannot find zero trust script${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Zero Trust Network <<<${C_RST}"
    echo -e "${C_INFO}Audit mode is read-only, installation/config generation does not directly modify running services.${C_RST}"
    echo ""
    bash "$zt_script" "$mode"
    wait_key
}

page_ops_waf() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}    WAF Deployment         ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🧱 Audit WAF config (read-only)"
        echo -e "  ${C_WARN}2.${C_RST} 📦 Install Coraza + CRS v4"
        echo -e "  ${C_WARN}3.${C_RST} 📋 Generate Caddy + Coraza config"
        echo -e "  ${C_WARN}4.${C_RST} 📋 Generate Nginx + Coraza config"
        echo -e "  ${C_WARN}5.${C_RST} 📋 Generate HAProxy + Coraza config"
        echo -e "  ${C_WARN}6.${C_RST} 📋 Generate rule tuning config"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-6]: " pick
        case $pick in
            1) waf_run "--audit" ;;
            2) waf_run "--install" ;;
            3) waf_run "--caddy" ;;
            4) waf_run "--nginx" ;;
            5) waf_run "--haproxy" ;;
            6) waf_run "--tune" ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

waf_run() {
    local mode="$1"
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local waf_script="$script_dir/scripts/waf_setup.sh"
    [ ! -f "$waf_script" ] && waf_script="/usr/local/share/secure-vps/scripts/waf_setup.sh"
    if [ ! -f "$waf_script" ]; then
        echo -e "${C_FAIL}Cannot find WAF script${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> WAF Deployment <<<${C_RST}"
    echo -e "${C_INFO}Audit mode is read-only, configuration generation does not directly modify running reverse proxies.${C_RST}"
    echo ""
    bash "$waf_script" "$mode"
    wait_key
}

page_ops_tls() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   TLS Certificate Lifecycle  ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🛡️ Audit TLS config (read-only)"
        echo -e "  ${C_WARN}2.${C_RST} 📦 Install acme.sh"
        echo -e "  ${C_WARN}3.${C_RST} 📊 Monitor certificate expiry"
        echo -e "  ${C_WARN}4.${C_RST} 🔄 Renew all certificates"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-4]: " pick
        case $pick in
            1) tls_run "--audit" ;;
            2) tls_run "--install" ;;
            3) tls_run "--monitor" ;;
            4) tls_run "--renew" ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

tls_run() {
    local mode="$1"
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local tls_script="$script_dir/scripts/tls_lifecycle.sh"
    [ ! -f "$tls_script" ] && tls_script="/usr/local/share/secure-vps/scripts/tls_lifecycle.sh"
    if [ ! -f "$tls_script" ]; then
        echo -e "${C_FAIL}Cannot find TLS script${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> TLS Certificate Lifecycle <<<${C_RST}"
    echo -e "${C_INFO}Audit mode is read-only, install/renew/monitor does not directly modify running reverse proxies.${C_RST}"
    echo ""
    bash "$tls_script" "$mode"
    wait_key
}

page_ops_secret_scan() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   Key and Secret Scanning     ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🛡️ Audit key management config (read-only)"
        echo -e "  ${C_WARN}2.${C_RST} 📦 Install gitleaks + trufflehog"
        echo -e "  ${C_WARN}3.${C_RST} 🔍 Quick scan (gitleaks)"
        echo -e "  ${C_WARN}4.${C_RST} 📜 Scan git history"
        echo -e "  ${C_WARN}5.${C_RST} 🏴 Deep scan (trufflehog verified)"
        echo -e "  ${C_WARN}6.${C_RST} 📋 Generate CI/pre-commit config"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-6]: " pick
        case $pick in
            1) secret_run "--audit" ;;
            2) secret_run "--install" ;;
            3) secret_run "--scan" ;;
            4) secret_run "--scan-git" ;;
            5) secret_run "--deep" ;;
            6) secret_run "--ci" ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

secret_run() {
    local mode="$1"
    local script_dir
    script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
    local secret_script="$script_dir/scripts/secret_scan.sh"
    [ ! -f "$secret_script" ] && secret_script="/usr/local/share/secure-vps/scripts/secret_scan.sh"
    if [ ! -f "$secret_script" ]; then
        echo -e "${C_FAIL}Cannot find key scanning script${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> Key and Secret Scanning <<<${C_RST}"
    echo -e "${C_INFO}Scanning is read-only, no files are modified. Deep scan sends verification requests to APIs.${C_RST}"
    echo ""
    bash "$secret_script" "$mode"
    wait_key
}

page_emergency_perf() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   Performance and Resources      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🧠 Enable BBR"
        echo -e "  ${C_WARN}2.${C_RST} 💾 Create Swap"
        echo -e "  ${C_WARN}3.${C_RST} 💾 Delete Swap"
        echo -e "  ${C_WARN}4.${C_RST} 📊 Real-time Resource Dashboard"
        echo -e "  ${C_WARN}5.${C_RST} 🥇 YABS (CPU/Disk)"
        echo -e "  ${C_WARN}6.${C_RST} 🌍 Bandwidth speed test (bench.sh)"
        echo -e "  ${C_WARN}7.${C_RST} 🏅 Comprehensive benchmark"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-7]: " pick
        case $pick in
            1) net_bbr_enable ;;
            2) mem_swap_build ;;
            3) mem_swap_drop ;;
            4) sys_pulse ;;
            5) bench_cpu_disk ;;
            6) bench_speed ;;
            7) bench_omni ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

auto_updates_on() {
    echo -e "${C_WARN}>>> Automatic security updates <<<${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        if ! eval "$PKG_INSTALL unattended-upgrades"; then
            echo -e "${C_FAIL}Installation failed, please check package repositories.${C_RST}"
            wait_key; return
        fi
        printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
            > /etc/apt/apt.conf.d/20auto-upgrades
        systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
        echo -e "${C_OK}Enabled: daily automatic security updates (unattended-upgrades).${C_RST}"
        echo -e "${C_WARN}Defaults to security source only; details in /var/log/unattended-upgrades/.${C_RST}"
        if ask_yes "Auto-reboot when needed (default 04:00, only kernel updates trigger)?"; then
            printf 'Unattended-Upgrade::Automatic-Reboot "true";\nUnattended-Upgrade::Automatic-Reboot-Time "04:00";\n' \
                > /etc/apt/apt.conf.d/52unattended-upgrades-reboot
            echo -e "${C_OK}Auto-reboot policy configured.${C_RST}"
        fi
    else
        if [ "$DISTRO" = "centos" ] && [ "$DISTRO_MAJOR" = "7" ]; then
            eval "$PKG_INSTALL yum-cron" || { echo -e "${C_FAIL}Failed to install yum-cron.${C_RST}"; wait_key; return; }
            sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf
            systemctl enable --now yum-cron >/dev/null 2>&1
            echo -e "${C_OK}yum-cron auto-update enabled.${C_RST}"
        else
            eval "$PKG_INSTALL dnf-automatic" || { echo -e "${C_FAIL}Failed to install dnf-automatic.${C_RST}"; wait_key; return; }
            sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
            systemctl enable --now dnf-automatic.timer >/dev/null 2>&1
            echo -e "${C_OK}dnf-automatic scheduled update enabled.${C_RST}"
        fi
        echo -e "${C_WARN}For security-only updates, change upgrade type to security yourself.${C_RST}"
    fi
    wait_key
}

lynis_audit() {
    echo -e "${C_WARN}>>> Lynis security audit <<<${C_RST}"
    if [[ "$DISTRO" =~ ^(centos|rhel|almalinux|rocky)$ ]]; then
        eval "$PKG_INSTALL epel-release > /dev/null 2>&1"
    fi
    if ! command -v lynis >/dev/null 2>&1; then
        echo -e "${C_INFO}Installing Lynis (distro repo version)...${C_RST}"
        if ! eval "$PKG_INSTALL lynis"; then
            echo -e "${C_FAIL}Installation failed, please check package repositories.${C_RST}"
            wait_key; return
        fi
    fi
    echo -e "${C_INFO}Starting audit (read-only, no system changes)...${C_RST}"
    lynis audit system --quick 2>/dev/null | tee /tmp/secure-vps-lynis.out >/dev/null
    echo ""
    echo -e "${C_WARN}>>> Results summary <<<${C_RST}"
    grep -E "Hardening index" /tmp/secure-vps-lynis.out | tail -n 1
    echo -e "Warnings:      $(grep -cE '^\s+- Warning' /tmp/secure-vps-lynis.out)"
    echo -e "Suggestions:   $(grep -cE '^\s+- Suggestion' /tmp/secure-vps-lynis.out)"
    echo ""
    echo -e "${C_OK}Main warnings (up to 10):${C_RST}"
    grep -E "^\s+- Warning" /tmp/secure-vps-lynis.out | head -n 10
    echo ""
    echo -e "${C_WARN}Full log: /var/log/lynis.log and /var/log/lynis-report.dat${C_RST}"
    echo -e "${C_WARN}Note: higher Hardening index is better, improve per Suggestions.${C_RST}"
    wait_key
}

page_integrity() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   AIDE Integrity      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        if command -v aide >/dev/null 2>&1; then
            echo -e "Status: ${C_OK}Installed${C_RST}"
        else
            echo -e "Status: ${C_FAIL}Not installed${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} Install and build baseline"
        echo -e "  ${C_WARN}2.${C_RST} Rebuild baseline (required after system upgrade)"
        echo -e "  ${C_WARN}3.${C_RST} Run check now"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-3]: " pick
        case $pick in
            1) integrity_seed ;;
            2) integrity_reseed ;;
            3) integrity_verify ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_docker() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}    Docker Engine     ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        if command -v docker >/dev/null 2>&1; then
            echo -e "Status: ${C_OK}Installed${C_RST}"
        else
            echo -e "Status: ${C_FAIL}Not installed${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} Install engine"
        echo -e "  ${C_WARN}2.${C_RST} Registry mirror and log rotation"
        echo -e "  ${C_WARN}3.${C_RST} 🔥 UFW takeover (fix port bypass)"
        echo -e "  ${C_WARN}4.${C_RST} Uninstall engine"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-4]: " pick
        case $pick in
            1) docker_engine_on ;;
            2) docker_registry_tune ;;
            3) docker_ufw_takeover ;;
            4) docker_engine_off ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_apps() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Container Apps      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
            echo -n "Status: "
            docker_up portainer   && echo -ne "${C_OK}Portainer✔${C_RST} " || echo -ne "${C_FAIL}Portainer✘${C_RST} "
            docker_up watchtower  && echo -ne "${C_OK}Watchtower✔${C_RST} " || echo -ne "${C_FAIL}Watchtower✘${C_RST} "
            docker_up uptime-kuma && echo -ne "${C_OK}Kuma✔${C_RST}\n"      || echo -ne "${C_FAIL}Kuma✘${C_RST}\n"
        else
            echo -e "Status: ${C_FAIL}Docker not installed or not running${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} Portainer (Web management panel)"
        echo -e "  ${C_WARN}2.${C_RST} Watchtower (auto-update)"
        echo -e "  ${C_WARN}3.${C_RST} Uptime Kuma (uptime monitoring)"
        echo -e "  ${C_WARN}4.${C_RST} Uninstall Portainer"
        echo -e "  ${C_WARN}5.${C_RST} Uninstall Watchtower"
        echo -e "  ${C_WARN}6.${C_RST} Uninstall Uptime Kuma"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-6]: " pick
        case $pick in
            1) app_portainer_on ;;
            2) app_watch_on ;;
            3) app_kuma_on ;;
            4) app_portainer_off ;;
            5) app_watch_off ;;
            6) app_kuma_off ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_1panel() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}      1Panel       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        if command -v 1pctl >/dev/null 2>&1; then
            echo -e "Status: ${C_OK}Installed${C_RST}"
        else
            echo -e "Status: ${C_FAIL}Not installed${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} Install"
        echo -e "  ${C_WARN}2.${C_RST} Uninstall"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-2]: " pick
        case $pick in
            1) app_1panel_on ;;
            2) app_1panel_off ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_deploy() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     App Deployment      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} Docker engine (install/mirror/UFW takeover/uninstall)"
        echo -e "  ${C_WARN}2.${C_RST} Container apps (Portainer/Watchtower/Uptime Kuma)"
        echo -e "  ${C_WARN}3.${C_RST} 1Panel panel"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-3]: " pick
        case $pick in
            1) page_docker ;;
            2) page_apps ;;
            3) page_1panel ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

page_bench() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     Monitoring and Benchmarking       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📊 Real-time Resource Dashboard"
        echo -e "  ${C_WARN}2.${C_RST} 🥇 YABS (CPU/Disk)"
        echo -e "  ${C_WARN}3.${C_RST} 🌍 Bandwidth speed test (bench.sh)"
        echo -e "  ${C_WARN}4.${C_RST} 📺 Streaming unlock"
        echo -e "  ${C_WARN}5.${C_RST} 🛰 Return route (NextTrace)"
        echo -e "  ${C_WARN}6.${C_RST} 🏅 Comprehensive benchmark"
        echo -e "  ${C_WARN}7.${C_RST} 🛡 IP quality score"
        echo -e "  ${C_WARN}0.${C_RST} Back"
        echo
        local pick
        read -r -p "Select [0-7]: " pick
        case $pick in
            1) sys_pulse ;;
            2) bench_cpu_disk ;;
            3) bench_speed ;;
            4) bench_stream ;;
            5) bench_route ;;
            6) bench_omni ;;
            7) bench_ip_score ;;
            0) break ;;
            *) echo -e "${C_FAIL}Invalid input${C_RST}"; sleep 1 ;;
        esac
    done
}

home_page() {
    while true; do
        clear
        local hint=""
        if [ -x /usr/local/bin/secure-vps ]; then
            hint=" ${C_WARN}[Type secure-vps anywhere to launch]${C_RST}"
        fi
        echo -e "${C_OK}   ❰ secure-vps ❱  VPS Security Enhancement Scripts  ${C_WARN}${APP_VER}${C_RST}"
        echo -e "${C_OK}══════════════════════════════════════${C_RST}"
        echo -e "${C_INFO}Host: ${PRETTY_NAME:-$DISTRO}${C_RST}$hint"
        echo ""
        echo -e "${C_INFO}▎A · Quick Access${C_RST}"
        echo -e "  ${C_FAIL}a1${C_RST} 🛡  Full security init (update+firewall+BBR+Swap+Fail2Ban+kernel)"
        echo -e "      ${C_WARN}(For new servers: kernel optimization, basic defense, virtual memory in one step)${C_RST}"
        echo ""
        echo -e "${C_INFO}▎B · Access Security${C_RST}"
        echo -e "  ${C_WARN}b1${C_RST} 🔐 SSH and Login"
        echo -e "  ${C_WARN}b2${C_RST} 🧱 Firewall"
        echo -e "  ${C_WARN}b3${C_RST} 🚫 Intrusion Blocking (Fail2Ban / CrowdSec)"
        echo -e "  ${C_WARN}b8${C_RST} 🛡️ Zero Trust Network (WireGuard/Headscale)"
        echo -e "  ${C_WARN}b9${C_RST} 🧱 WAF Deployment (Coraza/CRS v4)"
        echo -e "  ${C_WARN}b10${C_RST} 🔑 TLS Certificate Lifecycle (acme.sh)"
        echo -e "  ${C_WARN}b11${C_RST} 🕵️ Key and Secret Scanning (gitleaks/trufflehog)"
        echo ""
        echo -e "${C_INFO}▎C · Defense in Depth${C_RST}"
        echo -e "  ${C_WARN}c1${C_RST} 🩺 Baseline Check (read-only)"
        echo -e "  ${C_WARN}c2${C_RST} 🧱 Kernel hardening"
        echo -e "  ${C_WARN}c3${C_RST} 🔍 Audit and Integrity (auditd/AIDE/Rkhunter/Lynis)"
        echo -e "  ${C_WARN}c4${C_RST} 🔑 Password and Permissions (Password policy/sudo/User Management)"
        echo ""
        echo -e "${C_INFO}▎D · Security Operations${C_RST}"
        echo -e "  ${C_WARN}d1${C_RST} 🐳 Container Security (Docker/Portainer/Watchtower/1Panel)"
        echo -e "  ${C_WARN}d2${C_RST} 📊 Security Monitoring (Uptime Kuma/Resource Dashboard)"
        echo -e "  ${C_WARN}d3${C_RST} 🛰 Network Diagnostics (Route/IP Quality/Streaming)"
        echo -e "  ${C_WARN}d4${C_RST} 🧰 System tools (profile/timezone/DNS/cleanup)"
        echo -e "  ${C_WARN}d5${C_RST} ☁️ Cloud security (AWS/GCP/Azure CIS baseline)"
        echo -e "  ${C_WARN}d6${C_RST} 🗄️ Database security (MySQL/PG/Redis/Mongo)"
        echo -e "  ${C_WARN}d7${C_RST} 📊 Big data security (Hadoop/Spark SSL+audit)"
        echo ""
        echo -e "${C_INFO}▎E · Emergency and Recovery${C_RST}"
        echo -e "  ${C_WARN}e1${C_RST} 🚨 Emergency check (compromise investigation)"
        echo -e "  ${C_WARN}e2${C_RST} 📊 Performance and resources (benchmark/BBR/Swap)"
        echo ""
        echo -e "${C_INFO}▎Z · Maintenance${C_RST}"
        echo -e "  ${C_WARN}z1${C_RST} Install global command secure-vps"
        echo -e "  ${C_WARN}z2${C_RST} Remove global command"
        echo -e "  ${C_WARN}z3${C_RST} Check for updates"
        echo -e "   0  Exit"
        echo
        local pick
        read -r -p "❯ " pick
        pick=$(echo "$pick" | tr '[:upper:]' '[:lower:]')
        case $pick in
            a1)
                echo -e "${C_WARN}Full init will adjust firewall and kernel parameters.${C_RST}"
                read -r -p "Confirm? (y/N): " ack
                if [[ "$ack" =~ ^[Yy]$ ]]; then
                    pkg_upgrade_all
                    fw_init
                    net_bbr_enable
                    mem_swap_build
                    f2b_deploy
                    kernel_arm_core
                    echo -e "${C_OK}Full initialization complete (incl. kernel hardening).${C_RST}"
                    wait_key
                fi
                ;;
            b1) page_ssh ;;
            b2) page_fw ;;
            b3) page_intrusion ;;
            c1) page_shield_baseline ;;
            c2) page_shield_kernel ;;
            c3) page_shield_audit ;;
            c4) page_shield_access ;;
            d1) page_ops_docker ;;
            d2) page_ops_monitor ;;
            d3) page_ops_network ;;
            d4) page_toolbox ;;
            d5) page_ops_cloud ;;
            d6) page_ops_database ;;
            d7) page_ops_bigdata ;;
            b8) page_ops_zerotrust ;;
            b9) page_ops_waf ;;
            b10) page_ops_tls ;;
            b11) page_ops_secret_scan ;;
            e1) page_emergency ;;
            e2) page_emergency_perf ;;
            z1) secure_vps_alias_on ;;
            z2) secure_vps_alias_off ;;
            z3) secure_vps_self_update ;;
            0) clear; echo -e "${C_OK}Exited.${C_RST}"; exit 0 ;;
            *) echo -e "${C_FAIL}Invalid input!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ── Startup ─────────────────────────────────────────────────────
home_page
