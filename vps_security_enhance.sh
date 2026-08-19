#!/bin/bash
# ════════════════════════════════════════════════════════════
#  secure-vps — VPS Security Enhancement Scripts
#  适用系统: Ubuntu / Debian / CentOS / AlmaLinux / Rocky
#  运行身份: root
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts (MIT)
# ════════════════════════════════════════════════════════════

# ── [base] 颜色与全局标识 ────────────────────────────────────
C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'
APP_VER="v2.0.0"
UPSTREAM_URL="https://raw.githubusercontent.com/0x10debug/vps-security-enhancement-scripts/main/vps_security_enhance.sh"

# ── [base] 前置环境探测 ──────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${C_FAIL}权限不足: 请以 root 身份运行。${C_RST}"
    exit 1
fi

# /usr/sbin 下的管理工具纳入查找路径
command -v sshd >/dev/null 2>&1 || PATH="$PATH:/usr/sbin:/usr/local/sbin"

DISTRO=""
DISTRO_VER=""
DISTRO_MAJOR=""
PKG_UPGRADE=""
PKG_INSTALL=""
FW_KIND=""

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    DISTRO_VER=$VERSION_ID
    DISTRO_MAJOR=$(echo "$VERSION_ID" | cut -d. -f1)
else
    echo -e "${C_FAIL}无法识别操作系统 (缺少 /etc/os-release)。${C_RST}"
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
        echo -e "${C_FAIL}暂不支持该发行版 (支持 Ubuntu/Debian/CentOS/AlmaLinux/Rocky)。${C_RST}"
        exit 1
        ;;
esac

# ── [util] 交互辅助 ──────────────────────────────────────────
wait_key() {
    echo ""
    read -n 1 -s -r -p "敲任意键返回…"
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

# 修改前留快照, 时间戳后缀避免覆盖更早的快照
snapshot_file() {
    local f=$1
    if [ -f "$f" ]; then
        cp "$f" "${f}.orig-$(date +%Y%m%d%H%M%S)"
    fi
}

# ── [ssh] 配置写入与安全重载 ─────────────────────────────────
# 读取 sshd 实际生效端口 (sshd -T 优先, 兼容 Include 展开后的真实值)
ssh_port_live() {
    local p
    p=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')
    [ -z "$p" ] && p=$(grep -E "^Port " /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
    [ -z "$p" ] && p=22
    echo "$p"
}

ssh_opt_write() {
    local key=$1 val=$2
    # 先清除同键旧行 (含被注释的), 再追加唯一生效行
    sed -i "/^#*$key /d" /etc/ssh/sshd_config
    echo "$key $val" >> /etc/ssh/sshd_config
}

# 老版本 sshd 不认识的新指令仅在探测通过时写入
ssh_opt_write_safe() {
    local key=$1 val=$2
    if sshd -o "${key}=${val}" -T >/dev/null 2>&1; then
        ssh_opt_write "$key" "$val"
        return 0
    fi
    return 1
}

# 校验通过才重启; 校验失败自动回滚最近快照
ssh_apply_and_reload() {
    if sshd -t 2>/dev/null; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh
        return 0
    fi
    echo -e "${C_FAIL}sshd 配置校验未通过, 自动回滚最近快照…${C_RST}"
    ssh_config_rewind "auto"
    return 1
}

ssh_config_rewind() {
    local mode=$1 latest
    latest=$(ls -1t /etc/ssh/sshd_config.orig-* 2>/dev/null | head -n 1)
    if [ -z "$latest" ]; then
        echo -e "${C_FAIL}没有可用的配置快照, 无法回滚。${C_RST}"
        return 1
    fi
    [ "$mode" != "auto" ] && echo -e "${C_WARN}使用的快照: $latest${C_RST}"
    cp "$latest" /etc/ssh/sshd_config
    if sshd -t 2>/dev/null; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh
        # 回滚后端口可能变化, 同步 Fail2Ban 封禁端口避免脱节
        if [ -f /etc/fail2ban/jail.local ] && command -v fail2ban-client >/dev/null 2>&1; then
            local back_port
            back_port=$(ssh_port_live)
            sed -i -E "/^\[sshd\]/,/^\[/ s/^port[[:space:]]*=.*/port = $back_port/" /etc/fail2ban/jail.local
            systemctl restart fail2ban 2>/dev/null
        fi
        echo -e "${C_OK}已恢复该快照并重启 sshd。${C_RST}"
        return 0
    fi
    echo -e "${C_FAIL}快照内容也无法通过校验, 请手工检查 /etc/ssh/sshd_config${C_RST}"
    return 1
}

# ── [ui] 占比条 ──────────────────────────────────────────────
gauge() {
    local name=$1 pct=$2 tone i
    if   [ "$pct" -lt 50 ]; then tone=$C_OK
    elif [ "$pct" -lt 80 ]; then tone=$C_WARN
    else tone=$C_FAIL; fi
    local width=20
    local fill=$(( pct * width / 100 ))
    local blank=$(( width - fill ))
    printf "  %-10s ${C_INFO}│" "$name"
    for ((i=0; i<fill; i++)); do printf "${tone}▮${C_RST}"; done
    for ((i=0; i<blank; i++)); do printf "▯"; done
    printf "${C_INFO}│${tone} %s%%${C_RST}\n" "$pct"
}

# ── [fw] 面向各模块的放行封装 ────────────────────────────────
fw_grant_tcp() {
    local port=$1
    if [ "$FW_KIND" = "ufw" ]; then
        ufw allow ${port}/tcp
    else
        firewall-cmd --permanent --add-port=${port}/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
}

# ── [self] 全局命令别名 ──────────────────────────────────────
secure_vps_alias_on() {
    if [ -L /usr/local/bin/secure-vps ] || [ -f /usr/local/bin/secure-vps ]; then
        echo -e "${C_WARN}检测到已有 secure-vps 命令, 重建软链接…${C_RST}"
        rm -f /usr/local/bin/secure-vps
    fi
    echo -e "${C_INFO}正在安装全局命令 secure-vps (软链接方式)…${C_RST}"
    ln -sf "$(readlink -f "$0")" /usr/local/bin/secure-vps
    chmod +x /usr/local/bin/secure-vps
    if [ -x /usr/local/bin/secure-vps ]; then
        echo -e "${C_OK}完成。任意目录输入 secure-vps 即可唤起本工具。${C_RST}"
        echo -e "${C_WARN}提示: 软链接跟随源文件, 更新脚本后命令自动同步。${C_RST}"
    else
        echo -e "${C_FAIL}写入 /usr/local/bin 失败, 请检查权限。${C_RST}"
    fi
    wait_key
}

secure_vps_alias_off() {
    if [ ! -e /usr/local/bin/secure-vps ]; then
        echo -e "${C_WARN}未发现 secure-vps 全局命令。${C_RST}"
        wait_key; return
    fi
    if ask_yes "确认移除全局命令 secure-vps？"; then
        rm -f /usr/local/bin/secure-vps
        echo -e "${C_OK}已移除。脚本本体仍保留在当前目录。${C_RST}"
    fi
    wait_key
}

# ── [self] 自更新 (先校验后覆盖, 绝不让坏文件顶替本体) ───────
secure_vps_self_update() {
    echo -e "${C_INFO}正在查询上游版本…${C_RST}"
    local tmp remote_ver
    tmp=$(mktemp /tmp/secure-vps.XXXXXX)
    if ! curl -fsSL --max-time 30 "$UPSTREAM_URL" -o "$tmp" 2>/dev/null; then
        echo -e "${C_FAIL}连接 GitHub 失败或下载异常, 放弃更新。${C_RST}"
        rm -f "$tmp"; wait_key; return
    fi
    remote_ver=$(grep -m1 'APP_VER=' "$tmp" | cut -d '"' -f 2)
    if [ -z "$remote_ver" ]; then
        echo -e "${C_FAIL}下载内容缺少版本标识, 放弃更新。${C_RST}"
        rm -f "$tmp"; wait_key; return
    fi
    if [ "$APP_VER" = "$remote_ver" ]; then
        echo -e "${C_OK}已是最新版本 ($APP_VER)。${C_RST}"
        rm -f "$tmp"; wait_key; return
    fi
    echo -e "${C_WARN}发现新版本: $remote_ver (当前 $APP_VER)${C_RST}"
    if ask_yes "立即升级？"; then
        if ! bash -n "$tmp"; then
            echo -e "${C_FAIL}下载脚本未通过语法校验, 放弃覆盖。${C_RST}"
            rm -f "$tmp"; wait_key; return
        fi
        local self
        self=$(readlink -f "$0")
        if cp "$tmp" "$self" && chmod +x "$self"; then
            rm -f "$tmp"
            echo -e "${C_OK}升级完成, 正在重启工具…${C_RST}"
            sleep 2
            exec bash "$0"
        fi
        echo -e "${C_FAIL}覆盖脚本失败, 请检查磁盘与权限。${C_RST}"
        rm -f "$tmp"
    else
        rm -f "$tmp"
    fi
    wait_key
}

# ════════════════════════════════════════════════════════════
#  模块: SSH 与登录
# ════════════════════════════════════════════════════════════

pkg_upgrade_all() {
    echo -e "${C_INFO}开始升级系统软件包, 过程可能较长…${C_RST}"
    eval $PKG_UPGRADE
    echo -e "${C_OK}软件包升级完毕。${C_RST}"
    wait_key
}

ssh_port_shift() {
    local new_port
    read -r -p "输入新的 SSH 端口 (推荐 20000-60000): " new_port
    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${C_FAIL}端口必须是 1-65535 的数字。${C_RST}"
        wait_key; return
    fi
    if [ "$new_port" = "$(ssh_port_live)" ]; then
        echo -e "${C_WARN}与当前端口相同, 无需变更。${C_RST}"
        wait_key; return
    fi
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${new_port}$"; then
        echo -e "${C_FAIL}端口 $new_port 已被占用, 请换一个。${C_RST}"
        wait_key; return
    fi

    echo -e "${C_INFO}准备切换 SSH 端口…${C_RST}"

    # 先放行新端口再动配置, 避免自锁
    if [ "$FW_KIND" = "ufw" ]; then
        eval "$PKG_INSTALL ufw > /dev/null 2>&1"
        ufw allow $new_port/tcp
    else
        eval "$PKG_INSTALL firewalld > /dev/null 2>&1"
        systemctl start firewalld
        firewall-cmd --permanent --add-port=$new_port/tcp
        firewall-cmd --reload
    fi

    # SELinux Enforcing 时必须登记 ssh_port_t, 否则 sshd 无法监听新端口
    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
        if ! command -v semanage >/dev/null 2>&1; then
            echo -e "${C_INFO}检测到 SELinux Enforcing, 安装 semanage…${C_RST}"
            eval "$PKG_INSTALL policycoreutils-python-utils >/dev/null 2>&1" || \
            eval "$PKG_INSTALL policycoreutils-python >/dev/null 2>&1"
        fi
        if command -v semanage >/dev/null 2>&1; then
            semanage port -a -t ssh_port_t -p tcp $new_port 2>/dev/null || \
            semanage port -m -t ssh_port_t -p tcp $new_port 2>/dev/null
            echo -e "${C_OK}已在 SELinux 登记端口 $new_port。${C_RST}"
        else
            echo -e "${C_WARN}SELinux 开启但 semanage 不可用, 若重启失败需手工处理。${C_RST}"
        fi
    fi

    snapshot_file /etc/ssh/sshd_config
    ssh_opt_write "Port" "$new_port"

    if ssh_apply_and_reload; then
        # 确认 sshd 真实监听
        sleep 2
        if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${new_port}$"; then
            echo -e "${C_OK}已确认 sshd 监听新端口 $new_port。${C_RST}"
        else
            echo -e "${C_FAIL}未探测到 $new_port 的监听, 请保持当前窗口, 用旧端口排查!${C_RST}"
        fi
        # Fail2Ban 的封禁端口必须跟随, 否则封禁动作全部落空
        if [ -f /etc/fail2ban/jail.local ] && command -v fail2ban-client >/dev/null 2>&1; then
            sed -i -E "/^\[sshd\]/,/^\[/ s/^port[[:space:]]*=.*/port = $new_port/" /etc/fail2ban/jail.local
            systemctl restart fail2ban 2>/dev/null
            echo -e "${C_OK}Fail2Ban 封禁端口已同步为 $new_port。${C_RST}"
        fi
        echo -e "${C_OK}SSH 端口切换为 $new_port。${C_RST}"
        echo -e "${C_WARN}请勿关闭当前窗口, 新开终端验证连通后再收工!${C_RST}"
        echo -e "${C_WARN}提示: 旧端口的放行规则暂时保留, 验证后可自行删除。${C_RST}"
        echo -e "${C_WARN}提示: 云厂商安全组需同步放行 $new_port。${C_RST}"
    fi
    wait_key
}

ssh_keys_from_github() {
    local gh_user keys
    read -r -p "输入 GitHub 用户名: " gh_user
    if [ -z "$gh_user" ]; then
        echo -e "${C_FAIL}用户名不能为空。${C_RST}"; wait_key; return
    fi
    echo -e "${C_INFO}拉取 $gh_user 的公钥…${C_RST}"
    keys=$(curl -sL --max-time 20 "https://github.com/${gh_user}.keys")
    if [[ "$keys" == "Not Found" ]] || [[ -z "$keys" ]] || [[ "$keys" == *"<h1>"* ]]; then
        echo -e "${C_FAIL}未取得公钥, 请核对用户名及其 GitHub 公钥设置。${C_RST}"
        wait_key; return
    fi
    mkdir -p ~/.ssh && chmod 700 ~/.ssh
    echo "$keys" >> ~/.ssh/authorized_keys
    sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    echo -e "${C_OK}公钥导入完成。${C_RST}"

    read -r -p "现在就关闭密码登录仅保留密钥？(y/N, 建议先新开终端验证密钥可用) : " shut_pw
    if [[ "$shut_pw" =~ ^[Yy]$ ]]; then
        snapshot_file /etc/ssh/sshd_config
        ssh_opt_write "PasswordAuthentication" "no"
        ssh_opt_write "PubkeyAuthentication" "yes"
        ssh_opt_write_safe "KbdInteractiveAuthentication" "no"
        ssh_opt_write_safe "ChallengeResponseAuthentication" "no"
        if ssh_apply_and_reload; then
            echo -e "${C_OK}密码登录已关闭。${C_RST}"
            echo -e "${C_WARN}请新开终端确认密钥登录成功后再关闭本窗口!${C_RST}"
        fi
    else
        echo -e "${C_INFO}密码登录策略保持不变。${C_RST}"
    fi
    wait_key
}

ssh_baseline_pack() {
    echo -e "${C_INFO}将应用以下基线参数:${C_RST}"
    echo "  · MaxAuthTries 3           单连接认证上限 3 次"
    echo "  · LoginGraceTime 30        未完成登录 30 秒即断开"
    echo "  · ClientAliveInterval 120  每 2 分钟探测客户端"
    echo "  · ClientAliveCountMax 3    连续 3 次无响应断开"
    echo "  · X11Forwarding no         关闭图形转发"
    echo "  · UseDNS no                跳过反向 DNS, 加快握手"
    echo "  · PermitEmptyPasswords no  拒绝空密码"
    echo "  · StrictModes yes          校验密钥文件属主与权限"
    echo "  · GSSAPIAuthentication no  关闭 GSSAPI"
    if ! ask_yes "确认应用？"; then wait_key; return; fi

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
        echo -e "${C_OK}SSH 基线参数已生效。${C_RST}"
        echo -e "${C_WARN}说明: ClientAlive 仅作用于服务端会话保活, 不影响隧道类业务。${C_RST}"
    fi
    wait_key
}

ssh_lock_root_passwd() {
    echo -e "${C_INFO}将设置 PermitRootLogin prohibit-password:${C_RST}"
    echo -e "${C_INFO}root 仍可用密钥登录, 只是失去密码登录能力, 兼顾安全与可用。${C_RST}"
    if [ ! -s /root/.ssh/authorized_keys ]; then
        echo -e "${C_FAIL}注意: root 名下没有任何公钥!${C_RST}"
        echo -e "${C_FAIL}此时关闭密码登录等于放弃 root 入口, 建议先导入公钥。${C_RST}"
        if ! ask_yes "仍然继续？"; then wait_key; return; fi
    fi
    snapshot_file /etc/ssh/sshd_config
    ssh_opt_write "PermitRootLogin" "prohibit-password"
    if ssh_apply_and_reload; then
        echo -e "${C_OK}root 密码登录已封禁 (密钥不受影响)。${C_RST}"
        echo -e "${C_WARN}请新开终端验证密钥通路后再关闭本窗口!${C_RST}"
    fi
    wait_key
}

ssh_gate_users() {
    echo -e "${C_WARN}>>> SSH 登录白名单 (AllowUsers) <<<${C_RST}"
    local current input u bad
    current=$(sshd -T 2>/dev/null | awk '/^allowusers /{$1=""; print}' | sed 's/^ //')
    if [ -n "$current" ]; then
        echo -e "${C_INFO}当前白名单: $current${C_RST}"
    else
        echo -e "${C_INFO}尚未设置白名单 (全部有效用户都可尝试登录)。${C_RST}"
    fi
    read -r -p "输入允许登录的用户 (空格分隔, 直接回车=清空白名单): " input

    snapshot_file /etc/ssh/sshd_config
    if [ -z "$input" ]; then
        sed -i '/^AllowUsers /d' /etc/ssh/sshd_config
        if ssh_apply_and_reload; then
            echo -e "${C_OK}白名单已清空, 恢复默认策略。${C_RST}"
        fi
        wait_key; return
    fi

    # 先验证用户真实存在, 拼写错误直接取消, 防止整体锁死
    bad=""
    for u in $input; do
        id "$u" >/dev/null 2>&1 || bad="$bad $u"
    done
    if [ -n "$bad" ]; then
        echo -e "${C_FAIL}以下用户不存在:${bad} , 已取消 (防误锁)。${C_RST}"
        wait_key; return
    fi

    sed -i '/^AllowUsers /d' /etc/ssh/sshd_config
    echo "AllowUsers $input" >> /etc/ssh/sshd_config
    if ssh_apply_and_reload; then
        echo -e "${C_OK}白名单生效: 仅 $input 可登录。${C_RST}"
        echo -e "${C_WARN}请新开终端验证目标用户可正常登录后再关闭本窗口!${C_RST}"
    fi
    wait_key
}

# ════════════════════════════════════════════════════════════
#  模块: 防火墙
# ════════════════════════════════════════════════════════════

fw_init() {
    echo -e "${C_INFO}部署防火墙并放行基础端口 (SSH/80/443)…${C_RST}"
    local p; p=$(ssh_port_live)
    if [ "$FW_KIND" = "ufw" ]; then
        eval "$PKG_INSTALL ufw"
        ufw allow $p/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        echo "y" | ufw enable
    else
        eval "$PKG_INSTALL firewalld"
        systemctl enable firewalld
        systemctl start firewalld
        firewall-cmd --permanent --add-port=$p/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
    fi
    echo -e "${C_OK}防火墙已就位。${C_RST}"
    wait_key
}

fw_report() {
    echo -e "${C_WARN}>>> 防火墙当前状态与规则 <<<${C_RST}"
    if [ "$FW_KIND" = "ufw" ]; then
        ufw status verbose
    else
        firewall-cmd --list-all
    fi
    wait_key
}

fw_open() {
    local port
    read -r -p "输入要放行的端口 (如 8888 或 8888/tcp): " port
    [ -z "$port" ] && return
    [[ "$port" != *"/"* ]] && port="$port/tcp"
    echo -e "${C_INFO}放行 $port …${C_RST}"
    if [ "$FW_KIND" = "ufw" ]; then
        ufw allow $port
    else
        firewall-cmd --permanent --add-port=$port
        firewall-cmd --reload
    fi
    echo -e "${C_OK}$port 已放行。${C_RST}"
    wait_key
}

fw_reload() {
    if [ "$FW_KIND" = "ufw" ]; then ufw reload; else firewall-cmd --reload; fi
    echo -e "${C_OK}规则已重载。${C_RST}"
    wait_key
}

# ════════════════════════════════════════════════════════════
#  模块: Fail2Ban
# ════════════════════════════════════════════════════════════

f2b_deploy() {
    echo -e "${C_INFO}部署 Fail2Ban 防暴力破解…${C_RST}"
    # RHEL 家族需先启用 EPEL 源
    if [[ "$DISTRO" =~ ^(centos|rhel|almalinux|rocky)$ ]]; then
        eval "$PKG_INSTALL epel-release > /dev/null 2>&1"
    fi
    # Debian/Ubuntu 的 systemd 日志后端依赖
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        eval "$PKG_INSTALL python3-systemd > /dev/null 2>&1"
    fi
    if ! eval "$PKG_INSTALL fail2ban"; then
        echo -e "${C_FAIL}安装失败, 请检查软件源。${C_RST}"
        wait_key; return
    fi

    local p; p=$(ssh_port_live)

    # Ubuntu 最小化系统没有 rsyslog/auth.log, Debian/Ubuntu 显式走 systemd 后端
    # (CentOS 7 的旧版 fail2ban 不支持该后端, 维持默认读 /var/log/secure)
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
        echo -e "${C_OK}Fail2Ban 就绪: 5 次失败尝试封禁 24 小时。${C_RST}"
    else
        echo -e "${C_FAIL}Fail2Ban 启动异常, 最近日志:${C_RST}"
        journalctl -u fail2ban --no-pager -n 5 2>/dev/null
        echo -e "${C_WARN}可用 'fail2ban-client -d' 进一步排查。${C_RST}"
    fi
    wait_key
}

f2b_report() {
    echo -e "${C_WARN}>>> Fail2Ban 运行状态 <<<${C_RST}"
    systemctl status fail2ban --no-pager | grep Active
    echo ""
    echo -e "${C_WARN}>>> SSH jail 当前封禁名单 <<<${C_RST}"
    fail2ban-client status sshd 2>/dev/null || echo -e "${C_FAIL}取不到状态, 可能尚未部署。${C_RST}"
    wait_key
}

f2b_log_tail() {
    echo -e "${C_WARN}>>> 最近的拦截记录 <<<${C_RST}"
    tail -n 15 /var/log/fail2ban.log 2>/dev/null || echo "没有日志文件, 可能尚未部署。"
    wait_key
}

# ════════════════════════════════════════════════════════════
#  模块: 性能 (BBR / Swap)
# ════════════════════════════════════════════════════════════

net_bbr_enable() {
    echo -e "${C_INFO}检查 BBR…${C_RST}"
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        echo -e "${C_OK}BBR 已在运行, 无需重复配置。${C_RST}"
        wait_key; return
    fi
    # BBR 要求内核 4.9 以上
    if ! uname -r | awk -F. '{exit !($1>4 || ($1==4 && $2>=9))}'; then
        echo -e "${C_FAIL}内核 $(uname -r) 过旧 (需 4.9+)。${C_RST}"
        echo -e "${C_WARN}CentOS 7 默认 3.10, 请先安装 ELRepo 新内核再试。${C_RST}"
        wait_key; return
    fi
    modprobe tcp_bbr 2>/dev/null
    if ! grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        echo -e "${C_FAIL}内核未能加载 BBR 模块, 放弃配置。${C_RST}"
        wait_key; return
    fi
    # 独立配置文件, 避免污染主 sysctl.conf
    cat > /etc/sysctl.d/99-secure-vps-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl -p /etc/sysctl.d/99-secure-vps-bbr.conf >/dev/null 2>&1
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        echo -e "${C_OK}BBR 已开启。${C_RST}"
    else
        echo -e "${C_FAIL}参数写入后未生效, 请检查内核模块状态。${C_RST}"
    fi
    wait_key
}

mem_swap_build() {
    if swapon --show 2>/dev/null | grep -q "/"; then
        echo -e "${C_WARN}系统已有 Swap, 跳过。当前状态:${C_RST}"
        swapon --show
        wait_key; return
    fi
    echo -e "${C_WARN}>>> 新建 Swap (防突发内存耗尽) <<<${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} 512 MB"
    echo -e "  ${C_WARN}2.${C_RST} 1 GB ${C_OK}(推荐)${C_RST}"
    echo -e "  ${C_WARN}3.${C_RST} 2 GB"
    echo -e "  ${C_WARN}4.${C_RST} 4 GB"
    echo -e "  ${C_WARN}5.${C_RST} 自定义 (MB)"
    local choice mb
    read -r -p "❯ 选择容量 [2]: " choice
    choice=${choice:-2}
    case $choice in
        1) mb=512 ;;
        2) mb=1024 ;;
        3) mb=2048 ;;
        4) mb=4096 ;;
        5)
            read -r -p "输入容量 (MB): " mb
            if ! [[ "$mb" =~ ^[0-9]+$ ]] || [ "$mb" -lt 128 ] || [ "$mb" -gt 32768 ]; then
                echo -e "${C_FAIL}容量须在 128-32768 MB 之间。${C_RST}"
                wait_key; return
            fi
            ;;
        *) echo -e "${C_FAIL}无效选择。${C_RST}"; wait_key; return ;;
    esac

    # 磁盘余量检查: 预留 30% 冗余
    local avail_kb need_kb
    avail_kb=$(df / | awk 'NR==2{print $4}')
    need_kb=$(( mb * 1024 ))
    if [ "$avail_kb" -lt $(( need_kb * 13 / 10 )) ]; then
        echo -e "${C_FAIL}磁盘剩余不足 (需 ${mb}MB), 请先清理。${C_RST}"
        wait_key; return
    fi

    echo -e "${C_INFO}创建 ${mb}MB Swap 文件…${C_RST}"
    fallocate -l ${mb}M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=$mb status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    if ! swapon /swapfile; then
        echo -e "${C_FAIL}swapon 失败 (部分虚拟化平台不支持文件 Swap), 已清理临时文件。${C_RST}"
        rm -f /swapfile
        wait_key; return
    fi
    grep -q "^/swapfile" /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
    # 降低换出倾向, 优先用物理内存
    printf 'vm.swappiness = 10\n' > /etc/sysctl.d/99-secure-vps-swap.conf
    sysctl -p /etc/sysctl.d/99-secure-vps-swap.conf >/dev/null 2>&1
    echo -e "${C_OK}Swap ${mb}MB 建好并已写入开机挂载 (swappiness=10)。${C_RST}"
    wait_key
}

mem_swap_drop() {
    if ! swapon --show 2>/dev/null | grep -q "/swapfile"; then
        echo -e "${C_WARN}没有发现本工具创建的 /swapfile。${C_RST}"
        wait_key; return
    fi
    if ! ask_yes "确认删除 /swapfile？"; then wait_key; return; fi
    swapoff /swapfile
    sed -i '\|^/swapfile|d' /etc/fstab
    rm -f /swapfile
    rm -f /etc/sysctl.d/99-secure-vps-swap.conf
    sysctl -w vm.swappiness=60 >/dev/null 2>&1
    echo -e "${C_OK}Swap 已删除, fstab 与 swappiness 已还原。${C_RST}"
    wait_key
}

# ════════════════════════════════════════════════════════════
#  模块: 用户
# ════════════════════════════════════════════════════════════

user_add_admin() {
    echo -e "${C_WARN}>>> 创建带 sudo 权限的普通用户 <<<${C_RST}"
    local name
    read -r -p "输入新用户名: " name
    if [ -z "$name" ]; then
        echo -e "${C_FAIL}用户名不能为空。${C_RST}"; wait_key; return
    fi
    if id "$name" &>/dev/null; then
        echo -e "${C_WARN}用户 $name 已存在。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}创建用户 $name …${C_RST}"
    if ! useradd -m -s /bin/bash "$name"; then
        echo -e "${C_FAIL}创建失败, 请查看系统日志。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}为 $name 设置登录密码:${C_RST}"
    passwd "$name"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        usermod -aG sudo "$name"
    else
        usermod -aG wheel "$name"
    fi
    echo -e "${C_OK}用户 $name 建好并已获得 sudo 权限。${C_RST}"
    echo -e "${C_WARN}建议日常以该用户登录, 需要时再用 sudo。${C_RST}"
    wait_key
}

user_roster() {
    echo -e "${C_INFO}系统中的普通用户:${C_RST}"
    awk -F: '($3>=1000 && $1!="nobody") {print $1}' /etc/passwd
    wait_key
}

user_drop() {
    local name
    read -r -p "输入要删除的用户名: " name
    if [ -z "$name" ]; then
        echo -e "${C_FAIL}用户名不能为空。${C_RST}"; wait_key; return
    fi
    if ! id "$name" &>/dev/null; then
        echo -e "${C_FAIL}用户 $name 不存在。${C_RST}"; wait_key; return
    fi
    if [ "$name" = "root" ]; then
        echo -e "${C_FAIL}root 不可删除。${C_RST}"; wait_key; return
    fi
    echo -e "${C_WARN}将删除用户 $name 及其家目录, 不可恢复!${C_RST}"
    read -r -p "确认？(y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        userdel -r "$name"
        echo -e "${C_OK}用户 $name 已删除。${C_RST}"
    else
        echo -e "${C_INFO}已取消。${C_RST}"
    fi
    wait_key
}

# ════════════════════════════════════════════════════════════
#  模块: 工具箱
# ════════════════════════════════════════════════════════════

sys_identity() {
    clear
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_INFO}        🖥  主机档案           ${C_RST}"
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_OK}▸ 基本信息:${C_RST}"
    echo "  系统:     ${PRETTY_NAME:-$DISTRO $DISTRO_VER}"
    echo "  内核:     $(uname -r)"
    echo "  架构:     $(uname -m)"
    echo "  处理器:   $(lscpu 2>/dev/null | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}') ($(/usr/bin/nproc 2>/dev/null || echo ?) 核)"
    local virt; virt=$(systemd-detect-virt 2>/dev/null)
    [ -z "$virt" ] && virt="物理机/未知"
    echo "  虚拟化:   $virt"
    echo "  SSH 端口: $(ssh_port_live)"
    echo "  已运行:   $(uptime -p)"
    echo ""
    echo -e "${C_OK}▸ 资源水位:${C_RST}"
    local cpu mem_t mem_u mem_p disk_p
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | awk '{printf "%.0f", $1}')
    gauge "CPU" "$cpu"
    mem_t=$(free | grep Mem | awk '{print $2}')
    mem_u=$(free | grep Mem | awk '{print $3}')
    mem_p=$(( mem_u * 100 / mem_t ))
    gauge "内存" "$mem_p"
    disk_p=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    gauge "磁盘" "$disk_p"
    echo ""
    echo -e "${C_OK}▸ 公网出口:${C_RST}"
    local ipinfo
    ipinfo=$(curl -s --max-time 8 "http://ip-api.com/line?lang=zh-CN&fields=status,country,city,isp,query" 2>/dev/null)
    if [ "$(echo "$ipinfo" | head -n 1)" = "success" ]; then
        echo "$ipinfo" | tail -n 4 | awk 'NR==1{print "  归属地:   "$1} NR==2{print "  城市:     "$1} NR==3{print "  运营商:   "$1} NR==4{print "  IP:       "$1}'
    else
        echo -e "  ${C_WARN}查询超时或网络受限, 可稍后重试。${C_RST}"
    fi
    wait_key
}

sys_timezone() {
    echo -e "${C_WARN}>>> 时区设置 (当前: $(timedatectl 2>/dev/null | grep 'Time zone' | awk '{print $3}')) <<<${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} Asia/Shanghai     (上海 UTC+8)"
    echo -e "  ${C_WARN}2.${C_RST} Asia/Hong_Kong    (香港 UTC+8)"
    echo -e "  ${C_WARN}3.${C_RST} Asia/Tokyo        (东京 UTC+9)"
    echo -e "  ${C_WARN}4.${C_RST} Asia/Singapore    (新加坡 UTC+8)"
    echo -e "  ${C_WARN}5.${C_RST} Europe/London     (伦敦)"
    echo -e "  ${C_WARN}6.${C_RST} America/New_York  (纽约)"
    echo -e "  ${C_WARN}7.${C_RST} UTC"
    echo -e "  ${C_WARN}8.${C_RST} 自定义 tz 名称"
    local pick tz
    read -r -p "❯ 选择 [1-8]: " pick
    case $pick in
        1) tz="Asia/Shanghai" ;;
        2) tz="Asia/Hong_Kong" ;;
        3) tz="Asia/Tokyo" ;;
        4) tz="Asia/Singapore" ;;
        5) tz="Europe/London" ;;
        6) tz="America/New_York" ;;
        7) tz="UTC" ;;
        8) read -r -p "输入时区名 (如 Asia/Shanghai): " tz ;;
        *) echo -e "${C_FAIL}无效选择。${C_RST}"; wait_key; return ;;
    esac
    if ! timedatectl set-timezone "$tz" 2>/dev/null; then
        echo -e "${C_FAIL}设置失败, 请确认时区名有效。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_OK}时区已切换为 $tz, 当前时间 $(date '+%Y-%m-%d %H:%M:%S')。${C_RST}"
    wait_key
}

sys_clock_sync() {
    echo -e "${C_INFO}开启 NTP 时间同步…${C_RST}"
    timedatectl set-ntp true 2>/dev/null
    sleep 1
    timedatectl | grep -E "Local time|Universal|Time zone|System clock|NTP"
    if timedatectl show -p NTP 2>/dev/null | grep -q '=yes'; then
        echo -e "${C_OK}时间同步服务已开启。${C_RST}"
    else
        echo -e "${C_WARN}内置 NTP 未激活, 尝试改用 chrony…${C_RST}"
        eval "$PKG_INSTALL chrony > /dev/null 2>&1" && systemctl enable --now chronyd 2>/dev/null
        if command -v chronyd >/dev/null 2>&1; then
            echo -e "${C_OK}chrony 已安装并启动。${C_RST}"
        else
            echo -e "${C_FAIL}chrony 安装失败, 请手工处理时间同步。${C_RST}"
        fi
    fi
    wait_key
}

sys_dns_switch() {
    echo -e "${C_WARN}>>> 切换系统 DNS <<<${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} Cloudflare   1.1.1.1 / 1.0.0.1"
    echo -e "  ${C_WARN}2.${C_RST} Google       8.8.8.8 / 8.8.4.4"
    echo -e "  ${C_WARN}3.${C_RST} Quad9        9.9.9.9 / 149.112.112.112"
    echo -e "  ${C_WARN}4.${C_RST} 阿里 DNS     223.5.5.5 / 223.6.6.6"
    echo -e "  ${C_WARN}5.${C_RST} 腾讯 DNSPod  119.29.29.29 / 119.28.28.28"
    echo -e "  ${C_WARN}6.${C_RST} 自定义 (多个用空格分隔)"
    local pick servers ns
    read -r -p "❯ 选择 [1-6]: " pick
    case $pick in
        1) servers="1.1.1.1 1.0.0.1" ;;
        2) servers="8.8.8.8 8.8.4.4" ;;
        3) servers="9.9.9.9 149.112.112.112" ;;
        4) servers="223.5.5.5 223.6.6.6" ;;
        5) servers="119.29.29.29 119.28.28.28" ;;
        6) read -r -p "输入 DNS 服务器: " servers ;;
        *) echo -e "${C_FAIL}无效选择。${C_RST}"; wait_key; return ;;
    esac
    if [ -z "$servers" ]; then
        echo -e "${C_FAIL}DNS 不能为空。${C_RST}"; wait_key; return
    fi

    # systemd-resolved 环境改上游配置; 其余直接写 resolv.conf
    if systemctl is-active --quiet systemd-resolved 2>/dev/null || [ -L /etc/resolv.conf ]; then
        echo -e "${C_INFO}检测到 systemd-resolved, 修改上游 DNS…${C_RST}"
        snapshot_file /etc/systemd/resolved.conf
        sed -i -E '/^#?DNS=.*/d' /etc/systemd/resolved.conf
        echo "DNS=$servers" >> /etc/systemd/resolved.conf
        systemctl restart systemd-resolved
        echo -e "${C_OK}上游 DNS 已切换为: $servers${C_RST}"
        echo -e "${C_WARN}本机仍经 127.0.0.53 代理查询, 上游已生效。${C_RST}"
    else
        snapshot_file /etc/resolv.conf
        # 此前可能被本功能锁过, 先解锁再重写
        chattr -i /etc/resolv.conf 2>/dev/null
        : > /etc/resolv.conf
        for ns in $servers; do echo "nameserver $ns" >> /etc/resolv.conf; done
        echo -e "${C_OK}系统 DNS 已切换为: $servers${C_RST}"
        if ask_yes "锁定 /etc/resolv.conf 防止被 DHCP 覆盖？(再次修改时本功能会自动解锁)"; then
            chattr +i /etc/resolv.conf
            echo -e "${C_OK}已锁定。${C_RST}"
        fi
    fi
    wait_key
}

sys_root_key() {
    echo -e "${C_WARN}>>> 重设 root 密码 <<<${C_RST}"
    echo -e "${C_WARN}建议 16 位以上随机值; 配合密钥登录时可仅作应急备用。${C_RST}"
    passwd root
    wait_key
}

net_tcp_ping() {
    local host port tmo
    read -r -p "目标 IP 或域名: " host
    read -r -p "目标端口: " port
    read -r -p "超时秒数 [3]: " tmo
    tmo=${tmo:-3}
    if [ -z "$host" ] || ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo -e "${C_FAIL}输入无效。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}探测 ${host}:${port} (超时 ${tmo}s)…${C_RST}"
    if timeout "$tmo" bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "${C_OK}✔ 端口开放, 连接成功。${C_RST}"
    else
        echo -e "${C_FAIL}✘ 连不上 (端口关闭/服务未起/被墙或被防火墙拦截)。${C_RST}"
    fi
    wait_key
}

sys_login_trail() {
    echo -e "${C_WARN}>>> 最近 15 次成功登录 <<<${C_RST}"
    last -n 15 2>/dev/null | head -n 16 || echo -e "${C_FAIL}读不到登录记录。${C_RST}"
    echo ""
    echo -e "${C_WARN}>>> 最近 15 次失败尝试 (爆破痕迹) <<<${C_RST}"
    if lastb -n 15 2>/dev/null | head -n 16; then
        local total; total=$(lastb 2>/dev/null | grep -c "^[[:alnum:]_-]")
        echo ""
        echo -e "${C_INFO}失败登录总计: $total 次${C_RST}"
        [ "$total" -gt 100 ] && echo -e "${C_WARN}失败次数偏高, 建议确认 Fail2Ban 与密钥登录均已就位。${C_RST}"
    else
        echo -e "${C_FAIL}读不到失败记录 (需要 btmp 权限)。${C_RST}"
    fi
    wait_key
}

sys_sweep() {
    echo -e "${C_WARN}>>> 系统瘦身清理 <<<${C_RST}"
    echo -e "${C_INFO}清理前磁盘: $(df -h / | tail -1 | awk '{print "已用 "$3" / 可用 "$4}')${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        apt-get clean
        echo -e "${C_OK}apt 缓存已清空。${C_RST}"
    else
        yum clean all >/dev/null 2>&1
        echo -e "${C_OK}yum 缓存已清空。${C_RST}"
    fi
    journalctl --vacuum-time=7d 2>/dev/null | tail -n 1
    if ask_yes "执行 autoremove 清理孤立依赖与旧内核包？"; then
        if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
            apt-get autoremove --purge -y >/dev/null 2>&1
        else
            yum autoremove -y >/dev/null 2>&1
        fi
        echo -e "${C_OK}孤立依赖已清理。${C_RST}"
    fi
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        if ask_yes "检测到 Docker, 清理无用镜像/容器/缓存？(数据卷不动)"; then
            docker system prune -af 2>/dev/null | tail -n 1
        fi
    fi
    echo -e "${C_INFO}清理后磁盘: $(df -h / | tail -1 | awk '{print "已用 "$3" / 可用 "$4}')${C_RST}"
    wait_key
}

# ════════════════════════════════════════════════════════════
#  模块: 纵深防御
# ════════════════════════════════════════════════════════════

KERNEL_CONF_FILE="/etc/sysctl.d/99-secure-vps-kernel.conf"

kernel_arm_core() {
    cat > "$KERNEL_CONF_FILE" <<EOF
# secure-vps 内核加固 (SYN Cookie / 反欺骗 / 信息收敛)
# 取自 CIS 基线中适配 VPS 场景的保守子集
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
    echo -e "${C_OK}内核加固参数已写入 $KERNEL_CONF_FILE 并加载。${C_RST}"
    echo -e "${C_WARN}说明: rp_filter 用宽松模式(2), 兼容多 IP/策略路由场景。${C_RST}"
    echo -e "${C_WARN}说明: ptrace_scope=1 限制非父进程调试, 普通用户 strace 会受限, 属预期。${C_RST}"
}

kernel_arm() {
    echo -e "${C_WARN}>>> 内核参数加固 <<<${C_RST}"
    echo -e "${C_INFO}内容: SYN Cookie、拒绝 ICMP 重定向与源路由、SYN 积压扩容、内核信息收敛。${C_RST}"
    echo -e "${C_INFO}全部为保守参数, 不影响正常业务。${C_RST}"
    if [ -f "$KERNEL_CONF_FILE" ]; then
        echo -e "${C_WARN}已有加固配置, 将覆盖更新。${C_RST}"
    fi
    if ask_yes "确认应用？"; then
        kernel_arm_core
    fi
    wait_key
}

kernel_disarm() {
    if [ ! -f "$KERNEL_CONF_FILE" ]; then
        echo -e "${C_WARN}没有加固配置文件, 无需撤销。${C_RST}"
        wait_key; return
    fi
    if ask_yes "确认撤销加固并恢复系统默认参数？"; then
        rm -f "$KERNEL_CONF_FILE"
        sysctl --system >/dev/null 2>&1
        echo -e "${C_OK}加固文件已移除, 内核参数已按其余配置重载。${C_RST}"
    fi
    wait_key
}

passwd_quality() {
    echo -e "${C_WARN}>>> 密码强度策略 (pwquality) <<<${C_RST}"
    echo -e "${C_INFO}新密码须至少 12 位, 且大写/小写/数字/符号各含其一。${C_RST}"
    echo -e "${C_WARN}只约束之后设置的密码, 不强制改已有的。${C_RST}"
    if ! ask_yes "确认应用？"; then wait_key; return; fi
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        eval "$PKG_INSTALL libpam-pwquality" || { echo -e "${C_FAIL}安装失败。${C_RST}"; wait_key; return; }
    else
        eval "$PKG_INSTALL libpwquality" || { echo -e "${C_FAIL}安装失败。${C_RST}"; wait_key; return; }
    fi
    snapshot_file /etc/security/pwquality.conf
    cat > /etc/security/pwquality.conf <<EOF
# secure-vps 密码强度策略
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
usercheck = 1
enforcing = 1
EOF
    echo -e "${C_OK}策略生效: 新密码至少 12 位, 四类字符各一。${C_RST}"
    wait_key
}

sudo_guard() {
    if ! command -v visudo >/dev/null 2>&1; then
        echo -e "${C_FAIL}没有 sudo 环境 (visudo 缺失), 无法配置。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> sudo 审计 <<<${C_RST}"
    echo -e "${C_INFO}内容: sudo 命令全量记录到 /var/log/sudo.log, 并启用 use_pty。${C_RST}"
    if ! ask_yes "确认应用？"; then wait_key; return; fi
    cat > /etc/sudoers.d/95-secure-vps-audit <<EOF
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
EOF
    chmod 0440 /etc/sudoers.d/95-secure-vps-audit
    # sudoers 写错会锁死整个提权体系, 必须先校验再保留
    if visudo -cf /etc/sudoers.d/95-secure-vps-audit >/dev/null 2>&1; then
        echo -e "${C_OK}sudo 审计已开启 (日志 /var/log/sudo.log)。${C_RST}"
    else
        rm -f /etc/sudoers.d/95-secure-vps-audit
        echo -e "${C_FAIL}校验未通过, 已撤销写入以保住 sudo。${C_RST}"
    fi
    wait_key
}

rootkit_watch() {
    echo -e "${C_WARN}>>> Rkhunter Rootkit 防御 <<<${C_RST}"
    if [[ "$DISTRO" =~ ^(centos|rhel|almalinux|rocky)$ ]]; then
        eval "$PKG_INSTALL epel-release > /dev/null 2>&1"
    fi
    if ! command -v rkhunter >/dev/null 2>&1; then
        echo -e "${C_INFO}安装 rkhunter…${C_RST}"
        eval "$PKG_INSTALL rkhunter" || { echo -e "${C_FAIL}安装失败。${C_RST}"; wait_key; return; }
    fi
    rkhunter --update >/dev/null 2>&1
    # 以当前文件属性建基线, 大幅减少后续误报
    rkhunter --propupd >/dev/null 2>&1
    cat > /etc/cron.d/secure-vps-rkhunter <<EOF
# secure-vps: 每日 00:00 rootkit 巡检
0 0 * * * root /usr/bin/rkhunter --check --sk --report-warnings-only >> /var/log/rkhunter-cron.log 2>&1
EOF
    chmod 644 /etc/cron.d/secure-vps-rkhunter
    echo -e "${C_OK}就绪: 基线已建, 每日 00:00 自动巡检 (日志 /var/log/rkhunter-cron.log)。${C_RST}"
    if ask_yes "现在跑一次首扫 (约 1-3 分钟)？"; then
        rkhunter --check --sk
    fi
    wait_key
}

integrity_seed() {
    echo -e "${C_WARN}>>> AIDE 文件完整性监控 <<<${C_RST}"
    echo -e "${C_INFO}原理: 建立系统文件摘要基线, 每日比对, 发现篡改即刻留痕。${C_RST}"
    echo -e "${C_WARN}初次建基线与升级后重建都需要几分钟, 属正常耗时。${C_RST}"
    if ! ask_yes "确认安装并建基线？"; then wait_key; return; fi
    eval "$PKG_INSTALL aide" || { echo -e "${C_FAIL}安装失败。${C_RST}"; wait_key; return; }
    echo -e "${C_INFO}建立初始基线 (期间请勿安装其他软件)…${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        aideinit -y -f >/dev/null 2>&1
    else
        aide --init >/dev/null 2>&1
        mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null
    fi
    cat > /etc/cron.d/secure-vps-aide <<EOF
# secure-vps: 每日 03:00 完整性比对
0 3 * * * root /usr/sbin/aide --check >> /var/log/aide-cron.log 2>&1
EOF
    chmod 644 /etc/cron.d/secure-vps-aide
    echo -e "${C_OK}基线就绪, 每日 03:00 自动比对 (日志 /var/log/aide-cron.log)。${C_RST}"
    echo -e "${C_WARN}重要: 每次系统升级后请执行「重建基线」, 否则误报刷屏。${C_RST}"
    wait_key
}

integrity_reseed() {
    if ! command -v aide >/dev/null 2>&1; then
        echo -e "${C_FAIL}尚未安装 AIDE。${C_RST}"; wait_key; return
    fi
    echo -e "${C_INFO}按当前系统状态重建基线 (系统升级后必须做)…${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        aideinit -y -f >/dev/null 2>&1
    else
        aide --init >/dev/null 2>&1
        mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null
    fi
    echo -e "${C_OK}基线已重建。${C_RST}"
    wait_key
}

integrity_verify() {
    if ! command -v aide >/dev/null 2>&1; then
        echo -e "${C_FAIL}尚未安装 AIDE。${C_RST}"; wait_key; return
    fi
    echo -e "${C_INFO}执行完整性比对 (可能数分钟)…${C_RST}"
    aide --check
    wait_key
}

auditd_install() {
    echo -e "${C_WARN}>>> auditd 审计规则 <<<${C_RST}"
    echo -e "${C_INFO}覆盖: 账户文件、sudoers、计划任务、SSH 与内核配置——提权与持久化的必经之路。${C_RST}"
    if ! ask_yes "确认安装并加载规则？"; then wait_key; return; fi
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        eval "$PKG_INSTALL auditd" || { echo -e "${C_FAIL}安装失败。${C_RST}"; wait_key; return; }
    else
        eval "$PKG_INSTALL audit" || { echo -e "${C_FAIL}安装失败。${C_RST}"; wait_key; return; }
    fi
    cat > /etc/audit/rules.d/95-secure-vps.rules <<EOF
# secure-vps 审计规则
# 账户与权限
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
# 计划任务 (持久化高发区)
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
# SSH 与内核配置
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
EOF
    augenrules --load >/dev/null 2>&1
    systemctl enable auditd >/dev/null 2>&1
    systemctl restart auditd 2>/dev/null
    echo -e "${C_OK}规则已加载 (identity/sudoers/cron/sshd/sysctl 五类)。${C_RST}"
    echo -e "${C_INFO}查询示例: ausearch -k sudoers | head -20${C_RST}"
    wait_key
}

services_trim() {
    echo -e "${C_WARN}>>> 收缩攻击面 <<<${C_RST}"
    echo -e "${C_INFO}目标: avahi(局域网发现)、cups(打印)、bluetooth、ModemManager(调制解调器)。${C_RST}"
    echo -e "${C_INFO}服务器场景基本用不到; 有特殊需求请取消。${C_RST}"
    if ! ask_yes "确认停用并禁止自启？"; then wait_key; return; fi
    local s
    for s in avahi-daemon cups bluetooth ModemManager; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${s}.service"; then
            if systemctl disable --now "$s" >/dev/null 2>&1; then
                echo -e "${C_OK}已停用 $s。${C_RST}"
            else
                echo -e "${C_WARN}$s 停用失败, 可能本就未运行。${C_RST}"
            fi
        else
            echo -e "${C_INFO}未安装 $s, 跳过。${C_RST}"
        fi
    done
    systemctl mask ctrl-alt-del.target >/dev/null 2>&1
    echo -e "${C_OK}ctrl-alt-del 组合键重启已屏蔽。${C_RST}"
    if ! grep -q "nospoof" /etc/host.conf 2>/dev/null; then
        snapshot_file /etc/host.conf
        echo "nospoof on" >> /etc/host.conf
        echo -e "${C_OK}/etc/host.conf 已启用 nospoof。${C_RST}"
    fi
    wait_key
}

# ── [scan] 基线体检 ──────────────────────────────────────────
SCAN_OK=0
SCAN_WARN=0
SCAN_FAIL=0
SCAN_REPORT=""

note_check() {
    local name=$1 status=$2 msg=$3 tone tag
    case $status in
        PASS) SCAN_OK=$((SCAN_OK+1));   tone=$C_OK;   tag="[通过]" ;;
        WARN) SCAN_WARN=$((SCAN_WARN+1)); tone=$C_WARN; tag="[警告]" ;;
        FAIL) SCAN_FAIL=$((SCAN_FAIL+1)); tone=$C_FAIL; tag="[未过]" ;;
    esac
    echo -e "${tone}${tag}${C_RST} ${name} ${tone}- $msg${C_RST}"
    echo "[$status] $name - $msg" >> "$SCAN_REPORT"
}

baseline_scan() {
    clear
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_INFO}        🩺 基线体检           ${C_RST}"
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_INFO}全程只读, 不改任何配置。SUID 巡检约需 1-2 分钟…${C_RST}"
    echo ""

    SCAN_OK=0; SCAN_WARN=0; SCAN_FAIL=0
    SCAN_REPORT="/var/log/secure-vps-scan-$(date +%Y%m%d%H%M%S).txt"
    echo "secure-vps 基线体检报告 - $(date)" > "$SCAN_REPORT"

    # SSH 生效值 (sshd -T 展开所有 Include, 比 grep 配置文件可靠)
    local cfg val
    cfg=$(sshd -T 2>/dev/null)
    if [ -n "$cfg" ]; then
        val=$(echo "$cfg" | awk '/^permitrootlogin /{print $2}')
        case $val in
            no)  note_check "SSH root 登录" PASS "已完全禁止" ;;
            prohibit-password|without-password) note_check "SSH root 登录" WARN "仅禁密码 ($val), 建议 PermitRootLogin no" ;;
            *)   note_check "SSH root 登录" FAIL "允许 root 登录 ($val), 高危" ;;
        esac
        val=$(echo "$cfg" | awk '/^passwordauthentication /{print $2}')
        if [ "$val" = "no" ]; then
            note_check "SSH 密码认证" PASS "已关闭, 仅密钥"
        else
            note_check "SSH 密码认证" FAIL "仍开着, 爆破面暴露"
        fi
        val=$(echo "$cfg" | awk '/^port /{print $2}')
        if [ "$val" = "22" ]; then
            note_check "SSH 端口" WARN "还是默认 22, 扫描器头号目标"
        else
            note_check "SSH 端口" PASS "非默认端口 $val"
        fi
        val=$(echo "$cfg" | awk '/^permitemptypasswords /{print $2}')
        if [ "$val" = "no" ]; then
            note_check "空密码登录" PASS "已禁止"
        else
            note_check "空密码登录" FAIL "允许空密码!"
        fi
    else
        note_check "SSH 配置" WARN "sshd -T 不可用, 跳过 SSH 项"
    fi

    # 防火墙
    if ufw status 2>/dev/null | grep -qw active; then
        note_check "防火墙" PASS "UFW 启用中"
    elif firewall-cmd --state 2>/dev/null | grep -q running; then
        note_check "防火墙" PASS "Firewalld 运行中"
    else
        note_check "防火墙" FAIL "没有处于启用状态的防火墙"
    fi

    # Fail2Ban 与端口对齐
    if command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active fail2ban >/dev/null 2>&1; then
        note_check "Fail2Ban" PASS "运行中"
        local live_port jail_port
        live_port=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}'); live_port=${live_port:-22}
        jail_port=$(awk -F= '/^\[sshd\]/{f=1;next} /^\[/{f=0} f && $1 ~ /^port/ {gsub(/[ \t]/,"",$2); print $2; exit}' \
            /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.local 2>/dev/null)
        jail_port=${jail_port:-ssh}
        if [ "$jail_port" = "$live_port" ] || [ "$jail_port" = "0:65535" ] || \
           [[ "$jail_port" == *"$live_port"* ]] || { [ "$jail_port" = "ssh" ] && [ "$live_port" = "22" ]; }; then
            note_check "Fail2Ban 端口对齐" PASS "封禁口 ($jail_port) 覆盖实际端口 ($live_port)"
        else
            note_check "Fail2Ban 端口对齐" FAIL "jail 封 $jail_port 而 SSH 在 $live_port, 封禁形同虚设!"
        fi
    else
        note_check "Fail2Ban" FAIL "未安装或未运行"
    fi

    # 自动更新
    if dpkg -l 2>/dev/null | grep -q "unattended-upgrades" || \
       systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || \
       systemctl is-enabled yum-cron >/dev/null 2>&1; then
        note_check "自动安全更新" PASS "已配置"
    else
        note_check "自动安全更新" WARN "未配置, 会错过关键补丁"
    fi

    # 待升级包
    local pend=0
    if command -v apt-get >/dev/null 2>&1; then
        pend=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')
    elif command -v yum >/dev/null 2>&1; then
        pend=$(yum -q check-update 2>/dev/null | grep -c '^[a-zA-Z0-9]')
    fi
    if [ "${pend:-0}" -eq 0 ] 2>/dev/null; then
        note_check "补丁状态" PASS "全部最新"
    else
        note_check "补丁状态" WARN "${pend} 个包待升级"
    fi

    # 重启需求
    if [ -f /var/run/reboot-required ]; then
        note_check "重启需求" WARN "有更新待重启生效"
    elif command -v needs-restarting >/dev/null 2>&1 && ! needs-restarting -r >/dev/null 2>&1; then
        note_check "重启需求" WARN "内核类更新需重启"
    else
        note_check "重启需求" PASS "无需重启"
    fi

    # 对外暴露端口
    local ports
    ports=$(ss -tuln 2>/dev/null | grep LISTEN | grep -v '127.0.0.1\|\[::1\]' | wc -l)
    if [ "$ports" -le 10 ]; then
        note_check "对外端口" PASS "$ports 个, 面积可控"
    elif [ "$ports" -le 20 ]; then
        note_check "对外端口" WARN "$ports 个, 建议逐个核对"
    else
        note_check "对外端口" FAIL "$ports 个, 暴露面过大"
    fi

    # 运行服务数
    local svcs
    svcs=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c running)
    if [ "$svcs" -eq 0 ] 2>/dev/null && ! command -v systemctl >/dev/null 2>&1; then
        note_check "运行服务" WARN "无 systemd, 无法统计"
    elif [ "$svcs" -lt 20 ]; then
        note_check "运行服务" PASS "$svcs 个"
    elif [ "$svcs" -lt 40 ]; then
        note_check "运行服务" WARN "$svcs 个, 可收敛"
    else
        note_check "运行服务" FAIL "$svcs 个, 攻击面过大"
    fi

    # 失败登录
    local bad=0
    if command -v lastb >/dev/null 2>&1; then
        bad=$(lastb 2>/dev/null | grep -c "^[[:alnum:]_-]")
    elif command -v journalctl >/dev/null 2>&1; then
        bad=$(journalctl -u ssh -u sshd --since "24 hours ago" 2>/dev/null | grep -c "Failed password")
    fi
    if [ "$bad" -lt 10 ]; then
        note_check "失败登录" PASS "累计 $bad 次"
    elif [ "$bad" -lt 50 ]; then
        note_check "失败登录" WARN "累计 $bad 次, 有扫描迹象"
    else
        note_check "失败登录" FAIL "累计 $bad 次, 疑似持续爆破"
    fi

    # 账户异常
    local empties
    empties=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | wc -l)
    if [ "$empties" -eq 0 ] 2>/dev/null; then
        note_check "空密码账户" PASS "不存在"
    else
        note_check "空密码账户" FAIL "$empties 个: $(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')"
    fi
    local roots
    roots=$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd 2>/dev/null | wc -l)
    if [ "$roots" -eq 0 ] 2>/dev/null; then
        note_check "UID=0 账户" PASS "仅 root"
    else
        note_check "UID=0 账户" FAIL "root 之外还有: $(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd | tr '\n' ' ')"
    fi

    # 策略与配置
    if grep -Eq '^\s*minlen\s*=\s*[0-9]+' /etc/security/pwquality.conf 2>/dev/null; then
        note_check "密码策略" PASS "minlen 已配置"
    else
        note_check "密码策略" WARN "未配置, 弱密码可被接受"
    fi
    if grep -rq "logfile" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        note_check "sudo 审计" PASS "已启用"
    else
        note_check "sudo 审计" WARN "未启用, 提权不可追溯"
    fi
    if [ -f /etc/sysctl.d/99-secure-vps-kernel.conf ]; then
        note_check "内核加固" PASS "已应用 secure-vps 配置"
    else
        note_check "内核加固" WARN "未应用"
    fi

    # 非标准路径 SUID (限根文件系统, 90 秒超时)
    local suid_list suid_n
    suid_list=$(timeout 90 find / -xdev -type f -perm -4000 2>/dev/null | grep -vE '^/(usr/)?(bin|sbin|lib|libexec|lib64)/')
    suid_n=$(echo "$suid_list" | grep -c .)
    if [ "$suid_n" -eq 0 ]; then
        note_check "SUID 文件" PASS "无非标准路径项"
    else
        note_check "SUID 文件" WARN "$suid_n 个非标准路径, 请人工核实"
        echo "---- 非标准路径 SUID ----" >> "$SCAN_REPORT"
        echo "$suid_list" >> "$SCAN_REPORT"
    fi

    # 防御组件在位情况
    if command -v rkhunter >/dev/null 2>&1; then
        note_check "Rootkit 防御" PASS "rkhunter 在位"
    else
        note_check "Rootkit 防御" WARN "缺 rkhunter"
    fi
    if command -v aide >/dev/null 2>&1; then
        note_check "完整性监控" PASS "AIDE 在位"
    else
        note_check "完整性监控" WARN "缺 AIDE"
    fi

    echo ""
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "体检结论: ${C_OK}通过 $SCAN_OK${C_RST} / ${C_WARN}警告 $SCAN_WARN${C_RST} / ${C_FAIL}未过 $SCAN_FAIL${C_RST}"
    if [ "$SCAN_FAIL" -gt 0 ]; then
        echo -e "${C_FAIL}存在未过项, 建议优先处理 (大多可在「纵深防御」一屏内修复)。${C_RST}"
    elif [ "$SCAN_WARN" -gt 0 ]; then
        echo -e "${C_WARN}无高危项, 有改进空间, 可按报告逐项处理。${C_RST}"
    else
        echo -e "${C_OK}状态优秀!${C_RST}"
    fi
    echo -e "${C_INFO}报告已存档: $SCAN_REPORT${C_RST}"
    echo "==== 结论: PASS=$SCAN_OK WARN=$SCAN_WARN FAIL=$SCAN_FAIL ====" >> "$SCAN_REPORT"
    wait_key
}

# ════════════════════════════════════════════════════════════
#  模块: 应用与容器
# ════════════════════════════════════════════════════════════

docker_engine_on() {
    if command -v docker >/dev/null 2>&1; then
        echo -e "${C_WARN}Docker 已存在, 跳过安装。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}>>> 调用 Docker 官方安装脚本… <<<${C_RST}"
    curl -fsSL https://get.docker.com | bash -s docker
    systemctl enable docker
    systemctl start docker
    echo -e "${C_OK}>>> Docker 已安装并启动。<<<${C_RST}"
    wait_key
}

docker_registry_tune() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}请先安装 Docker。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_WARN}>>> 镜像加速与日志轮转 <<<${C_RST}"
    echo -e "${C_INFO}公共加速源时效性强, 失效时重跑本项更换即可。${C_RST}"
    echo -e "  ${C_WARN}1.${C_RST} docker.1ms.run"
    echo -e "  ${C_WARN}2.${C_RST} docker.m.daocloud.io"
    echo -e "  ${C_WARN}3.${C_RST} 两个都用"
    echo -e "  ${C_WARN}4.${C_RST} 自定义 (空格分隔, 含 https://)"
    local pick mirrors m json
    read -r -p "❯ 选择 [1-4]: " pick
    case $pick in
        1) mirrors="https://docker.1ms.run" ;;
        2) mirrors="https://docker.m.daocloud.io" ;;
        3) mirrors="https://docker.1ms.run https://docker.m.daocloud.io" ;;
        4) read -r -p "输入加速地址: " mirrors ;;
        *) echo -e "${C_FAIL}无效选择。${C_RST}"; wait_key; return ;;
    esac
    if [ -z "$mirrors" ]; then
        echo -e "${C_FAIL}地址不能为空。${C_RST}"; wait_key; return
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
    echo -e "${C_INFO}重启 Docker 使其生效…${C_RST}"
    systemctl restart docker
    sleep 2
    if docker info >/dev/null 2>&1; then
        echo -e "${C_OK}生效: 加速与日志轮转 (单文件 50m × 3) 已应用。${C_RST}"
    else
        echo -e "${C_FAIL}Docker 重启失败, 回滚 daemon.json…${C_RST}"
        local bak; bak=$(ls -1t /etc/docker/daemon.json.orig-* 2>/dev/null | head -n 1)
        if [ -n "$bak" ]; then
            cp "$bak" /etc/docker/daemon.json
            systemctl restart docker
            echo -e "${C_WARN}已回到先前配置。${C_RST}"
        fi
    fi
    wait_key
}

# Docker 的 -p 发布端口直接写 iptables, 会整体绕过 UFW 暴露公网。
# 处理: daemon.json 关掉 iptables 托管 + before.rules 注入 docker0 出网 NAT。
docker_ufw_takeover() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}请先安装 Docker。${C_RST}"
        wait_key; return
    fi
    if [ "$FW_KIND" != "ufw" ]; then
        echo -e "${C_WARN}该方案目前只覆盖 UFW 体系 (Ubuntu/Debian), 当前系统是 firewalld。${C_RST}"
        wait_key; return
    fi
    if grep -q '"iptables"[[:space:]]*:[[:space:]]*false' /etc/docker/daemon.json 2>/dev/null; then
        echo -e "${C_OK}接管已处于启用状态。${C_RST}"
        if ask_yes "撤销接管 (恢复 Docker 默认 iptables 行为)？"; then
            local bd bu
            bd=$(ls -1t /etc/docker/daemon.json.orig-* 2>/dev/null | head -n 1)
            bu=$(ls -1t /etc/ufw/before.rules.orig-* 2>/dev/null | head -n 1)
            [ -n "$bd" ] && cp "$bd" /etc/docker/daemon.json
            [ -n "$bu" ] && cp "$bu" /etc/ufw/before.rules
            ufw reload >/dev/null 2>&1
            systemctl restart docker
            echo -e "${C_OK}已撤销。${C_RST}"
        fi
        wait_key; return
    fi

    echo -e "${C_WARN}>>> Docker 绕过 UFW 修复 <<<${C_RST}"
    echo -e "${C_INFO}问题: -p 发布端口绕过 UFW 直接暴露公网, 几乎所有默认安装都中招。${C_RST}"
    echo -e "${C_INFO}方案: Docker 不再自管 iptables, 端口统一经 UFW 收口 + 注入 docker0 出网 NAT。${C_RST}"
    echo -e "${C_FAIL}影响提示:${C_RST}"
    echo -e "${C_FAIL}  1. 已发布容器端口立即对外不可达, 需逐个 ufw allow (这正是目的);${C_RST}"
    echo -e "${C_FAIL}  2. 自定义 bridge 网络的出网需自行补对应网段 NAT。${C_RST}"
    if ! ask_yes "确认接管？"; then wait_key; return; fi

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
        sed -i "/^\*filter/i # secure-vps: docker0 出网 NAT (配合 iptables:false)\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 172.17.0.0\/16 ! -o docker0 -j MASQUERADE\nCOMMIT\n" /etc/ufw/before.rules
    fi

    ufw reload >/dev/null 2>&1
    systemctl restart docker
    sleep 3
    if docker info >/dev/null 2>&1; then
        echo -e "${C_OK}接管成功, 此后容器端口全部由 UFW 把关。${C_RST}"
        echo -e "${C_WARN}放行示例: ufw allow 8080/tcp${C_RST}"
        echo -e "${C_WARN}出网说明: 默认 bridge (172.17.0.0/16) 已带 NAT; 自定义网络参照 /etc/ufw/before.rules 中 SECURE_VPS_DOCKER_MASQ 行追加。${C_RST}"
    else
        echo -e "${C_FAIL}Docker 重启失败, 回滚…${C_RST}"
        local bd bu
        bd=$(ls -1t /etc/docker/daemon.json.orig-* 2>/dev/null | head -n 1)
        bu=$(ls -1t /etc/ufw/before.rules.orig-* 2>/dev/null | head -n 1)
        [ -n "$bd" ] && cp "$bd" /etc/docker/daemon.json
        [ -n "$bu" ] && cp "$bu" /etc/ufw/before.rules
        ufw reload >/dev/null 2>&1
        systemctl restart docker
        echo -e "${C_WARN}已回到接管前状态。${C_RST}"
    fi
    wait_key
}

docker_engine_off() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}未发现 Docker。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_FAIL}警告: 卸载会停掉并移除所有容器!${C_RST}"
    read -r -p "确认彻底卸载 Docker？(y/N): " ack
    if [[ ! "$ack" =~ ^[Yy]$ ]]; then
        echo -e "${C_INFO}已取消。${C_RST}"; wait_key; return
    fi
    echo -e "${C_INFO}停止 Docker…${C_RST}"
    systemctl stop docker 2>/dev/null
    echo -e "${C_INFO}移除组件…${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
        apt-get autoremove -y --purge
    else
        yum remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
    fi
    read -r -p "连同删除所有数据 (镜像/容器/卷, 含 /var/lib/docker)？(y/N): " wipe
    if [[ "$wipe" =~ ^[Yy]$ ]]; then
        rm -rf /var/lib/docker /etc/docker
        echo -e "${C_OK}Docker 与数据已彻底清除。${C_RST}"
    else
        echo -e "${C_OK}引擎已卸载, 数据保留。${C_RST}"
    fi
    wait_key
}

docker_up()      { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; }
docker_present() { docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; }

app_portainer_on() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}请先安装 Docker。${C_RST}"; wait_key; return
    fi
    if docker_present portainer; then
        echo -e "${C_WARN}Portainer 容器已存在, 如需重装请先卸载。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}部署 Portainer 管理面板…${C_RST}"
    docker volume create portainer_data >/dev/null
    docker run -d --name portainer --restart=always \
        -p 9000:9000 \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v portainer_data:/data \
        portainer/portainer-ce:latest >/dev/null
    if docker_up portainer; then
        echo -e "${C_OK}就绪: http://服务器IP:9000 首登设置管理员。${C_RST}"
        ask_yes "防火墙放行 9000 端口？" && fw_grant_tcp 9000
    else
        echo -e "${C_FAIL}启动失败, 查看: docker logs portainer${C_RST}"
    fi
    wait_key
}

app_portainer_off() {
    if ! docker_present portainer; then
        echo -e "${C_WARN}没有 Portainer 容器。${C_RST}"; wait_key; return
    fi
    docker rm -f portainer >/dev/null 2>&1
    if ask_yes "连同删除其数据卷 (面板配置)？"; then
        docker volume rm portainer_data >/dev/null 2>&1
        echo -e "${C_OK}容器与数据已清除。${C_RST}"
    else
        echo -e "${C_OK}容器已删, 数据卷保留。${C_RST}"
    fi
    wait_key
}

app_watch_on() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}请先安装 Docker。${C_RST}"; wait_key; return
    fi
    # 已存在则重建为新版: 安装与更新合一
    if docker_present watchtower; then
        echo -e "${C_INFO}已有 Watchtower, 拉新重建…${C_RST}"
        docker rm -f watchtower >/dev/null 2>&1
    fi
    echo -e "${C_INFO}部署 Watchtower 容器自动更新 (每 24h 巡检)…${C_RST}"
    docker run -d --name watchtower --restart unless-stopped \
        -v /var/run/docker.sock:/var/run/docker.sock \
        containrrr/watchtower --cleanup --interval 86400 >/dev/null
    if docker_up watchtower; then
        echo -e "${C_OK}就绪: 其他容器将自动升级并清理旧镜像。${C_RST}"
    else
        echo -e "${C_FAIL}启动失败, 查看: docker logs watchtower${C_RST}"
    fi
    wait_key
}

app_watch_off() {
    if ! docker_present watchtower; then
        echo -e "${C_WARN}没有 Watchtower 容器。${C_RST}"; wait_key; return
    fi
    docker rm -f watchtower >/dev/null 2>&1
    echo -e "${C_OK}已移除, 容器不再自动更新。${C_RST}"
    wait_key
}

app_kuma_on() {
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "${C_FAIL}请先安装 Docker。${C_RST}"; wait_key; return
    fi
    if docker_present uptime-kuma; then
        echo -e "${C_WARN}Uptime Kuma 已存在。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}部署 Uptime Kuma 拨测面板…${C_RST}"
    docker run -d --restart=always --name uptime-kuma \
        -p 3001:3001 \
        -v uptime-kuma:/app/data \
        louislam/uptime-kuma:1 >/dev/null
    if docker_up uptime-kuma; then
        echo -e "${C_OK}就绪: http://服务器IP:3001 初始化账号。${C_RST}"
        ask_yes "防火墙放行 3001 端口？" && fw_grant_tcp 3001
    else
        echo -e "${C_FAIL}启动失败, 查看: docker logs uptime-kuma${C_RST}"
    fi
    wait_key
}

app_kuma_off() {
    if ! docker_present uptime-kuma; then
        echo -e "${C_WARN}没有 Uptime Kuma 容器。${C_RST}"; wait_key; return
    fi
    docker rm -f uptime-kuma >/dev/null 2>&1
    if ask_yes "连同删除监控历史数据卷？"; then
        docker volume rm uptime-kuma >/dev/null 2>&1
        echo -e "${C_OK}容器与数据已清除。${C_RST}"
    else
        echo -e "${C_OK}容器已删, 数据卷保留。${C_RST}"
    fi
    wait_key
}

app_1panel_on() {
    if command -v 1pctl >/dev/null 2>&1; then
        echo -e "${C_WARN}已检测到 1Panel, 注意是否重复安装。${C_RST}"
    fi
    echo -e "${C_INFO}>>> 调用 1Panel 官方极速安装脚本… <<<${C_RST}"
    curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh && sudo bash quick_start.sh
    wait_key
}

app_1panel_off() {
    if ! command -v 1pctl >/dev/null 2>&1; then
        echo -e "${C_FAIL}未发现 1Panel (无 1pctl)。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_FAIL}警告: 卸载 1Panel 会停掉相关容器。${C_RST}"
    read -r -p "确认卸载？(y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        1pctl uninstall
        echo -e "${C_OK}卸载脚本已执行。${C_RST}"
    else
        echo -e "${C_INFO}已取消。${C_RST}"
    fi
    wait_key
}

# ════════════════════════════════════════════════════════════
#  模块: 监控与评测
# ════════════════════════════════════════════════════════════

sys_pulse() {
    clear
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_INFO}      📊 实时资源仪表         ${C_RST}"
    echo -e "${C_INFO}═══════════════════════════════${C_RST}"
    echo -e "${C_OK}▸ 运行时长: $(uptime -p)${C_RST}"
    echo ""
    echo -e "${C_OK}▸ 核心水位:${C_RST}"
    local cpu mem_t mem_u mem_p disk_p
    cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | awk '{printf "%.0f", $1}')
    gauge "CPU" "$cpu"
    mem_t=$(free | grep Mem | awk '{print $2}')
    mem_u=$(free | grep Mem | awk '{print $3}')
    mem_p=$(( mem_u * 100 / mem_t ))
    gauge "内存" "$mem_p"
    disk_p=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    gauge "磁盘" "$disk_p"
    echo ""
    echo -e "${C_OK}▸ 负载均值: $(cat /proc/loadavg | awk '{print $1" / "$2" / "$3}')${C_RST}"
    echo ""
    echo -e "${C_OK}▸ 网卡地址:${C_RST}"
    if command -v ip >/dev/null; then
        ip -4 -br addr | grep -v "127.0.0.1" | awk '{print "  " $1 ": " $3}'
    fi
    wait_key
}

bench_omni() {
    echo -e "${C_WARN}警告: 融合怪综合评测耗时长、负载高。${C_RST}"
    read -r -p "确认执行？(y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        curl -L https://gitlab.com/spiritysdx/za/-/raw/main/ecs.sh -o ecs.sh && chmod +x ecs.sh && bash ecs.sh
    fi
    wait_key
}

bench_ip_score() {
    echo -e "${C_INFO}执行 IP 质量与风险评分 (IP.Check.Place)…${C_RST}"
    bash <(curl -Ls https://raw.githubusercontent.com/xykt/IPQuality/main/ip.sh)
    wait_key
}

bench_cpu_disk() {
    echo -e "${C_WARN}【高负载】YABS 压测 (含 Geekbench) 对低配机不友好。${C_RST}"
    read -r -p "确认执行？(y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        curl -sL yabs.sh | bash
    fi
    wait_key
}

bench_speed() {
    echo -e "${C_WARN}【耗流量】全球节点测速会吃掉不少流量。${C_RST}"
    read -r -p "确认执行？(y/N): " ack
    if [[ "$ack" =~ ^[Yy]$ ]]; then
        curl -Lso- bench.sh | bash
    fi
    wait_key
}

bench_stream() {
    echo -e "${C_INFO}调用流媒体解锁检测…${C_RST}"
    bash <(curl -L -s check.unlock.media)
    wait_key
}

bench_route() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     回程路由      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 指定目标追踪"
        echo -e "  ${C_WARN}2.${C_RST} 三网回程快测"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick target
        read -r -p "❯ 选择 [0-2]: " pick
        case $pick in
            1)
                read -r -p "目标 IP 或域名 (留空=自动): " target
                command -v nexttrace >/dev/null 2>&1 || { echo -e "${C_INFO}安装 NextTrace…${C_RST}"; curl nxtrace.org/nt | bash; }
                if [ -z "$target" ]; then nexttrace --ipv4; else nexttrace "$target"; fi
                wait_key
                ;;
            2)
                echo -e "${C_INFO}三网快测中…${C_RST}"
                command -v nexttrace >/dev/null 2>&1 || { echo -e "${C_INFO}安装 NextTrace…${C_RST}"; curl nxtrace.org/nt | bash; }
                nexttrace --fast-trace
                wait_key
                ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

# ════════════════════════════════════════════════════════════
#  页面 (菜单)
# ════════════════════════════════════════════════════════════

page_ssh() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     SSH 与登录     ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 升级系统软件包"
        echo -e "  ${C_WARN}2.${C_RST} 导入 GitHub 公钥并关闭密码登录"
        echo -e "  ${C_WARN}3.${C_RST} SSH 基线参数包 (防爆破)"
        echo -e "  ${C_WARN}4.${C_RST} 更换 SSH 端口"
        echo -e "  ${C_WARN}5.${C_RST} 封禁 root 密码登录 (保留密钥)"
        echo -e "  ${C_WARN}6.${C_RST} 登录白名单 (AllowUsers)"
        echo -e "  ${C_WARN}7.${C_RST} 回滚最近配置快照"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-7]: " pick
        case $pick in
            1) pkg_upgrade_all ;;
            2) ssh_keys_from_github ;;
            3) ssh_baseline_pack ;;
            4) ssh_port_shift ;;
            5) ssh_lock_root_passwd ;;
            6) ssh_gate_users ;;
            7) ssh_config_rewind "manual"; wait_key ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_fw() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}       防火墙      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 初始化并启用"
        echo -e "  ${C_WARN}2.${C_RST} 查看状态与规则"
        echo -e "  ${C_WARN}3.${C_RST} 放行自定义端口"
        echo -e "  ${C_WARN}4.${C_RST} 重载规则"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-4]: " pick
        case $pick in
            1) fw_init ;;
            2) fw_report ;;
            3) fw_open ;;
            4) fw_reload ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_intrusion() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     入侵封禁       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🚫 Fail2Ban 部署防护"
        echo -e "  ${C_WARN}2.${C_RST} 📋 Fail2Ban 状态与封禁名单"
        echo -e "  ${C_WARN}3.${C_RST} 📜 Fail2Ban 拦截日志"
        echo -e "  ${C_WARN}4.${C_RST} 🔄 重启 Fail2Ban"
        echo -e "  ${C_WARN}5.${C_RST} 🛡 CrowdSec 安装 (现代替代)"
        echo -e "  ${C_WARN}6.${C_RST} 📋 CrowdSec 状态"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-6]: " pick
        case $pick in
            1) f2b_deploy ;;
            2) f2b_report ;;
            3) f2b_log_tail ;;
            4) systemctl restart fail2ban; echo -e "${C_OK}已重启。${C_RST}"; wait_key ;;
            5) crowdsec_deploy ;;
            6) crowdsec_status ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

crowdsec_deploy() {
    echo -e "${C_WARN}>>> CrowdSec 部署 <<<${C_RST}"
    if command -v cscli >/dev/null 2>&1; then
        echo -e "${C_WARN}CrowdSec 已安装。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}CrowdSec = 行为分析 + 众包威胁情报 + 多层 bouncer${C_RST}"
    echo -e "${C_INFO}资源开销: ~85MB RAM (Fail2ban ~22MB, 可接受)${C_RST}"
    if ! ask_yes "安装 CrowdSec？(可与 Fail2ban 共存)"; then return; fi
    curl -fsSL https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/scripts/install.sh \
        -o /tmp/crowdsec-install.sh 2>/dev/null || {
        echo -e "${C_FAIL}下载安装脚本失败, 请检查网络。${C_RST}"; wait_key; return; }
    bash /tmp/crowdsec-install.sh
    rm -f /tmp/crowdsec-install.sh
    if command -v cscli >/dev/null 2>&1; then
        echo -e "${C_OK}CrowdSec 已安装。${C_RST}"
        echo -e "${C_INFO}常用命令:${C_RST}"
        echo -e "  ${C_WARN}cscli metrics${C_RST}     — 查看检测指标"
        echo -e "  ${C_WARN}cscli decisions list${C_RST} — 查看封禁列表"
        echo -e "  ${C_WARN}cscli alerts list${C_RST}    — 查看告警"
        echo -e "${C_INFO}建议安装 bouncer (如 iptables-bouncer):${C_RST}"
        echo -e "  ${C_WARN}cscli bouncers install -n iptables${C_RST}"
    else
        echo -e "${C_FAIL}CrowdSec 安装失败, 请手动排查。${C_RST}"
    fi
    wait_key
}

crowdsec_status() {
    echo -e "${C_WARN}>>> CrowdSec 状态 <<<${C_RST}"
    if ! command -v cscli >/dev/null 2>&1; then
        echo -e "${C_FAIL}CrowdSec 未安装。${C_RST}"
        wait_key; return
    fi
    echo -e "${C_INFO}── 服务状态 ──${C_RST}"
    systemctl is-active crowdsec 2>/dev/null && echo -e "${C_OK}crowdsec 运行中${C_RST}" || echo -e "${C_FAIL}crowdsec 未运行${C_RST}"
    echo ""
    echo -e "${C_INFO}── 检测指标 ──${C_RST}"
    cscli metrics 2>/dev/null || echo -e "${C_WARN}无法获取指标${C_RST}"
    echo ""
    echo -e "${C_INFO}── 封禁决策 ──${C_RST}"
    cscli decisions list 2>/dev/null || echo -e "${C_WARN}无封禁决策${C_RST}"
    echo ""
    echo -e "${C_INFO}── Bouncer ──${C_RST}"
    cscli bouncers list 2>/dev/null || echo -e "${C_WARN}无 bouncer${C_RST}"
    wait_key
}

page_tuning() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}    性能调优        ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 开启 BBR"
        echo -e "  ${C_WARN}2.${C_RST} 新建 Swap (可选容量)"
        echo -e "  ${C_WARN}3.${C_RST} 删除 Swap"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-3]: " pick
        case $pick in
            1) net_bbr_enable ;;
            2) mem_swap_build ;;
            3) mem_swap_drop ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_users() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     用户管理      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 新建 sudo 用户"
        echo -e "  ${C_WARN}2.${C_RST} 查看普通用户"
        echo -e "  ${C_WARN}3.${C_RST} 删除普通用户"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-3]: " pick
        case $pick in
            1) user_add_admin ;;
            2) user_roster ;;
            3) user_drop ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_toolbox() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}      工具箱       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🖥  主机档案 (CPU/虚拟化/IP归属)"
        echo -e "  ${C_WARN}2.${C_RST} 🕐  时区切换"
        echo -e "  ${C_WARN}3.${C_RST} ⏱  NTP 时间同步"
        echo -e "  ${C_WARN}4.${C_RST} 🌐  DNS 切换"
        echo -e "  ${C_WARN}5.${C_RST} 🔐  root 密码重设"
        echo -e "  ${C_WARN}6.${C_RST} 🔗  端口连通探测"
        echo -e "  ${C_WARN}7.${C_RST} 📜  登录轨迹 (含爆破记录)"
        echo -e "  ${C_WARN}8.${C_RST} 🧹  系统清理"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-8]: " pick
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
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_shield_baseline() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     基线体检       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🩺 基线体检 (只读, 不改系统)"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-1]: " pick
        case $pick in
            1) baseline_scan ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_shield_kernel() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     内核加固       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🧱 内核参数加固"
        echo -e "  ${C_WARN}2.${C_RST} ♻  撤销内核加固"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-2]: " pick
        case $pick in
            1) kernel_arm ;;
            2) kernel_disarm ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_shield_audit() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   审计与完整性    ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🕵 Rkhunter 防御"
        echo -e "  ${C_WARN}2.${C_RST} 🧬 AIDE 完整性"
        echo -e "  ${C_WARN}3.${C_RST} 📡 auditd 审计"
        echo -e "  ${C_WARN}4.${C_RST} 🔌 收缩攻击面"
        echo -e "  ${C_WARN}5.${C_RST} 🔍 Lynis 审计"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-5]: " pick
        case $pick in
            1) rootkit_watch ;;
            2) page_integrity ;;
            3) auditd_install ;;
            4) services_trim ;;
            5) lynis_audit ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_shield_access() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   密码与权限      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🔑 密码强度策略"
        echo -e "  ${C_WARN}2.${C_RST} 📝 sudo 审计"
        echo -e "  ${C_WARN}3.${C_RST} 🔄 自动安全更新"
        echo -e "  ${C_WARN}4.${C_RST} 👥 新建 sudo 用户"
        echo -e "  ${C_WARN}5.${C_RST} 👥 查看普通用户"
        echo -e "  ${C_WARN}6.${C_RST} 👥 删除普通用户"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-6]: " pick
        case $pick in
            1) passwd_quality ;;
            2) sudo_guard ;;
            3) auto_updates_on ;;
            4) user_add_admin ;;
            5) user_roster ;;
            6) user_drop ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_emergency() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     应急检查       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🚨 快速安全体检 (基线扫描)"
        echo -e "  ${C_WARN}2.${C_RST} 👥 最近登录记录"
        echo -e "  ${C_WARN}3.${C_RST} ⏰ 可疑定时任务"
        echo -e "  ${C_WARN}4.${C_RST} 📖 参阅应急手册 (handbook/03-incident-response.md)"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-4]: " pick
        case $pick in
            1) baseline_scan ;;
            2) emergency_logins ;;
            3) emergency_cron ;;
            4) echo -e "${C_INFO}请参阅 handbook/03-incident-response.md${C_RST}"; wait_key ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

emergency_logins() {
    echo -e "${C_WARN}>>> 最近登录记录 <<<${C_RST}"
    echo -e "${C_INFO}── 成功登录 (最近 20 条) ──${C_RST}"
    last -20 2>/dev/null || echo -e "${C_WARN}last 命令不可用${C_RST}"
    echo ""
    echo -e "${C_INFO}── 失败登录 (最近 20 条) ──${C_RST}"
    lastb -20 2>/dev/null || echo -e "${C_WARN}lastb 命令不可用 (需 root)${C_RST}"
    echo ""
    echo -e "${C_INFO}── 当前登录用户 ──${C_RST}"
    who 2>/dev/null
    wait_key
}

emergency_cron() {
    echo -e "${C_WARN}>>> 可疑定时任务排查 <<<${C_RST}"
    echo -e "${C_INFO}── root crontab ──${C_RST}"
    crontab -l 2>/dev/null || echo -e "${C_WARN}无 root crontab${C_RST}"
    echo ""
    echo -e "${C_INFO}── /etc/cron.d/ ──${C_RST}"
    ls -la /etc/cron.d/ 2>/dev/null
    echo ""
    echo -e "${C_INFO}── /etc/crontab ──${C_RST}"
    cat /etc/crontab 2>/dev/null || echo -e "${C_WARN}无 /etc/crontab${C_RST}"
    echo ""
    echo -e "${C_INFO}── 所有用户 crontab ──${C_RST}"
    for user in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
        local cron
        cron=$(crontab -u "$user" -l 2>/dev/null) || continue
        [ -n "$cron" ] && echo -e "${C_WARN}$user:${C_RST}" && echo "$cron"
    done
    echo ""
    echo -e "${C_WARN}检查项: 未知脚本路径、可疑下载命令、非标准时段任务${C_RST}"
    wait_key
}

page_ops_docker() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     容器安全       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        if command -v docker >/dev/null 2>&1; then
            echo -e "状态: ${C_OK}已安装${C_RST}"
        else
            echo -e "状态: ${C_FAIL}未安装${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} 🐳 Docker 引擎 (安装/配置/UFW 修复)"
        echo -e "  ${C_WARN}2.${C_RST} 📦 Portainer (Web 管理面板)"
        echo -e "  ${C_WARN}3.${C_RST} 🔄 Watchtower (自动更新)"
        echo -e "  ${C_WARN}4.${C_RST} 🖥 1Panel (服务器面板)"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-4]: " pick
        case $pick in
            1) page_docker ;;
            2) app_portainer_on ;;
            3) app_watch_on ;;
            4) page_1panel ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_ops_monitor() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     安全监控       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📊 Uptime Kuma (拨测监控)"
        echo -e "  ${C_WARN}2.${C_RST} 📊 实时资源仪表"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-2]: " pick
        case $pick in
            1) app_kuma_on ;;
            2) sys_pulse ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_ops_network() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     网络诊断       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🛰 回程路由 (NextTrace)"
        echo -e "  ${C_WARN}2.${C_RST} 🛡 IP 质量评分"
        echo -e "  ${C_WARN}3.${C_RST} 📺 流媒体解锁"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-3]: " pick
        case $pick in
            1) bench_route ;;
            2) bench_ip_score ;;
            3) bench_stream ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_emergency_perf() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   性能与资源      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🧠 开启 BBR"
        echo -e "  ${C_WARN}2.${C_RST} 💾 新建 Swap"
        echo -e "  ${C_WARN}3.${C_RST} 💾 删除 Swap"
        echo -e "  ${C_WARN}4.${C_RST} 📊 实时资源仪表"
        echo -e "  ${C_WARN}5.${C_RST} 🥇 YABS (CPU/磁盘)"
        echo -e "  ${C_WARN}6.${C_RST} 🌍 带宽测速 (bench.sh)"
        echo -e "  ${C_WARN}7.${C_RST} 🏅 融合怪综合评测"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-7]: " pick
        case $pick in
            1) net_bbr_enable ;;
            2) mem_swap_build ;;
            3) mem_swap_drop ;;
            4) sys_pulse ;;
            5) bench_cpu_disk ;;
            6) bench_speed ;;
            7) bench_omni ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

auto_updates_on() {
    echo -e "${C_WARN}>>> 自动安全更新 <<<${C_RST}"
    if [ "$DISTRO" = "ubuntu" ] || [ "$DISTRO" = "debian" ]; then
        if ! eval "$PKG_INSTALL unattended-upgrades"; then
            echo -e "${C_FAIL}安装失败, 请检查软件源。${C_RST}"
            wait_key; return
        fi
        printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
            > /etc/apt/apt.conf.d/20auto-upgrades
        systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
        echo -e "${C_OK}已开启: 每日自动装安全更新 (unattended-upgrades)。${C_RST}"
        echo -e "${C_WARN}默认只装 security 源; 明细在 /var/log/unattended-upgrades/。${C_RST}"
        if ask_yes "需要时自动重启 (默认凌晨 04:00, 仅内核类更新触发)？"; then
            printf 'Unattended-Upgrade::Automatic-Reboot "true";\nUnattended-Upgrade::Automatic-Reboot-Time "04:00";\n' \
                > /etc/apt/apt.conf.d/52unattended-upgrades-reboot
            echo -e "${C_OK}自动重启策略已配置。${C_RST}"
        fi
    else
        if [ "$DISTRO" = "centos" ] && [ "$DISTRO_MAJOR" = "7" ]; then
            eval "$PKG_INSTALL yum-cron" || { echo -e "${C_FAIL}安装 yum-cron 失败。${C_RST}"; wait_key; return; }
            sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/yum/yum-cron.conf
            systemctl enable --now yum-cron >/dev/null 2>&1
            echo -e "${C_OK}yum-cron 自动更新已开启。${C_RST}"
        else
            eval "$PKG_INSTALL dnf-automatic" || { echo -e "${C_FAIL}安装 dnf-automatic 失败。${C_RST}"; wait_key; return; }
            sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
            systemctl enable --now dnf-automatic.timer >/dev/null 2>&1
            echo -e "${C_OK}dnf-automatic 定时更新已开启。${C_RST}"
        fi
        echo -e "${C_WARN}如需仅安全更新, 可自行把升级类型调成 security。${C_RST}"
    fi
    wait_key
}

lynis_audit() {
    echo -e "${C_WARN}>>> Lynis 安全审计 <<<${C_RST}"
    if [[ "$DISTRO" =~ ^(centos|rhel|almalinux|rocky)$ ]]; then
        eval "$PKG_INSTALL epel-release > /dev/null 2>&1"
    fi
    if ! command -v lynis >/dev/null 2>&1; then
        echo -e "${C_INFO}安装 Lynis (发行版仓库版)…${C_RST}"
        if ! eval "$PKG_INSTALL lynis"; then
            echo -e "${C_FAIL}安装失败, 请检查软件源。${C_RST}"
            wait_key; return
        fi
    fi
    echo -e "${C_INFO}开始审计 (只读, 不改系统)…${C_RST}"
    lynis audit system --quick 2>/dev/null | tee /tmp/secure-vps-lynis.out >/dev/null
    echo ""
    echo -e "${C_WARN}>>> 结果摘要 <<<${C_RST}"
    grep -E "Hardening index" /tmp/secure-vps-lynis.out | tail -n 1
    echo -e "WARNING 数:    $(grep -cE '^\s+- Warning' /tmp/secure-vps-lynis.out)"
    echo -e "Suggestion 数: $(grep -cE '^\s+- Suggestion' /tmp/secure-vps-lynis.out)"
    echo ""
    echo -e "${C_OK}主要警告 (至多 10 条):${C_RST}"
    grep -E "^\s+- Warning" /tmp/secure-vps-lynis.out | head -n 10
    echo ""
    echo -e "${C_WARN}完整日志: /var/log/lynis.log 与 /var/log/lynis-report.dat${C_RST}"
    echo -e "${C_WARN}提示: Hardening index 越高越好, 按 Suggestion 逐项改进。${C_RST}"
    wait_key
}

page_integrity() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}   AIDE 完整性      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        if command -v aide >/dev/null 2>&1; then
            echo -e "状态: ${C_OK}已安装${C_RST}"
        else
            echo -e "状态: ${C_FAIL}未安装${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} 安装并建基线"
        echo -e "  ${C_WARN}2.${C_RST} 重建基线 (系统升级后必做)"
        echo -e "  ${C_WARN}3.${C_RST} 立即比对"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-3]: " pick
        case $pick in
            1) integrity_seed ;;
            2) integrity_reseed ;;
            3) integrity_verify ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_docker() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}    Docker 引擎     ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        if command -v docker >/dev/null 2>&1; then
            echo -e "状态: ${C_OK}已安装${C_RST}"
        else
            echo -e "状态: ${C_FAIL}未安装${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} 安装引擎"
        echo -e "  ${C_WARN}2.${C_RST} 镜像加速与日志轮转"
        echo -e "  ${C_WARN}3.${C_RST} 🔥 UFW 接管 (修复端口绕过)"
        echo -e "  ${C_WARN}4.${C_RST} 卸载引擎"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-4]: " pick
        case $pick in
            1) docker_engine_on ;;
            2) docker_registry_tune ;;
            3) docker_ufw_takeover ;;
            4) docker_engine_off ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_apps() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     容器应用      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
            echo -n "状态: "
            docker_up portainer   && echo -ne "${C_OK}Portainer✔${C_RST} " || echo -ne "${C_FAIL}Portainer✘${C_RST} "
            docker_up watchtower  && echo -ne "${C_OK}Watchtower✔${C_RST} " || echo -ne "${C_FAIL}Watchtower✘${C_RST} "
            docker_up uptime-kuma && echo -ne "${C_OK}Kuma✔${C_RST}\n"      || echo -ne "${C_FAIL}Kuma✘${C_RST}\n"
        else
            echo -e "状态: ${C_FAIL}Docker 未安装或未运行${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} Portainer (Web 管理面板)"
        echo -e "  ${C_WARN}2.${C_RST} Watchtower (自动更新)"
        echo -e "  ${C_WARN}3.${C_RST} Uptime Kuma (拨测监控)"
        echo -e "  ${C_WARN}4.${C_RST} 卸载 Portainer"
        echo -e "  ${C_WARN}5.${C_RST} 卸载 Watchtower"
        echo -e "  ${C_WARN}6.${C_RST} 卸载 Uptime Kuma"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-6]: " pick
        case $pick in
            1) app_portainer_on ;;
            2) app_watch_on ;;
            3) app_kuma_on ;;
            4) app_portainer_off ;;
            5) app_watch_off ;;
            6) app_kuma_off ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
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
            echo -e "状态: ${C_OK}已安装${C_RST}"
        else
            echo -e "状态: ${C_FAIL}未安装${C_RST}"
        fi
        echo
        echo -e "  ${C_WARN}1.${C_RST} 安装"
        echo -e "  ${C_WARN}2.${C_RST} 卸载"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-2]: " pick
        case $pick in
            1) app_1panel_on ;;
            2) app_1panel_off ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_deploy() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     应用部署      ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} Docker 引擎 (安装/加速/UFW 接管/卸载)"
        echo -e "  ${C_WARN}2.${C_RST} 容器应用 (Portainer/Watchtower/Uptime Kuma)"
        echo -e "  ${C_WARN}3.${C_RST} 1Panel 面板"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-3]: " pick
        case $pick in
            1) page_docker ;;
            2) page_apps ;;
            3) page_1panel ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

page_bench() {
    while true; do
        clear
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "${C_OK}     监控评测       ${C_RST}"
        echo -e "${C_OK}═══════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 📊 实时资源仪表"
        echo -e "  ${C_WARN}2.${C_RST} 🥇 YABS (CPU/磁盘)"
        echo -e "  ${C_WARN}3.${C_RST} 🌍 带宽测速 (bench.sh)"
        echo -e "  ${C_WARN}4.${C_RST} 📺 流媒体解锁"
        echo -e "  ${C_WARN}5.${C_RST} 🛰 回程路由 (NextTrace)"
        echo -e "  ${C_WARN}6.${C_RST} 🏅 融合怪综合评测"
        echo -e "  ${C_WARN}7.${C_RST} 🛡 IP 质量评分"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-7]: " pick
        case $pick in
            1) sys_pulse ;;
            2) bench_cpu_disk ;;
            3) bench_speed ;;
            4) bench_stream ;;
            5) bench_route ;;
            6) bench_omni ;;
            7) bench_ip_score ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

home_page() {
    while true; do
        clear
        local hint=""
        if [ -x /usr/local/bin/secure-vps ]; then
            hint=" ${C_WARN}[任意处输入 secure-vps 可唤起]${C_RST}"
        fi
        echo -e "${C_OK}   ❰ secure-vps ❱  VPS Security Enhancement Scripts  ${C_WARN}${APP_VER}${C_RST}"
        echo -e "${C_OK}══════════════════════════════════════${C_RST}"
        echo -e "${C_INFO}主机: ${PRETTY_NAME:-$DISTRO}${C_RST}$hint"
        echo ""
        echo -e "${C_INFO}▎A · 快速通道${C_RST}"
        echo -e "  ${C_FAIL}a1${C_RST} 🛡  全量安全初始化 (更新+防火墙+BBR+Swap+Fail2Ban+内核)"
        echo -e "      ${C_WARN}(新机专用: 内核优化、基础防御、虚拟内存一步到位)${C_RST}"
        echo ""
        echo -e "${C_INFO}▎B · 访问安全${C_RST}"
        echo -e "  ${C_WARN}b1${C_RST} 🔐 SSH 与登录"
        echo -e "  ${C_WARN}b2${C_RST} 🧱 防火墙"
        echo -e "  ${C_WARN}b3${C_RST} 🚫 入侵封禁 (Fail2Ban / CrowdSec)"
        echo ""
        echo -e "${C_INFO}▎C · 纵深防御${C_RST}"
        echo -e "  ${C_WARN}c1${C_RST} 🩺 基线体检 (只读)"
        echo -e "  ${C_WARN}c2${C_RST} 🧱 内核加固"
        echo -e "  ${C_WARN}c3${C_RST} 🔍 审计与完整性 (auditd/AIDE/Rkhunter/Lynis)"
        echo -e "  ${C_WARN}c4${C_RST} 🔑 密码与权限 (密码策略/sudo/用户管理)"
        echo ""
        echo -e "${C_INFO}▎D · 安全运维${C_RST}"
        echo -e "  ${C_WARN}d1${C_RST} 🐳 容器安全 (Docker/Portainer/Watchtower/1Panel)"
        echo -e "  ${C_WARN}d2${C_RST} 📊 安全监控 (Uptime Kuma/资源仪表)"
        echo -e "  ${C_WARN}d3${C_RST} 🛰 网络诊断 (路由/IP 质量/流媒体)"
        echo -e "  ${C_WARN}d4${C_RST} 🧰 系统工具 (档案/时区/DNS/清理)"
        echo ""
        echo -e "${C_INFO}▎E · 应急与恢复${C_RST}"
        echo -e "  ${C_WARN}e1${C_RST} 🚨 应急检查 (被黑排查)"
        echo -e "  ${C_WARN}e2${C_RST} 📊 性能与资源 (跑分/BBR/Swap)"
        echo ""
        echo -e "${C_INFO}▎Z · 维护${C_RST}"
        echo -e "  ${C_WARN}z1${C_RST} 安装全局命令 secure-vps"
        echo -e "  ${C_WARN}z2${C_RST} 移除全局命令"
        echo -e "  ${C_WARN}z3${C_RST} 检查更新"
        echo -e "   0  退出"
        echo
        local pick
        read -r -p "❯ " pick
        pick=$(echo "$pick" | tr 'A-Z' 'a-z')
        case $pick in
            a1)
                echo -e "${C_WARN}全量初始化会调整防火墙与内核参数。${C_RST}"
                read -r -p "确认执行？(y/N): " ack
                if [[ "$ack" =~ ^[Yy]$ ]]; then
                    pkg_upgrade_all
                    fw_init
                    net_bbr_enable
                    mem_swap_build
                    f2b_deploy
                    kernel_arm_core
                    echo -e "${C_OK}全量初始化完成 (含内核加固)。${C_RST}"
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
            e1) page_emergency ;;
            e2) page_emergency_perf ;;
            z1) secure_vps_alias_on ;;
            z2) secure_vps_alias_off ;;
            z3) secure_vps_self_update ;;
            0) clear; echo -e "${C_OK}已退出。${C_RST}"; exit 0 ;;
            *) echo -e "${C_FAIL}无效输入!${C_RST}"; sleep 1 ;;
        esac
    done
}

# ── 启动 ─────────────────────────────────────────────────────
home_page
