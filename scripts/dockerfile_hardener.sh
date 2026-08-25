#!/bin/bash
# ════════════════════════════════════════════════════════════
#  dockerfile_hardener.sh — Dockerfile Security Analysis & Hardening
#  适用系统: 任何 Linux/macOS 主机
#  运行身份: 普通用户
#  模式: 只读分析 (默认) / 自动修复 (--fix)
#  参考: macbuildssys/dockerfile-hardener + CIS Docker Benchmark 4.x
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   ./scripts/dockerfile_hardener.sh Dockerfile                    # 分析单个 Dockerfile
#   ./scripts/dockerfile_hardener.sh ./path/to/Dockerfile          # 分析指定路径
#   ./scripts/dockerfile_hardener.sh --fix Dockerfile              # 分析 + 自动修复
#   ./scripts/dockerfile_hardener.sh --sarif Dockerfile            # 输出 SARIF v2.1.0 报告
#   ./scripts/dockerfile_hardener.sh --quiet Dockerfile            # 只输出摘要
#   ./scripts/dockerfile_hardener.sh -r ./                         # 递归扫描目录下所有 Dockerfile
#
# 退出码:
#   0 — 分析完成 (无论是否发现问题)
#   1 — 参数错误 / 文件不存在
#   2 — 修复模式中部分修复失败

set -euo pipefail

APP_NAME="dockerfile_hardener"
APP_VER="v2.2.0"
QUIET=0
FIX_MODE=0
SARIF_ONLY=0
RECURSIVE=0
TARGET=""
REPORT_DIR="/var/log/dockerfile-hardener"
REPORT_TXT=""
REPORT_SARIF=""
TIMESTAMP=$(date +%Y%m%d%H%M%S)

COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_INFO=0
TOTAL_CHECKS=0
SARIF_RESULTS="[]"

C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── 参数解析 ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --quiet) QUIET=1; shift ;;
            --fix) FIX_MODE=1; shift ;;
            --sarif) SARIF_ONLY=1; shift ;;
            -r|--recursive) RECURSIVE=1; shift ;;
            -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
            -*) echo "未知参数: $1"; exit 1 ;;
            *) TARGET="$1"; shift ;;
        esac
    done
    if [ -z "$TARGET" ]; then
        echo "用法: $0 [--fix] [--sarif] [--quiet] [-r] <Dockerfile|目录>"
        exit 1
    fi
}

# ── 报告初始化 ───────────────────────────────────────────────
init_report() {
    if ! mkdir -p "$REPORT_DIR" 2>/dev/null; then
        REPORT_DIR="/tmp/dockerfile-hardener"
        mkdir -p "$REPORT_DIR" 2>/dev/null || true
    fi
    REPORT_TXT="$REPORT_DIR/dockerfile-hardener-${TIMESTAMP}.txt"
    REPORT_SARIF="$REPORT_DIR/dockerfile-hardener-${TIMESTAMP}.sarif"
    {
        echo "Dockerfile Security Analysis & Hardening Report"
        echo "================================================"
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo "Script: $APP_NAME $APP_VER"
        echo "Target: $TARGET"
        echo "Mode: $([ "$FIX_MODE" -eq 1 ] && echo 'ANALYZE + FIX' || echo 'READ-ONLY ANALYSIS')"
        echo ""
    } > "$REPORT_TXT"
}

# ── 检查结果记录 ─────────────────────────────────────────────
record_result() {
    local rule_id="$1" severity="$2" message="$3" line_no="${4:-0}" suggestion="${5:-}"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    case "$severity" in
        error)   COUNT_FAIL=$((COUNT_FAIL + 1)) ;;
        warning) COUNT_WARN=$((COUNT_WARN + 1)) ;;
        info)    COUNT_INFO=$((COUNT_INFO + 1)) ;;
        pass)    COUNT_PASS=$((COUNT_PASS + 1)) ;;
    esac

    if [ "$QUIET" -eq 0 ]; then
        local color symbol
        case "$severity" in
            error)   color="$C_FAIL"; symbol="FAIL" ;;
            warning) color="$C_WARN"; symbol="WARN" ;;
            info)    color="$C_INFO"; symbol="INFO" ;;
            pass)    color="$C_OK";  symbol="PASS" ;;
        esac
        if [ "$line_no" -gt 0 ]; then
            printf "  ${color}%-4s${C_RST} %s  L%-4s  %s\n" "$symbol" "$rule_id" "$line_no" "$message"
        else
            printf "  ${color}%-4s${C_RST} %s  %s\n" "$symbol" "$rule_id" "$message"
        fi
        [ -n "$suggestion" ] && printf "         ${C_INFO}→ %s${C_RST}\n" "$suggestion"
    fi

    {
        echo ""
        echo "[$severity] $rule_id $message (line $line_no)"
        [ -n "$suggestion" ] && echo "  Suggestion: $suggestion"
    } >> "$REPORT_TXT"

    # SARIF result entry
    local sarif_level
    case "$severity" in
        error)   sarif_level="error" ;;
        warning) sarif_level="warning" ;;
        info)    sarif_level="note" ;;
        pass)    sarif_level="none" ;;
    esac
    local entry
    entry=$(cat <<EOF
{
  "ruleId": "$rule_id",
  "level": "$sarif_level",
  "message": { "text": "${message//\"/\\\"}" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "$TARGET" },
      "region": { "startLine": $line_no }
    }
  }]
}
EOF
)
    if [ "$TOTAL_CHECKS" -eq 1 ]; then
        SARIF_RESULTS="[$entry]"
    else
        SARIF_RESULTS="${SARIF_RESULTS%,}]},$entry]"
    fi
}

# ── 收集 Dockerfile 行 ───────────────────────────────────────
# 读取文件并保留行号, 跳过注释和空行
get_lines() {
    local file="$1"
    awk 'NF && $1 !~ /^#/ { printf "%d\t%s\n", NR, $0 }' "$file"
}

# 提取指令关键字 (FROM/RUN/COPY/ADD/USER/ENV/HEALTHCHECK 等)
get_directive() {
    local line="$1"
    echo "$line" | awk '{print toupper($1)}'
}

# ── 检查函数 ─────────────────────────────────────────────────

# DF-001: FROM :latest 检测
check_from_latest() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        local directive
        directive=$(get_directive "$line")
        if [ "$directive" = "FROM" ]; then
            local image
            image=$(echo "$line" | awk '{print $2}')
            # 去掉 AS alias 部分
            image=${image%% *}
            if echo "$image" | grep -qE ':latest$'; then
                record_result "DF-001" "error" "FROM 使用 :latest 标签: $image" "$line_no" \
                    "替换为具体版本, 如 nginx:1.27.2-alpine"
            elif ! echo "$image" | grep -qE ':'; then
                record_result "DF-001" "error" "FROM 未指定版本标签: $image" "$line_no" \
                    "添加具体版本, 如 $image:1.27.2"
            fi
        fi
    done < <(get_lines "$file")
}

# DF-002: 缺少 USER 指令 (以 root 运行)
check_no_user() {
    local file="$1"
    if ! grep -qiE '^[[:space:]]*USER[[:space:]]' "$file"; then
        record_result "DF-002" "warning" "未设置 USER 指令, 容器默认以 root 运行" 0 \
            "添加 USER <non-root-user>, 并在前面 useradd 创建用户"
    fi
}

# DF-003: USER root 显式声明
check_user_root() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE '^USER[[:space:]]+root'; then
            record_result "DF-003" "error" "USER 显式声明为 root" "$line_no" \
                "使用非 root 用户, 如 USER appuser"
        fi
    done < <(get_lines "$file")
}

# DF-004: ENV 中硬编码 secrets
check_env_secrets() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE '^ENV[[:space:]]' && \
           echo "$line" | grep -qiE '(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|CREDENTIAL)[[:space:]]*='; then
            record_result "DF-004" "error" "ENV 中检测到硬编码 secret 关键字" "$line_no" \
                "使用运行时注入: 环境变量 / Docker secrets / Vault"
        fi
    done < <(get_lines "$file")
}

# DF-005: ARG 中硬编码 secrets
check_arg_secrets() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE '^ARG[[:space:]]' && \
           echo "$line" | grep -qiE '(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|CREDENTIAL)'; then
            record_result "DF-005" "error" "ARG 中检测到 secret 关键字 (ARG 会留在镜像历史)" "$line_no" \
                "ARG 中的 secret 会留在镜像层历史, 改用 BuildKit --mount=type=secret"
        fi
    done < <(get_lines "$file")
}

# DF-006: 缺少 HEALTHCHECK
check_no_healthcheck() {
    local file="$1"
    if ! grep -qiE '^[[:space:]]*HEALTHCHECK[[:space:]]' "$file"; then
        record_result "DF-006" "warning" "缺少 HEALTHCHECK 指令" 0 \
            "添加 HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1"
    fi
}

# DF-007: 使用 ADD 而非 COPY (URL/压缩包场景除外)
check_add_usage() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE '^ADD[[:space:]]'; then
            # ADD 合法场景: URL 或 .tar.gz 自动解压
            if echo "$line" | grep -qE 'https?://|\.tar\.(gz|bz2|xz)' ; then
                record_result "DF-007" "info" "ADD 用于 URL/压缩包 (合法场景)" "$line_no"
            else
                record_result "DF-007" "warning" "使用 ADD 而非 COPY (非 URL/压缩包场景)" "$line_no" \
                    "改用 COPY, ADD 会引入自动解压等隐式行为"
            fi
        fi
    done < <(get_lines "$file")
}

# DF-008: apt-get install 后未清理缓存
check_apt_no_cleanup() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE 'apt-get[[:space:]]+install' && \
           ! echo "$line" | grep -qiE 'rm[[:space:]]+-rf[[:space:]]+/var/lib/apt/lists' && \
           ! echo "$line" | grep -qiE 'apt-get[[:space:]]+clean'; then
            # 检查后续 5 行是否有清理
            local has_cleanup=0
            local end=$((line_no + 5))
            local n
            for n in $(seq $((line_no + 1)) $end); do
                local next_line
                next_line=$(sed -n "${n}p" "$file" 2>/dev/null) || break
                if echo "$next_line" | grep -qiE 'rm[[:space:]]+-rf[[:space:]]+/var/lib/apt/lists|apt-get[[:space:]]+clean'; then
                    has_cleanup=1; break
                fi
            done
            if [ "$has_cleanup" -eq 0 ]; then
                record_result "DF-008" "warning" "apt-get install 后未清理 apt 缓存" "$line_no" \
                    "同层追加: && rm -rf /var/lib/apt/lists/*"
            fi
        fi
    done < <(get_lines "$file")
}

# DF-009: apt-get install 未使用 --no-install-recommends
check_apt_no_install_recommends() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE 'apt-get[[:space:]]+install' && \
           ! echo "$line" | grep -qiE '\-\-no-install-recommends'; then
            record_result "DF-009" "info" "apt-get install 未使用 --no-install-recommends" "$line_no" \
                "添加 --no-install-recommends 减小镜像体积"
        fi
    done < <(get_lines "$file")
}

# DF-010: chmod 777 (过度权限)
check_chmod_777() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE 'chmod[[:space:]]+777'; then
            record_result "DF-010" "error" "chmod 777 赋予所有用户 rwx" "$line_no" \
                "使用最小权限, 如 chmod 750 或 chmod 640"
        fi
    done < <(get_lines "$file")
}

# DF-011: 使用 sudo (容器内不应有 sudo)
check_sudo() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE '(^|[[:space:]])sudo([[:space:]]|$)'; then
            record_result "DF-011" "warning" "RUN 中使用 sudo (容器内通常不需要)" "$line_no" \
                "容器以 root 构建阶段运行, 无需 sudo; 或用 gosu/su-exec 切换用户"
        fi
    done < <(get_lines "$file")
}

# DF-012: curl/wget 管道到 shell (盲目执行远程脚本)
check_curl_pipe_shell() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE '(curl|wget)[^|]*\|[[:space:]]*(sh|bash|/bin/sh|/bin/bash)'; then
            record_result "DF-012" "error" "curl/wget 管道直接执行远程脚本" "$line_no" \
                "先下载、校验 checksum、再执行; 或使用 COPY 拷入脚本"
        fi
    done < <(get_lines "$file")
}

# DF-013: COPY . . (可能复制敏感文件)
check_copy_all() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE '^COPY[[:space:]]+\.[[:space:]]+\.'; then
            record_result "DF-013" "warning" "COPY . . 可能复制敏感文件 (.env/.git/密钥)" "$line_no" \
                "使用 .dockerignore 排除敏感文件, 或精确 COPY 指定路径"
        fi
    done < <(get_lines "$file")
}

# DF-014: .dockerignore 缺失
check_no_dockerignore() {
    local dir
    dir=$(dirname "$1")
    if [ ! -f "$dir/.dockerignore" ]; then
        record_result "DF-014" "warning" "缺少 .dockerignore 文件" 0 \
            "创建 .dockerignore 排除 .git .env *.pem node_modules 等"
    fi
}

# DF-015: ENTRYPOINT/CMD 使用 shell 形式 (信号传递问题)
check_shell_form_cmd() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE '^(ENTRYPOINT|CMD)[[:space:]]+[^[]' && \
           ! echo "$line" | grep -qE '^(ENTRYPOINT|CMD)[[:space:]]+\[' ; then
            record_result "DF-015" "warning" "ENTRYPOINT/CMD 使用 shell 形式 (PID 1 是 shell, 信号无法传递)" "$line_no" \
                "使用 exec 形式: CMD [\"executable\", \"arg\"]"
        fi
    done < <(get_lines "$file")
}

# DF-016: RUN 指令链过长 (层数过多)
check_many_layers() {
    local file="$1"
    local run_count
    run_count=$(grep -ciE '^RUN[[:space:]]' "$file" 2>/dev/null || true)
    run_count=${run_count:-0}
    if [ "$run_count" -gt 10 ]; then
        record_result "DF-016" "info" "RUN 指令 $run_count 个, 建议合并减少层数" 0 \
            "用 && 连接多个 RUN 命令, 减少镜像层数"
    fi
}

# DF-017: EXPOSE 端口过多
check_expose_ports() {
    local file="$1"
    local port_count
    port_count=$(grep -ciE '^EXPOSE[[:space:]]' "$file" 2>/dev/null || true)
    port_count=${port_count:-0}
    if [ "$port_count" -gt 5 ]; then
        record_result "DF-017" "info" "EXPOSE $port_count 个端口, 检查是否必要" 0 \
            "仅暴露必要端口, 内部服务不需要 EXPOSE"
    fi
}

# DF-018: 未使用多阶段构建
check_no_multistage() {
    local file="$1"
    local from_count
    from_count=$(grep -ciE '^FROM[[:space:]]' "$file" 2>/dev/null || true)
    from_count=${from_count:-0}
    if [ "$from_count" -lt 2 ]; then
        record_result "DF-018" "info" "未使用多阶段构建 (single-stage)" 0 \
            "编译阶段与运行阶段分离, 减小最终镜像体积"
    fi
}

# ── 分析单个 Dockerfile ──────────────────────────────────────
analyze_dockerfile() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo -e "${C_FAIL}文件不存在: $file${C_RST}"
        return 1
    fi
    if [ "$QUIET" -eq 0 ]; then
        echo ""
        echo -e "${C_INFO}━━━ 分析: $file ━━━${C_RST}"
    fi

    check_from_latest "$file"
    check_no_user "$file"
    check_user_root "$file"
    check_env_secrets "$file"
    check_arg_secrets "$file"
    check_no_healthcheck "$file"
    check_add_usage "$file"
    check_apt_no_cleanup "$file"
    check_apt_no_install_recommends "$file"
    check_chmod_777 "$file"
    check_sudo "$file"
    check_curl_pipe_shell "$file"
    check_copy_all "$file"
    check_no_dockerignore "$file"
    check_shell_form_cmd "$file"
    check_many_layers "$file"
    check_expose_ports "$file"
    check_no_multistage "$file"

    if [ "$FIX_MODE" -eq 1 ]; then
        apply_fixes "$file"
    fi
}

# ── 自动修复 ─────────────────────────────────────────────────
apply_fixes() {
    local file="$1"
    local fixed=0
    local tmp="${file}.hardened.$TIMESTAMP"
    cp "$file" "$tmp"

    echo ""
    echo -e "${C_WARN}>>> 自动修复: $file → $tmp ${C_RST}"

    # 修复 1: ADD → COPY (非 URL/压缩包场景)
    local modified
    modified=$(awk '
        /^[[:space:]]*ADD[[:space:]]/ && !/https?:\/\// && !/\.tar\.(gz|bz2|xz)/ {
            sub(/^ADD/, "COPY")
            print
            next
        }
        { print }
    ' "$tmp")
    echo "$modified" > "$tmp"

    # 修复 2: :latest → 提示用户 (不自动替换, 因为不知道目标版本)
    if grep -qE 'FROM[[:space:]]+[^[:space:]]+:latest' "$tmp"; then
        echo -e "${C_WARN}  → 检测到 :latest, 请手动替换为具体版本 (未自动修改)${C_RST}"
    fi

    # 修复 3: 缺少 HEALTHCHECK → 追加默认
    if ! grep -qiE '^[[:space:]]*HEALTHCHECK[[:space:]]' "$tmp"; then
        {
            echo ""
            echo "# Added by dockerfile_hardener.sh"
            echo "HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\"
            echo "  CMD curl -f http://localhost/ || exit 1"
        } >> "$tmp"
        echo -e "${C_OK}  → 追加默认 HEALTHCHECK${C_RST}"
        fixed=1
    fi

    # 修复 4: apt-get install 后追加清理 (仅在同一 RUN 行末尾)
    # 使用 perl 处理多行 RUN ... && apt-get install ... 场景
    if grep -qE 'apt-get[[:space:]]+install' "$tmp"; then
        perl -i -pe '
            if (/apt-get install/ && !/rm -rf \/var\/lib\/apt\/lists/ && !/apt-get clean/) {
                s/(\s*&&\s*)?\\?\s*$//;
                $_ .= " && rm -rf /var/lib/apt/lists/* \\\n" if /\\$/;
                $_ .= " && rm -rf /var/lib/apt/lists/*\n" unless /\\$/;
            }
        ' "$tmp" 2>/dev/null || true
        echo -e "${C_OK}  → 尝试追加 apt 缓存清理${C_RST}"
        fixed=1
    fi

    # 修复 5: 创建 .dockerignore (如缺失)
    local dir
    dir=$(dirname "$file")
    if [ ! -f "$dir/.dockerignore" ]; then
        cat > "$dir/.dockerignore" <<'EOF'
.git
.gitignore
.env
.env.*
*.pem
*.key
*.p12
node_modules
__pycache__
*.pyc
.venv
venv
.DS_Store
README.md
LICENSE
EOF
        echo -e "${C_OK}  → 创建 .dockerignore${C_RST}"
        fixed=1
    fi

    if [ "$fixed" -eq 1 ]; then
        echo -e "${C_OK}  修复完成, 新文件: $tmp${C_RST}"
        echo -e "${C_INFO}  请 diff 检查后替换原文件: diff $file $tmp${C_RST}"
        echo "  [FIX] Applied to $tmp" >> "$REPORT_TXT"
    else
        echo -e "${C_INFO}  无可自动修复项${C_RST}"
        rm -f "$tmp"
    fi
}

# ── SARIF 报告 ───────────────────────────────────────────────
write_sarif_report() {
    cat > "$REPORT_SARIF" <<EOF
{
  "\$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "$APP_NAME",
        "version": "$APP_VER",
        "informationUri": "https://github.com/0x10debug/vps-security-enhancement-scripts"
      }
    },
    "results": $SARIF_RESULTS
  }]
}
EOF
}

# ── 摘要 ─────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
    echo -e "${C_INFO}║  Dockerfile Hardener Summary              ║${C_RST}"
    echo -e "${C_INFO}║  $APP_NAME $APP_VER                        ║${C_RST}"
    echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
    echo -e "Target: $TARGET"
    echo -e "Mode:   $([ "$FIX_MODE" -eq 1 ] && echo 'ANALYZE + FIX' || echo 'READ-ONLY')"
    echo ""
    printf "  ${C_OK}PASS${C_RST}:  %d\n" "$COUNT_PASS"
    printf "  ${C_FAIL}FAIL${C_RST}:  %d\n" "$COUNT_FAIL"
    printf "  ${C_WARN}WARN${C_RST}:  %d\n" "$COUNT_WARN"
    printf "  ${C_INFO}INFO${C_RST}:  %d\n" "$COUNT_INFO"
    printf "  Total: %d\n" "$TOTAL_CHECKS"
    echo ""
    echo -e "报告: $REPORT_TXT"
    if [ "$SARIF_ONLY" -eq 1 ]; then
        echo -e "SARIF: $REPORT_SARIF"
    fi
}

# ── 递归扫描 ─────────────────────────────────────────────────
scan_recursive() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        echo -e "${C_FAIL}目录不存在: $dir${C_RST}"
        exit 1
    fi
    local count=0
    while IFS= read -r f; do
        analyze_dockerfile "$f"
        count=$((count + 1))
    done < <(find "$dir" -type f -name "Dockerfile*" 2>/dev/null)
    if [ "$count" -eq 0 ]; then
        echo -e "${C_WARN}未找到 Dockerfile${C_RST}"
    else
        echo ""
        echo -e "${C_INFO}扫描完成, 共 $count 个 Dockerfile${C_RST}"
    fi
}

# ── 主流程 ───────────────────────────────────────────────────
main() {
    parse_args "$@"
    init_report

    if [ "$QUIET" -eq 0 ]; then
        echo ""
        echo -e "${C_INFO}╔══════════════════════════════════════════╗${C_RST}"
        echo -e "${C_INFO}║  Dockerfile Security Analysis             ║${C_RST}"
        echo -e "${C_INFO}║  $APP_NAME $APP_VER                        ║${C_RST}"
        echo -e "${C_INFO}╚══════════════════════════════════════════╝${C_RST}"
        echo -e "${C_INFO}Target: $TARGET${C_RST}"
        echo -e "${C_INFO}Mode:   $([ "$FIX_MODE" -eq 1 ] && echo 'ANALYZE + FIX' || echo 'READ-ONLY ANALYSIS')${C_RST}"
    fi

    if [ "$RECURSIVE" -eq 1 ]; then
        scan_recursive "$TARGET"
    else
        analyze_dockerfile "$TARGET"
    fi

    write_sarif_report
    print_summary

    if [ "$SARIF_ONLY" -eq 1 ]; then
        echo "$REPORT_SARIF"
    fi
    return 0
}

main "$@"
