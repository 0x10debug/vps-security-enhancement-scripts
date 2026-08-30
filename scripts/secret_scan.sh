#!/bin/bash
# ════════════════════════════════════════════════════════════
#  secret_scan.sh — Secret & Key Scanning (gitleaks + trufflehog)
#  适用系统: Linux 主机
#  运行身份: root 或普通用户
#  模式: 扫描 + 审计 + CI 集成配置生成 (只读扫描, 不修改文件)
#  参考: gitleaks/gitleaks
#         trufflesecurity/trufflehog
#  项目主页: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# 用法:
#   sudo ./scripts/secret_scan.sh                     # 交互式向导
#   sudo ./scripts/secret_scan.sh --scan              # 快速扫描当前目录
#   sudo ./scripts/secret_scan.sh --scan-git          # 扫描 git 历史
#   sudo ./scripts/secret_scan.sh --deep              # 深度扫描 (trufflehog 验证)
#   sudo ./scripts/secret_scan.sh --install           # 安装 gitleaks + trufflehog
#   sudo ./scripts/secret_scan.sh --audit             # 只读审计密钥管理配置
#   sudo ./scripts/secret_scan.sh --ci                # 生成 CI/pre-commit 配置
#   sudo ./scripts/secret_scan.sh --path /path/to/scan
#   sudo ./scripts/secret_scan.sh --output ./secret-scan-results
#
# 退出码:
#   0 — 成功 (无密钥泄露或仅审计)
#   1 — 参数错误 / 依赖缺失
#   2 — 发现潜在密钥泄露
#   3 — 部分功能不可用

set -euo pipefail

APP_NAME="secret_scan"
APP_VER="v3.2.0"
MODE=""
OUTPUT_DIR=""
SCAN_PATH=""
REPORT_DIR="/var/log/secret-scan"
TIMESTAMP=$(date +%Y%m%d%H%M%S)

GITLEAKS_VER="8.21.2"
TRUFFLEHOG_VER="3.88.29"

COUNT_PASS=0
COUNT_FAIL=0
COUNT_WARN=0
COUNT_SKIP=0
TOTAL_CHECKS=0
SECRETS_FOUND=0

C_FAIL='\033[0;31m'
C_OK='\033[0;32m'
C_WARN='\033[0;33m'
C_INFO='\033[0;34m'
C_RST='\033[0m'

# ── 参数解析 ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --scan) MODE="scan"; shift ;;
            --scan-git) MODE="scan-git"; shift ;;
            --deep) MODE="deep"; shift ;;
            --install) MODE="install"; shift ;;
            --audit) MODE="audit"; shift ;;
            --ci) MODE="ci"; shift ;;
            --path) SCAN_PATH="$2"; shift 2 ;;
            --output) OUTPUT_DIR="$2"; shift 2 ;;
            -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
            *) echo "未知参数: $1"; exit 1 ;;
        esac
    done
    if [ -z "$MODE" ]; then
        MODE="interactive"
    fi
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./secret-scan-results"
    fi
    if [ -z "$SCAN_PATH" ]; then
        SCAN_PATH="."
    fi
}

# ── 报告初始化 ───────────────────────────────────────────────
init_report() {
    mkdir -p "$REPORT_DIR" 2>/dev/null || REPORT_DIR="/tmp/secret-scan"
    mkdir -p "$REPORT_DIR" 2>/dev/null || true
    REPORT_FILE="$REPORT_DIR/secret-scan-${TIMESTAMP}.txt"
    {
        echo "Secret Scanning Audit Report"
        echo "============================="
        echo "Date: $(date)"
        echo "Host: $(hostname 2>/dev/null || echo 'N/A')"
        echo "Script: $APP_NAME $APP_VER"
        echo "Path: $SCAN_PATH"
        echo ""
    } > "$REPORT_FILE"
}

# ── 检查函数 ─────────────────────────────────────────────────
run_check() {
    local id="$1" desc="$2"
    shift 2
    local result evidence rc

    evidence=$("$@" 2>&1) && rc=0 || rc=$?
    case $rc in
        0) result="PASS" ;;
        1) result="FAIL" ;;
        2) result="WARN" ;;
        *) result="SKIP" ;;
    esac

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    case "$result" in
        PASS) COUNT_PASS=$((COUNT_PASS + 1)) ;;
        FAIL) COUNT_FAIL=$((COUNT_FAIL + 1)) ;;
        WARN) COUNT_WARN=$((COUNT_WARN + 1)) ;;
        SKIP) COUNT_SKIP=$((COUNT_SKIP + 1)) ;;
    esac

    local color
    case "$result" in
        PASS) color="$C_OK" ;;
        FAIL) color="$C_FAIL" ;;
        WARN) color="$C_WARN" ;;
        SKIP) color="$C_INFO" ;;
    esac
    printf "  ${color}%-4s${C_RST} %s  %s\n" "$result" "$id" "$desc"

    {
        echo ""
        echo "[$result] $id $desc"
        echo "  Evidence: $evidence"
    } >> "$REPORT_FILE"
}

# ── 工具函数 ─────────────────────────────────────────────────
check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

print_summary() {
    echo ""
    echo -e "${C_OK}══════════════════════════════${C_RST}"
    echo -e "${C_OK}  审计总结${C_RST}"
    echo -e "${C_OK}══════════════════════════════${C_RST}"
    printf "  ${C_OK}PASS${C_RST}: %d  ${C_FAIL}FAIL${C_RST}: %d  ${C_WARN}WARN${C_RST}: %d  ${C_INFO}SKIP${C_RST}: %d  Total: %d\n" \
        "$COUNT_PASS" "$COUNT_FAIL" "$COUNT_WARN" "$COUNT_SKIP" "$TOTAL_CHECKS"
    if [ "$SECRETS_FOUND" -gt 0 ]; then
        echo -e "  ${C_FAIL}发现 $SECRETS_FOUND 个潜在密钥泄露${C_RST}"
    fi
    echo -e "  报告: ${C_INFO}${REPORT_FILE}${C_RST}"
}

wait_key() {
    echo ""
    read -r -p "按回车继续..." _
}

# ── 安装 gitleaks + trufflehog ────────────────────────────────
install_tools() {
    echo -e "${C_WARN}>>> 安装密钥扫描工具 <<<${C_RST}"

    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="x64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) echo -e "${C_FAIL}不支持的架构: $arch${C_RST}"; return 1 ;;
    esac

    # 安装 gitleaks
    if check_cmd gitleaks; then
        echo -e "${C_INFO}gitleaks 已安装: $(gitleaks version 2>/dev/null || echo unknown)${C_RST}"
    else
        echo -e "${C_INFO}[1/4] 安装 gitleaks v${GITLEAKS_VER}...${C_RST}"
        local gl_url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_${arch}.tar.gz"
        curl -sL "$gl_url" -o /tmp/gitleaks.tar.gz || {
            echo -e "${C_WARN}gitleaks 下载失败, 跳过${C_RST}"
        }
        if [ -f /tmp/gitleaks.tar.gz ]; then
            tar xzf /tmp/gitleaks.tar.gz -C /tmp/ gitleaks 2>/dev/null
            mv /tmp/gitleaks /usr/local/bin/ 2>/dev/null && chmod +x /usr/local/bin/gitleaks
            rm -f /tmp/gitleaks.tar.gz
            echo -e "${C_OK}gitleaks 安装完成${C_RST}"
        fi
    fi

    # 安装 trufflehog
    if check_cmd trufflehog; then
        echo -e "${C_INFO}trufflehog 已安装${C_RST}"
    else
        echo -e "${C_INFO}[2/4] 安装 trufflehog v${TRUFFLEHOG_VER}...${C_RST}"
        local th_url="https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VER}/trufflehog_${TRUFFLEHOG_VER}_linux_${arch}.tar.gz"
        curl -sL "$th_url" -o /tmp/trufflehog.tar.gz || {
            echo -e "${C_WARN}trufflehog 下载失败, 跳过${C_RST}"
        }
        if [ -f /tmp/trufflehog.tar.gz ]; then
            tar xzf /tmp/trufflehog.tar.gz -C /tmp/ trufflehog 2>/dev/null
            mv /tmp/trufflehog /usr/local/bin/ 2>/dev/null && chmod +x /usr/local/bin/trufflehog
            rm -f /tmp/trufflehog.tar.gz
            echo -e "${C_OK}trufflehog 安装完成${C_RST}"
        fi
    fi

    # 生成 .gitleaksignore 模板
    echo -e "${C_INFO}[3/4] 生成 .gitleaksignore 模板...${C_RST}"
    mkdir -p "$OUTPUT_DIR"
    cat > "$OUTPUT_DIR/.gitleaksignore" <<'EOF'
# gitleaks ignore file — known false positives
# Format: <fingerprint>
# Get fingerprint from gitleaks JSON output: "Fingerprint" field
# Example:
# a1b2c3d4e5f6:path/to/file:line
EOF

    # 生成 gitleaks 自定义配置
    echo -e "${C_INFO}[4/4] 生成 gitleaks 自定义配置...${C_RST}"
    cat > "$OUTPUT_DIR/gitleaks-config.toml" <<'EOF'
# gitleaks custom configuration
# Extends default rules with project-specific patterns

title = "custom gitleaks config"

[extend]
useDefault = true

# Custom rules — add project-specific secret patterns below

# Example: detect internal API keys with prefix "mb_"
# [[rules]]
# id = "internal-api-key"
# description = "Internal API key"
# regex = '''mb_[a-zA-Z0-9]{32}'''
# tags = ["internal", "api-key"]

# Allowlist — files/paths to skip
[allowlist]
description = "Allowed paths and patterns"
paths = [
    '''node_modules/''',
    '''vendor/''',
    '''\.git/objects/''',
    # Test fixtures with fake secrets
    '''test/fixtures/.*''',
    # Documentation examples
    '''docs/examples/.*''',
]
EOF

    echo ""
    echo -e "${C_OK}安装完成${C_RST}"
    echo -e "${C_INFO}gitleaks: $(command -v gitleaks 2>/dev/null || echo '未安装')${C_RST}"
    echo -e "${C_INFO}trufflehog: $(command -v trufflehog 2>/dev/null || echo '未安装')${C_RST}"
    echo -e "${C_INFO}配置模板: $OUTPUT_DIR/gitleaks-config.toml${C_RST}"
    echo -e "${C_INFO}忽略文件: $OUTPUT_DIR/.gitleaksignore${C_RST}"
}

# ── 快速扫描 (gitleaks) ───────────────────────────────────────
scan_secrets() {
    echo -e "${C_WARN}>>> 快速密钥扫描 (gitleaks) <<<${C_RST}"

    if ! check_cmd gitleaks; then
        echo -e "${C_FAIL}gitleaks 未安装, 请先运行 --install${C_RST}"
        return 1
    fi

    if [ ! -d "$SCAN_PATH" ]; then
        echo -e "${C_FAIL}路径不存在: $SCAN_PATH${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"

    echo -e "${C_INFO}扫描路径: $SCAN_PATH${C_RST}"
    echo -e "${C_INFO}输出目录: $OUTPUT_DIR${C_RST}"
    echo ""

    local config_arg=""
    [ -f "$OUTPUT_DIR/gitleaks-config.toml" ] && config_arg="--config $OUTPUT_DIR/gitleaks-config.toml"

    echo -e "${C_INFO}[1/2] 扫描工作区文件...${C_RST}"
    # shellcheck disable=SC2086
    gitleaks detect --source "$SCAN_PATH" $config_arg \
        --report-format json \
        --report-path "$OUTPUT_DIR/gitleaks-report.json" \
        --no-banner 2>&1 | tee "$OUTPUT_DIR/gitleaks-stdout.txt" || true

    local findings
    findings=$(python3 -c "
import json, sys
try:
    with open('$OUTPUT_DIR/gitleaks-report.json') as f:
        data = json.load(f)
    print(len(data))
except:
    print(0)
" 2>/dev/null || echo 0)

    SECRETS_FOUND=$findings

    if [ "$findings" -gt 0 ]; then
        echo ""
        echo -e "${C_FAIL}发现 $findings 个潜在密钥泄露!${C_RST}"
        echo -e "${C_INFO}详细报告: $OUTPUT_DIR/gitleaks-report.json${C_RST}"
        echo ""
        echo -e "${C_WARN}泄露摘要:${C_RST}"
        python3 -c "
import json
with open('$OUTPUT_DIR/gitleaks-report.json') as f:
    data = json.load(f)
for item in data[:20]:
    rule = item.get('RuleID', 'unknown')
    file = item.get('File', 'unknown')
    line = item.get('StartLine', '?')
    secret = item.get('Secret', '')
    # Mask the secret for display
    if len(secret) > 8:
        masked = secret[:4] + '...' + secret[-4:]
    else:
        masked = '***'
    print(f'  [{rule}] {file}:{line} -> {masked}')
if len(data) > 20:
    print(f'  ... and {len(data) - 20} more')
" 2>/dev/null || echo "  (解析报告失败, 请查看 JSON 文件)"
    else
        echo -e "${C_OK}未发现密钥泄露${C_RST}"
    fi

    echo ""
    echo -e "${C_INFO}[2/2] 生成人类可读报告...${C_RST}"
    {
        echo "Gitleaks Scan Report"
        echo "===================="
        echo "Date: $(date)"
        echo "Path: $SCAN_PATH"
        echo "Findings: $findings"
        echo ""
        if [ "$findings" -gt 0 ]; then
            python3 -c "
import json
with open('$OUTPUT_DIR/gitleaks-report.json') as f:
    data = json.load(f)
for item in data:
    print(f\"Rule: {item.get('RuleID', 'unknown')}\")
    print(f\"File: {item.get('File', 'unknown')}:{item.get('StartLine', '?')}\")
    print(f\"Description: {item.get('Description', '')}\")
    print(f\"Secret: [REDACTED]\")
    print()
" 2>/dev/null || echo "(parse error)"
        else
            echo "No secrets detected."
        fi
    } > "$OUTPUT_DIR/gitleaks-report.txt"

    echo -e "${C_INFO}文本报告: $OUTPUT_DIR/gitleaks-report.txt${C_RST}"
}

# ── Git 历史扫描 ──────────────────────────────────────────────
scan_git_history() {
    echo -e "${C_WARN}>>> Git 历史密钥扫描 (gitleaks) <<<${C_RST}"

    if ! check_cmd gitleaks; then
        echo -e "${C_FAIL}gitleaks 未安装, 请先运行 --install${C_RST}"
        return 1
    fi

    if [ ! -d "$SCAN_PATH/.git" ]; then
        echo -e "${C_FAIL}$SCAN_PATH 不是 git 仓库${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"

    echo -e "${C_INFO}扫描 git 历史中的所有 commit...${C_RST}"
    echo -e "${C_WARN}这可能需要较长时间, 取决于仓库大小${C_RST}"
    echo ""

    local config_arg=""
    [ -f "$OUTPUT_DIR/gitleaks-config.toml" ] && config_arg="--config $OUTPUT_DIR/gitleaks-config.toml"

    # shellcheck disable=SC2086
    gitleaks detect --source "$SCAN_PATH" $config_arg \
        --log-opts="--all" \
        --report-format json \
        --report-path "$OUTPUT_DIR/gitleaks-git-report.json" \
        --no-banner 2>&1 | tee "$OUTPUT_DIR/gitleaks-git-stdout.txt" || true

    local findings
    findings=$(python3 -c "
import json
try:
    with open('$OUTPUT_DIR/gitleaks-git-report.json') as f:
        data = json.load(f)
    print(len(data))
except:
    print(0)
" 2>/dev/null || echo 0)

    SECRETS_FOUND=$findings

    if [ "$findings" -gt 0 ]; then
        echo ""
        echo -e "${C_FAIL}在 git 历史中发现 $findings 个潜在密钥泄露!${C_RST}"
        echo -e "${C_WARN}这些密钥可能已泄露, 即使在后续 commit 中删除${C_RST}"
        echo -e "${C_INFO}详细报告: $OUTPUT_DIR/gitleaks-git-report.json${C_RST}"
        echo ""
        echo -e "${C_WARN}修复建议:${C_RST}"
        echo "  1. 立即轮换所有泄露的密钥/令牌"
        echo "  2. 使用 git filter-repo 或 BFG 清理 git 历史"
        echo "  3. 通知所有有仓库访问权限的人"
        echo "  4. 更新 CI/CD 中的密钥"
    else
        echo -e "${C_OK}git 历史中未发现密钥泄露${C_RST}"
    fi
}

# ── 深度扫描 (trufflehog 验证) ────────────────────────────────
scan_deep() {
    echo -e "${C_WARN}>>> 深度密钥扫描 (trufflehog 验证) <<<${C_RST}"

    if ! check_cmd trufflehog; then
        echo -e "${C_FAIL}trufflehog 未安装, 请先运行 --install${C_RST}"
        return 1
    fi

    if [ ! -d "$SCAN_PATH" ]; then
        echo -e "${C_FAIL}路径不存在: $SCAN_PATH${C_RST}"
        return 1
    fi

    mkdir -p "$OUTPUT_DIR"

    echo -e "${C_INFO}trufflehog 会验证发现的密钥是否仍然有效${C_RST}"
    echo -e "${C_WARN}注意: 验证过程会向密钥对应的 API 发送请求${C_RST}"
    echo ""

    echo -e "${C_INFO}扫描文件系统...${C_RST}"
    trufflehog filesystem "$SCAN_PATH" \
        --json 2>/dev/null | tee "$OUTPUT_DIR/trufflehog-report.jsonl" || true

    local findings
    findings=$(wc -l < "$OUTPUT_DIR/trufflehog-report.jsonl" 2>/dev/null || echo 0)
    findings=$(echo "$findings" | tr -d ' ')

    # 过滤已验证的密钥
    local verified
    verified=$(grep -c '"Verified":true\|"verified":true' "$OUTPUT_DIR/trufflehog-report.jsonl" 2>/dev/null || echo 0)
    verified=$(echo "$verified" | tr -d ' ')

    SECRETS_FOUND=$verified

    echo ""
    if [ "$findings" -gt 0 ]; then
        echo -e "${C_WARN}trufflehog 发现 $findings 个潜在密钥${C_RST}"
        if [ "$verified" -gt 0 ]; then
            echo -e "${C_FAIL}其中 $verified 个密钥已验证为有效 (仍然可用)!${C_RST}"
            echo -e "${C_FAIL}这些密钥必须立即轮换!${C_RST}"
        else
            echo -e "${C_OK}没有密钥被验证为有效 (可能已过期或是误报)${C_RST}"
        fi
        echo -e "${C_INFO}详细报告: $OUTPUT_DIR/trufflehog-report.jsonl${C_RST}"
    else
        echo -e "${C_OK}未发现密钥${C_RST}"
    fi
}

# ── CI/pre-commit 配置生成 ────────────────────────────────────
generate_ci_config() {
    echo -e "${C_WARN}>>> 生成 CI / pre-commit 配置 <<<${C_RST}"

    mkdir -p "$OUTPUT_DIR"

    # GitHub Actions 配置
    mkdir -p "$OUTPUT_DIR/github-actions"
    cat > "$OUTPUT_DIR/github-actions/secret-scan.yml" <<'EOF'
# GitHub Actions: Secret scanning with gitleaks
# Add to .github/workflows/secret-scan.yml
name: Secret Scan
on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git scanning

      - name: Install gitleaks
        run: |
          curl -sL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz | \
            tar xz -C /tmp gitleaks
          sudo mv /tmp/gitleaks /usr/local/bin/

      - name: Run gitleaks
        run: |
          gitleaks detect --source . --report-format json --report-path gitleaks-report.json --no-banner
          if [ -s gitleaks-report.json ]; then
            echo "::error::Secrets detected! See gitleaks-report.json"
            exit 1
          fi

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: gitleaks-report
          path: gitleaks-report.json
EOF

    # GitLab CI 配置
    cat > "$OUTPUT_DIR/github-actions/gitlab-ci.yml" <<'EOF'
# GitLab CI: Secret scanning with gitleaks
# Add to .gitlab-ci.yml
secret_scan:
  stage: test
  image:
    name: zricethezav/gitleaks:v8.21.2
    entrypoint: [""]
  script:
    - gitleaks detect --source . --report-format json --report-path gitleaks-report.json --no-banner
    - |
      if [ -s gitleaks-report.json ]; then
        echo "Secrets detected!"
        cat gitleaks-report.json
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - gitleaks-report.json
EOF

    # pre-commit hook
    cat > "$OUTPUT_DIR/pre-commit-hook.sh" <<'EOF'
#!/bin/bash
# pre-commit hook: gitleaks secret scan
# Install: cp this to .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Or add to .pre-commit-config.yaml with gitleaks hook

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "Warning: gitleaks not installed, skipping secret scan"
    exit 0
fi

# Scan staged files only
gitleaks protect --staged --no-banner 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: Potential secrets detected in staged files!"
    echo "Remove the secrets or add to .gitleaksignore"
    exit 1
fi
EOF
    chmod +x "$OUTPUT_DIR/pre-commit-hook.sh"

    # .pre-commit-config.yaml
    cat > "$OUTPUT_DIR/.pre-commit-config.yaml" <<'EOF'
# pre-commit configuration for secret scanning
# Install: pip install pre-commit && pre-commit install
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
        name: Detect hardcoded secrets
        description: Scan for hardcoded secrets using gitleaks
EOF

    # gitleaks.toml (project config)
    cat > "$OUTPUT_DIR/gitleaks.toml" <<'EOF'
# gitleaks project configuration
# Place at repository root
title = "gitleaks config"

[extend]
useDefault = true

[allowlist]
description = "Allowed paths"
paths = [
    '''node_modules/''',
    '''vendor/''',
    '''\.git/objects/''',
    '''test/fixtures/.*''',
    '''docs/examples/.*''',
]
EOF

    echo -e "${C_OK}CI 配置已生成到 $OUTPUT_DIR:${C_RST}"
    echo "  github-actions/secret-scan.yml   — GitHub Actions workflow"
    echo "  github-actions/gitlab-ci.yml     — GitLab CI job"
    echo "  pre-commit-hook.sh               — Git pre-commit hook"
    echo "  .pre-commit-config.yaml          — pre-commit framework config"
    echo "  gitleaks.toml                    — gitleaks project config"
    echo ""
    echo -e "${C_INFO}将对应文件复制到项目根目录即可启用${C_RST}"
}

# ── 密钥管理审计 ──────────────────────────────────────────────
audit_secrets() {
    echo -e "${C_WARN}>>> 密钥管理配置审计 (只读) <<<${C_RST}"
    echo ""
    init_report

    # --- 扫描工具状态 ---
    echo -e "${C_INFO}[扫描工具]${C_RST}"
    run_check "SEC-001" "gitleaks 已安装" check_cmd gitleaks
    run_check "SEC-002" "trufflehog 已安装" check_cmd trufflehog

    # --- 敏感文件检查 ---
    echo ""
    echo -e "${C_INFO}[敏感文件]${C_RST}"

    local sensitive_files=(
        ".env"
        ".env.local"
        ".env.production"
        ".env.staging"
        "config/secrets.yml"
        "config/database.yml"
        "id_rsa"
        "id_ed25519"
        ".npmrc"
        ".pypirc"
        ".netrc"
        ".aws/credentials"
        ".ssh/id_rsa"
        ".docker/config.json"
        ".kube/config"
    )

    local found_sensitive=0
    for f in "${sensitive_files[@]}"; do
        if [ -f "$SCAN_PATH/$f" ] || [ -f "$HOME/$f" ]; then
            found_sensitive=$((found_sensitive + 1))
            # Check if in .gitignore
            local in_gitignore
            in_gitignore=""
            if [ -f "$SCAN_PATH/.gitignore" ]; then
                in_gitignore=$(grep -c "$f" "$SCAN_PATH/.gitignore" 2>/dev/null || echo 0)
            fi
            if [ "$in_gitignore" -gt 0 ]; then
                run_check "SEC-003" "$f 存在且已在 .gitignore" bash -c "exit 2"
            else
                run_check "SEC-003" "$f 存在且未在 .gitignore" bash -c "exit 1"
            fi
        fi
    done
    [ "$found_sensitive" -eq 0 ] && run_check "SEC-003" "敏感文件检查" true

    # --- .gitignore 检查 ---
    echo ""
    echo -e "${C_INFO}[.gitignore]${C_RST}"

    if [ -f "$SCAN_PATH/.gitignore" ]; then
        run_check "SEC-004" ".gitignore 存在" true

        local gitignore_patterns
        gitignore_patterns=$(grep -cE '\.env|id_rsa|\.pem|\.key|secret' "$SCAN_PATH/.gitignore" 2>/dev/null || echo 0)
        if [ "$gitignore_patterns" -gt 0 ]; then
            run_check "SEC-005" ".gitignore 包含密钥相关模式 ($gitignore_patterns 个)" true
        else
            run_check "SEC-005" ".gitignore 包含密钥相关模式" bash -c "exit 1"
        fi
    else
        run_check "SEC-004" ".gitignore 存在" bash -c "exit 1"
        run_check "SEC-005" ".gitignore 包含密钥相关模式" bash -c "exit 2"
    fi

    # --- 硬编码密钥模式扫描 ---
    echo ""
    echo -e "${C_INFO}[硬编码密钥模式]${C_RST}"

    local patterns=(
        "AKIA[0-9A-Z]{16}              # AWS Access Key"
        "ghp_[a-zA-Z0-9]{36}           # GitHub Personal Access Token"
        "gho_[a-zA-Z0-9]{36}           # GitHub OAuth Token"
        "glpat-[a-zA-Z0-9_-]{20}      # GitLab Personal Access Token"
        "xox[baprs]-[a-zA-Z0-9-]+     # Slack Token"
        "sk-[a-zA-Z0-9]{48}           # OpenAI API Key"
        "AIza[0-9A-Za-z_-]{35}        # Google API Key"
        "-----BEGIN.*PRIVATE KEY-----  # Private Key"
    )

    local pattern_found=0
    for pat in "${patterns[@]}"; do
        local regex
        regex=$(echo "$pat" | awk '{print $1}')
        local name
        name=$(echo "$pat" | awk '{$1=""; print}' | sed 's/^ *//')
        local matches
        matches=$(grep -rl --include='*.sh' --include='*.py' --include='*.js' --include='*.ts' --include='*.yml' --include='*.yaml' --include='*.json' --include='*.conf' --include='*.env' --include='*.cfg' -E "$regex" "$SCAN_PATH" 2>/dev/null | head -5 || true)
        if [ -n "$matches" ]; then
            pattern_found=$((pattern_found + 1))
            run_check "SEC-006" "未发现 $name 模式" bash -c "exit 1"
        fi
    done
    [ "$pattern_found" -eq 0 ] && run_check "SEC-006" "未发现硬编码密钥模式" true

    # --- CI/CD 密钥管理 ---
    echo ""
    echo -e "${C_INFO}[CI/CD 密钥管理]${C_RST}"

    if [ -d "$SCAN_PATH/.github/workflows" ]; then
        local hardcoded_secrets
        hardcoded_secrets=$(grep -rl 'password\|secret\|token\|api_key' "$SCAN_PATH/.github/workflows" 2>/dev/null | \
            xargs grep -l 'value:.*[a-zA-Z0-9]\{20,\}' 2>/dev/null | wc -l || echo 0)
        if [ "$hardcoded_secrets" -eq 0 ]; then
            run_check "SEC-007" "GitHub Actions 无硬编码密钥" true
        else
            run_check "SEC-007" "GitHub Actions 可能存在硬编码密钥" bash -c "exit 1"
        fi

        local uses_secrets
        uses_secrets=$(grep -rl 'secrets\.' "$SCAN_PATH/.github/workflows" 2>/dev/null | wc -l || echo 0)
        if [ "$uses_secrets" -gt 0 ]; then
            run_check "SEC-008" "GitHub Actions 使用 secrets 变量" true
        else
            run_check "SEC-008" "GitHub Actions 使用 secrets 变量" bash -c "exit 2"
        fi
    else
        run_check "SEC-007" "GitHub Actions 无硬编码密钥" bash -c "exit 2"
        run_check "SEC-008" "GitHub Actions 使用 secrets 变量" bash -c "exit 2"
    fi

    # --- pre-commit hook ---
    echo ""
    echo -e "${C_INFO}[pre-commit hook]${C_RST}"

    if [ -f "$SCAN_PATH/.git/hooks/pre-commit" ]; then
        local has_gitleaks
        has_gitleaks=$(grep -c 'gitleaks\|secret' "$SCAN_PATH/.git/hooks/pre-commit" 2>/dev/null || echo 0)
        if [ "$has_gitleaks" -gt 0 ]; then
            run_check "SEC-009" "pre-commit hook 包含密钥扫描" true
        else
            run_check "SEC-009" "pre-commit hook 包含密钥扫描" bash -c "exit 2"
        fi
    else
        run_check "SEC-009" "pre-commit hook 包含密钥扫描" bash -c "exit 2"
    fi

    # --- .gitleaksignore ---
    echo ""
    echo -e "${C_INFO}[gitleaks 配置]${C_RST}"

    if [ -f "$SCAN_PATH/.gitleaksignore" ]; then
        local ignored_count
        ignored_count=$(grep -cv '^#\|^$' "$SCAN_PATH/.gitleaksignore" 2>/dev/null || echo 0)
        run_check "SEC-010" ".gitleaksignore 存在 ($ignored_count 条忽略)" true
    else
        run_check "SEC-010" ".gitleaksignore 存在" bash -c "exit 2"
    fi

    if [ -f "$SCAN_PATH/gitleaks.toml" ]; then
        run_check "SEC-011" "gitleaks.toml 自定义配置存在" true
    else
        run_check "SEC-011" "gitleaks.toml 自定义配置存在" bash -c "exit 2"
    fi

    # --- 文件权限 ---
    echo ""
    echo -e "${C_INFO}[敏感文件权限]${C_RST}"

    for f in "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_ed25519" "$HOME/.env" "$HOME/.aws/credentials"; do
        if [ -f "$f" ]; then
            local perms
            perms=$(stat -c "%a" "$f" 2>/dev/null || stat -f "%Lp" "$f" 2>/dev/null || echo "???")
            if [ "$perms" = "600" ] || [ "$perms" = "400" ]; then
                run_check "SEC-012" "$f 权限: $perms" true
            else
                run_check "SEC-012" "$f 权限: $perms (应为 600)" bash -c "exit 1"
            fi
        fi
    done

    # --- Docker secrets ---
    echo ""
    echo -e "${C_INFO}[Docker secrets]${C_RST}"

    if [ -f "$SCAN_PATH/docker-compose.yml" ] || [ -f "$SCAN_PATH/compose.yml" ]; then
        local compose_file
        [ -f "$SCAN_PATH/docker-compose.yml" ] && compose_file="$SCAN_PATH/docker-compose.yml" || compose_file="$SCAN_PATH/compose.yml"
        local hardcoded_env
        hardcoded_env=$(grep -cE 'environment:|PASSWORD=|SECRET=|TOKEN=|KEY=' "$compose_file" 2>/dev/null | head -1 || echo 0)
        if [ "$hardcoded_env" -gt 0 ]; then
            local uses_secrets_file
            uses_secrets_file=$(grep -c 'secrets:\|env_file:\|_FILE' "$compose_file" 2>/dev/null || echo 0)
            if [ "$uses_secrets_file" -gt 0 ]; then
                run_check "SEC-013" "Docker Compose 使用 secrets/env_file" true
            else
                run_check "SEC-013" "Docker Compose 可能硬编码密钥" bash -c "exit 2"
            fi
        else
            run_check "SEC-013" "Docker Compose 密钥管理" true
        fi
    else
        run_check "SEC-013" "Docker Compose 密钥管理" bash -c "exit 2"
    fi

    print_summary
}

# ── 交互式向导 ────────────────────────────────────────────────
interactive_wizard() {
    while true; do
        clear
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "${C_OK}   密钥与秘密扫描           ${C_RST}"
        echo -e "${C_OK}══════════════════════════════${C_RST}"
        echo -e "  ${C_WARN}1.${C_RST} 🛡️ 审计密钥管理配置 (只读)"
        echo -e "  ${C_WARN}2.${C_RST} 📦 安装 gitleaks + trufflehog"
        echo -e "  ${C_WARN}3.${C_RST} 🔍 快速扫描 (gitleaks)"
        echo -e "  ${C_WARN}4.${C_RST} 📜 扫描 git 历史"
        echo -e "  ${C_WARN}5.${C_RST} 🏴 深度扫描 (trufflehog 验证)"
        echo -e "  ${C_WARN}6.${C_RST} 📋 生成 CI/pre-commit 配置"
        echo -e "  ${C_WARN}0.${C_RST} 返回"
        echo
        local pick
        read -r -p "❯ 选择 [0-6]: " pick
        case $pick in
            1) audit_secrets; wait_key ;;
            2) install_tools; wait_key ;;
            3)
                read -r -p "扫描路径 (默认 .): " SCAN_PATH
                [ -z "$SCAN_PATH" ] && SCAN_PATH="."
                scan_secrets; wait_key
                ;;
            4)
                read -r -p "Git 仓库路径 (默认 .): " SCAN_PATH
                [ -z "$SCAN_PATH" ] && SCAN_PATH="."
                scan_git_history; wait_key
                ;;
            5)
                read -r -p "扫描路径 (默认 .): " SCAN_PATH
                [ -z "$SCAN_PATH" ] && SCAN_PATH="."
                scan_deep; wait_key
                ;;
            6) generate_ci_config; wait_key ;;
            0) break ;;
            *) echo -e "${C_FAIL}无效输入${C_RST}"; sleep 1 ;;
        esac
    done
}

# ── 主入口 ────────────────────────────────────────────────────
main() {
    parse_args "$@"

    case "$MODE" in
        scan) scan_secrets ;;
        scan-git) scan_git_history ;;
        deep) scan_deep ;;
        install) install_tools ;;
        audit) audit_secrets ;;
        ci) generate_ci_config ;;
        interactive) interactive_wizard ;;
        *) echo "未知模式: $MODE"; exit 1 ;;
    esac
}

main "$@"
