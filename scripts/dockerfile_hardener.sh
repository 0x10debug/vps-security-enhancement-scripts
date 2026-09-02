#!/bin/bash
# ════════════════════════════════════════════════════════════
#  dockerfile_hardener.sh — Dockerfile Security Analysis & Hardening
#  Supported OS: Any Linux/macOS host
#  Run as: Regular user
#  Mode: Read-only analysis (default) / auto-fix (--fix)
#  Reference: macbuildssys/dockerfile-hardener + CIS Docker Benchmark 4.x
#  Project home: https://github.com/0x10debug/vps-security-enhancement-scripts
# ════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/dockerfile_hardener.sh Dockerfile                    # Analyze single Dockerfile
#   ./scripts/dockerfile_hardener.sh ./path/to/Dockerfile          # Analyze specified path
#   ./scripts/dockerfile_hardener.sh --fix Dockerfile              # Analyze + auto-fix
#   ./scripts/dockerfile_hardener.sh --sarif Dockerfile            # Output SARIF v2.1.0 report
#   ./scripts/dockerfile_hardener.sh --quiet Dockerfile            # Summary only
#   ./scripts/dockerfile_hardener.sh -r ./                         # Recursively scan all Dockerfiles in directory
#
# Exit codes:
#   0 — Analysis complete (regardless of findings)
#   1 — Parameter error / file not found
#   2 — Some fixes failed in fix mode

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

# ── Parameter parsing ─────────────────────────────────────────────────
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --quiet) QUIET=1; shift ;;
            --fix) FIX_MODE=1; shift ;;
            --sarif) SARIF_ONLY=1; shift ;;
            -r|--recursive) RECURSIVE=1; shift ;;
            -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
            -*) echo "Unknown parameter: $1"; exit 1 ;;
            *) TARGET="$1"; shift ;;
        esac
    done
    if [ -z "$TARGET" ]; then
        echo "Usage: $0 [--fix] [--sarif] [--quiet] [-r] <Dockerfile|directory>"
        exit 1
    fi
}

# ── Report initialization ───────────────────────────────────────────────
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

# ── Check results recording ─────────────────────────────────────────────
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

# ── Collect Dockerfile lines ───────────────────────────────────────
# Read file preserving line numbers, skip comments and empty lines
get_lines() {
    local file="$1"
    awk 'NF && $1 !~ /^#/ { printf "%d\t%s\n", NR, $0 }' "$file"
}

# Extract instruction keyword (FROM/RUN/COPY/ADD/USER/ENV/HEALTHCHECK etc.)
get_directive() {
    local line="$1"
    echo "$line" | awk '{print toupper($1)}'
}

# ── Check functions ─────────────────────────────────────────────────

# DF-001: FROM :latest detection
check_from_latest() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        local directive
        directive=$(get_directive "$line")
        if [ "$directive" = "FROM" ]; then
            local image
            image=$(echo "$line" | awk '{print $2}')
            # Remove AS alias part
            image=${image%% *}
            if echo "$image" | grep -qE ':latest$'; then
                record_result "DF-001" "error" "FROM uses :latest tag: $image" "$line_no" \
                    "Replace with specific version, e.g. nginx:1.27.2-alpine"
            elif ! echo "$image" | grep -qE ':'; then
                record_result "DF-001" "error" "FROM missing version tag: $image" "$line_no" \
                    "Add specific version, e.g. $image:1.27.2"
            fi
        fi
    done < <(get_lines "$file")
}

# DF-002: Missing USER instruction (runs as root)
check_no_user() {
    local file="$1"
    if ! grep -qiE '^[[:space:]]*USER[[:space:]]' "$file"; then
        record_result "DF-002" "warning" "No USER instruction set, container runs as root by default" 0 \
            "Add USER <non-root-user>, and create user with useradd first"
    fi
}

# DF-003: USER root explicit declaration
check_user_root() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE '^USER[[:space:]]+root'; then
            record_result "DF-003" "error" "USER explicitly set to root" "$line_no" \
                "Use non-root user, e.g. USER appuser"
        fi
    done < <(get_lines "$file")
}

# DF-004: Hardcoded secrets in ENV
check_env_secrets() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE '^ENV[[:space:]]' && \
           echo "$line" | grep -qiE '(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|CREDENTIAL)[[:space:]]*='; then
            record_result "DF-004" "error" "Hardcoded secret keyword detected in ENV" "$line_no" \
                "Use runtime injection: env vars / Docker secrets / Vault"
        fi
    done < <(get_lines "$file")
}

# DF-005: Hardcoded secrets in ARG
check_arg_secrets() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE '^ARG[[:space:]]' && \
           echo "$line" | grep -qiE '(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|CREDENTIAL)'; then
            record_result "DF-005" "error" "Secret keyword detected in ARG (ARG persists in image history)" "$line_no" \
                "ARG secrets persist in image layer history, use BuildKit --mount=type=secret instead"
        fi
    done < <(get_lines "$file")
}

# DF-006: Missing HEALTHCHECK
check_no_healthcheck() {
    local file="$1"
    if ! grep -qiE '^[[:space:]]*HEALTHCHECK[[:space:]]' "$file"; then
        record_result "DF-006" "warning" "Missing HEALTHCHECK instruction" 0 \
            "Add HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1"
    fi
}

# DF-007: Uses ADD instead of COPY (except URL/archive scenarios)
check_add_usage() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE '^ADD[[:space:]]'; then
            # ADD valid scenario: URL or .tar.gz auto-extract
            if echo "$line" | grep -qE 'https?://|\.tar\.(gz|bz2|xz)' ; then
                record_result "DF-007" "info" "ADD used for URL/archive (valid scenario)" "$line_no"
            else
                record_result "DF-007" "warning" "Uses ADD instead of COPY (non-URL/archive scenario)" "$line_no" \
                    "Use COPY instead, ADD introduces implicit behaviors like auto-extract"
            fi
        fi
    done < <(get_lines "$file")
}

# DF-008: apt-get install without cleaning cache
check_apt_no_cleanup() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE 'apt-get[[:space:]]+install' && \
           ! echo "$line" | grep -qiE 'rm[[:space:]]+-rf[[:space:]]+/var/lib/apt/lists' && \
           ! echo "$line" | grep -qiE 'apt-get[[:space:]]+clean'; then
            # Check next 5 lines for cleanup
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
                record_result "DF-008" "warning" "apt-get install without cleaning apt cache" "$line_no" \
                    "Append in same layer: && rm -rf /var/lib/apt/lists/**"
            fi
        fi
    done < <(get_lines "$file")
}

# DF-009: apt-get install without --no-install-recommends
check_apt_no_install_recommends() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qiE 'apt-get[[:space:]]+install' && \
           ! echo "$line" | grep -qiE '\-\-no-install-recommends'; then
            record_result "DF-009" "info" "apt-get install without --no-install-recommends" "$line_no" \
                "Add --no-install-recommends to reduce image size"
        fi
    done < <(get_lines "$file")
}

# DF-010: chmod 777 (excessive permissions)
check_chmod_777() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE 'chmod[[:space:]]+777'; then
            record_result "DF-010" "error" "chmod 777 grants rwx to all users" "$line_no" \
                "Use least privilege, e.g. chmod 750 or chmod 640"
        fi
    done < <(get_lines "$file")
}

# DF-011: Uses sudo (sudo should not be in container)
check_sudo() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE '(^|[[:space:]])sudo([[:space:]]|$)'; then
            record_result "DF-011" "warning" "Uses sudo in RUN (usually unnecessary in container)" "$line_no" \
                "Container runs as root during build, no sudo needed; or use gosu/su-exec to switch user"
        fi
    done < <(get_lines "$file")
}

# DF-012: curl/wget pipe to shell (blindly executing remote script)
check_curl_pipe_shell() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE '(curl|wget)[^|]*\|[[:space:]]*(sh|bash|/bin/sh|/bin/bash)'; then
            record_result "DF-012" "error" "curl/wget pipe directly executing remote script" "$line_no" \
                "Download, verify checksum, then execute; or use COPY to bring in script"
        fi
    done < <(get_lines "$file")
}

# DF-013: COPY . . (may copy sensitive files)
check_copy_all() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE '^COPY[[:space:]]+\.[[:space:]]+\.'; then
            record_result "DF-013" "warning" "COPY . . may copy sensitive files (.env/.git/keys)" "$line_no" \
                "Use .dockerignore to exclude sensitive files, or use precise COPY"
        fi
    done < <(get_lines "$file")
}

# DF-014: Missing .dockerignore
check_no_dockerignore() {
    local dir
    dir=$(dirname "$1")
    if [ ! -f "$dir/.dockerignore" ]; then
        record_result "DF-014" "warning" "Missing .dockerignore file" 0 \
            "Create .dockerignore to exclude .git .env *.pem node_modules etc"
    fi
}

# DF-015: ENTRYPOINT/CMD uses shell form (signal propagation issue)
check_shell_form_cmd() {
    local file="$1"
    local line_no line
    while IFS=$'\t' read -r line_no line; do
        if echo "$line" | grep -qE '^(ENTRYPOINT|CMD)[[:space:]]+[^[]' && \
           ! echo "$line" | grep -qE '^(ENTRYPOINT|CMD)[[:space:]]+\[' ; then
            record_result "DF-015" "warning" "ENTRYPOINT/CMD uses shell form (PID 1 is shell, signals cannot propagate)" "$line_no" \
                "Use exec form: CMD [\"executable\", \"arg\"]"
        fi
    done < <(get_lines "$file")
}

# DF-016: RUN chain too long (too many layers)
check_many_layers() {
    local file="$1"
    local run_count
    run_count=$(grep -ciE '^RUN[[:space:]]' "$file" 2>/dev/null || true)
    run_count=${run_count:-0}
    if [ "$run_count" -gt 10 ]; then
        record_result "DF-016" "info" "$run_count RUN instructions, consider merging to reduce layers" 0 \
            "Chain multiple RUN commands with && to reduce image layers"
    fi
}

# DF-017: Too many EXPOSE ports
check_expose_ports() {
    local file="$1"
    local port_count
    port_count=$(grep -ciE '^EXPOSE[[:space:]]' "$file" 2>/dev/null || true)
    port_count=${port_count:-0}
    if [ "$port_count" -gt 5 ]; then
        record_result "DF-017" "info" "$port_count EXPOSE ports, check if necessary" 0 \
            "Only expose necessary ports, internal services do not need EXPOSE"
    fi
}

# DF-018: Multi-stage build not used
check_no_multistage() {
    local file="$1"
    local from_count
    from_count=$(grep -ciE '^FROM[[:space:]]' "$file" 2>/dev/null || true)
    from_count=${from_count:-0}
    if [ "$from_count" -lt 2 ]; then
        record_result "DF-018" "info" "Multi-stage build not used (single-stage)" 0 \
            "Separate build and runtime stages to reduce final image size"
    fi
}

# ── Analyze single Dockerfile ──────────────────────────────────────
analyze_dockerfile() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo -e "${C_FAIL}File does not exist: $file${C_RST}"
        return 1
    fi
    if [ "$QUIET" -eq 0 ]; then
        echo ""
        echo -e "${C_INFO}━━━ Analysis: $file ━━━${C_RST}"
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

# ── Auto-fix ─────────────────────────────────────────────────
apply_fixes() {
    local file="$1"
    local fixed=0
    local tmp="${file}.hardened.$TIMESTAMP"
    cp "$file" "$tmp"

    echo ""
    echo -e "${C_WARN}>>> Auto-fix: $file → $tmp ${C_RST}"

    # Fix 1: ADD → COPY (non-URL/archive scenario)
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

    # Fix 2: :latest → prompt user (not auto-replaced, target version unknown)
    if grep -qE 'FROM[[:space:]]+[^[:space:]]+:latest' "$tmp"; then
        echo -e "${C_WARN}  → Detected :latest, please manually replace with specific version (not auto-modified)${C_RST}"
    fi

    # Fix 3: Missing HEALTHCHECK → append default
    if ! grep -qiE '^[[:space:]]*HEALTHCHECK[[:space:]]' "$tmp"; then
        {
            echo ""
            echo "# Added by dockerfile_hardener.sh"
            echo "HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\"
            echo "  CMD curl -f http://localhost/ || exit 1"
        } >> "$tmp"
        echo -e "${C_OK}  → Append default HEALTHCHECK${C_RST}"
        fixed=1
    fi

    # Fix 4: Append cleanup after apt-get install (only at end of same RUN line)
    # Use perl for multi-line RUN ... && apt-get install ... scenarios
    if grep -qE 'apt-get[[:space:]]+install' "$tmp"; then
        perl -i -pe '
            if (/apt-get install/ && !/rm -rf \/var\/lib\/apt\/lists/ && !/apt-get clean/) {
                s/(\s*&&\s*)?\\?\s*$//;
                $_ .= " && rm -rf /var/lib/apt/lists/* \\\n" if /\\$/;
                $_ .= " && rm -rf /var/lib/apt/lists/*\n" unless /\\$/;
            }
        ' "$tmp" 2>/dev/null || true
        echo -e "${C_OK}  → Attempt to append apt cache cleanup${C_RST}"
        fixed=1
    fi

    # Fix 5: Create .dockerignore (if missing)
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
        echo -e "${C_OK}  → Create .dockerignore${C_RST}"
        fixed=1
    fi

    if [ "$fixed" -eq 1 ]; then
        echo -e "${C_OK}  Fix complete, new file: $tmp${C_RST}"
        echo -e "${C_INFO}  Please diff and replace original file: diff $file $tmp${C_RST}"
        echo "  [FIX] Applied to $tmp" >> "$REPORT_TXT"
    else
        echo -e "${C_INFO}  No auto-fixable items${C_RST}"
        rm -f "$tmp"
    fi
}

# ── SARIF report ───────────────────────────────────────────────
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

# ── Summary ─────────────────────────────────────────────────────
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
    echo -e "Report: $REPORT_TXT"
    if [ "$SARIF_ONLY" -eq 1 ]; then
        echo -e "SARIF: $REPORT_SARIF"
    fi
}

# ── Recursive scan ─────────────────────────────────────────────────
scan_recursive() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        echo -e "${C_FAIL}Directory does not exist: $dir${C_RST}"
        exit 1
    fi
    local count=0
    while IFS= read -r f; do
        analyze_dockerfile "$f"
        count=$((count + 1))
    done < <(find "$dir" -type f -name "Dockerfile*" 2>/dev/null)
    if [ "$count" -eq 0 ]; then
        echo -e "${C_WARN}No Dockerfile found${C_RST}"
    else
        echo ""
        echo -e "${C_INFO}Scan complete, total $count  Dockerfiles${C_RST}"
    fi
}

# ── Main flow ───────────────────────────────────────────────────
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
