# 第 20 章：CrowdSec 部署与入侵封禁

> **场景**：你的 VPS 每天被数百个 IP 尝试 SSH 暴力破解，Nginx 日志里满是漏洞扫描和爬虫。Fail2Ban 能封单个 IP，但它只看本地日志、只做本地封禁，没有威胁情报共享。你需要一个能跨主机协同、能识别复杂攻击模式、能在多层（防火墙/反代/CDN）封禁的现代入侵防御系统。CrowdSec 就是为此而生。

## 为什么 CrowdSec 比 Fail2Ban 更好

Fail2Ban 是 2004 年的工具，设计目标是"扫日志 + 封 IP"。它在单机场景下工作良好，但有几个根本性局限：

| 维度 | Fail2Ban | CrowdSec |
|---|---|---|
| 架构 | 单机日志扫描 + 本地封禁 | 引擎 + Bouncer 解耦，支持分布式 |
| 检测能力 | 正则匹配单行日志 | 场景引擎，支持时间窗口、计数、关联 |
| 威胁情报 | 无 | 众包威胁情报，全球 IP 信誉库 |
| 封禁层级 | 仅本地防火墙 | iptables / Nginx / Cloudflare / 多层 |
| 资源开销 | ~22MB RAM | ~85MB RAM（可接受） |
| 社区生态 | 规则零散，各自维护 | Hub 统一管理场景/解析器/bouncer |
| 扩展性 | 难以跨主机 | Central API + Console 集中管理 |

**核心差异**：Fail2Ban 是"每个主机各自为战"，CrowdSec 是"全球主机联防"。当你的服务器被 IP `1.2.3.4` 攻击并封禁后，这个 IP 会被上报到 CrowdSec 全球威胁情报库，其他所有 CrowdSec 用户会自动预先封禁这个 IP。反之，你也会从社区获得其他国家主机上报的恶意 IP 列表。

**推荐策略**：两者可以共存。Fail2Ban 适合轻量单机、只防 SSH；CrowdSec 适合需要 Web 防护、多主机协同、CDN 层封禁的场景。本脚本两者都支持。

## 架构：引擎 + Bouncer + 场景

CrowdSec 的架构是解耦的，三个核心组件各司其职：

```
┌─────────────────────────────────────────────────────┐
│                    CrowdSec 架构                     │
│                                                     │
│  ┌──────────┐    ┌───────────┐    ┌──────────────┐  │
│  │ 日志源    │───▶│ CrowdSec  │───▶│  Bouncer     │  │
│  │ (syslog/ │    │  引擎     │    │ (iptables/   │  │
│  │  nginx/  │    │ + 场景    │    │  nginx/CF)   │  │
│  │  sshd)   │    │ + 解析器  │    │              │  │
│  └──────────┘    └─────┬─────┘    └──────────────┘  │
│                        │                            │
│                        ▼                            │
│                 ┌─────────────┐                     │
│                 │  Local API  │                     │
│                 │  (决策存储)  │                     │
│                 └──────┬──────┘                     │
│                        │                            │
│              ┌─────────┴──────────┐                 │
│              ▼                    ▼                 │
│       ┌────────────┐      ┌──────────────┐          │
│       │  Central   │      │  通知系统     │          │
│       │  API/Console│      │ (email/slack)│          │
│       │ (威胁情报)  │      │              │          │
│       └────────────┘      └──────────────┘          │
└─────────────────────────────────────────────────────┘
```

### 1. CrowdSec 引擎 (crowdsec 服务)

引擎是大脑，负责：
- **读取日志**：通过 acquis.yaml 配置日志源（syslog、nginx access log、sshd log 等）
- **解析日志**：用解析器（parser）把非结构化日志变成结构化事件
- **场景匹配**：用场景（scenario）定义攻击模式，如"10 秒内同一 IP SSH 失败 5 次"
- **生成决策**：匹配场景后生成封禁决策（decision），写入本地数据库
- **上报威胁情报**：将恶意 IP 上报到 Central API（可选）

### 2. Bouncer (封禁执行者)

Bouncer 是手脚，负责读取引擎生成的决策并执行封禁。Bouncer 和引擎解耦，通过 Local API 通信：

- **iptables bouncer**：在系统防火墙层封禁，通用，无需反代
- **nginx bouncer**：在 Nginx 反代层封禁，返回 403，不消耗后端资源
- **Cloudflare bouncer**：通过 Cloudflare API 在 CDN 边缘封禁，恶意流量根本不到你服务器

### 3. 场景 (Scenario) 与集合 (Collection)

场景是用 YAML 写的攻击检测规则，定义"什么行为算攻击"。集合是场景+解析器的打包：

- `crowdsecurity/sshd`：SSH 暴力破解检测
- `crowdsecurity/http-cve`：Web CVE 漏洞利用检测
- `crowdsecurity/http-probing`：Web 路径探测扫描
- `crowdsecurity/http-bad-user-agent`：恶意爬虫 User-Agent

## 安装方法

### 方法一：交互式向导（推荐）

```bash
sudo ./scripts/crowdsec_setup.sh
```

向导提供安装、场景配置、bouncer 部署、告警、审计等全部功能。

### 方法二：命令行直接安装

```bash
# 安装 CrowdSec
sudo ./scripts/crowdsec_setup.sh --install

# 配置检测场景
sudo ./scripts/crowdsec_setup.sh --scenarios

# 部署 iptables bouncer
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type iptables

# 配置 Slack 告警
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type slack
```

### 安装原理

脚本优先使用 CrowdSec 官方安装脚本（`raw.githubusercontent.com/crowdsecurity/crowdsec/master/scripts/install.sh`），它会自动检测发行版并配置对应包源。如果官方脚本下载失败，脚本回退到手动添加 packagecloud 源并用 `apt`/`yum` 安装。

安装完成后，CrowdSec 会：
1. 启用并启动 `crowdsec` systemd 服务
2. 默认安装基础场景集合（sshd、linux）
3. 开放 Local API（端口 8081）供 bouncer 连接

## 场景选择与配置

### 推荐场景集合

| 集合 | 检测内容 | 适用环境 |
|---|---|---|
| `crowdsecurity/sshd` | SSH 暴力破解 | 所有主机 |
| `crowdsecurity/ssh-slow-bf` | SSH 慢速暴力（低频长期） | 所有主机 |
| `crowdsecurity/http-cve` | Web CVE 漏洞利用（Log4Shell 等） | Web 服务器 |
| `crowdsecurity/http-probing` | 路径探测扫描（/admin、/.env 等） | Web 服务器 |
| `crowdsecurity/http-bad-user-agent` | 恶意爬虫、扫描器 UA | Web 服务器 |
| `crowdsecurity/http-sensitive-files` | 敏感文件访问（.git、.aws 等） | Web 服务器 |
| `crowdsecurity/whitelist-good-actors` | 白名单已知好演员（Googlebot 等） | Web 服务器 |
| `crowdsecurity/nfx` | 网络防火墙日志分析 | 有 iptables 日志的主机 |
| `crowdsecurity/iptables-logs` | iptables DROP/REJECT 日志 | 有 iptables 日志的主机 |
| `crowdsecurity/linux` | Linux 系统通用场景 | 所有主机 |

### 配置流程

```bash
# 更新 Hub 索引并安装推荐场景
sudo ./scripts/crowdsec_setup.sh --scenarios

# 或手动安装单个集合
cscli collections install crowdsecurity/http-cve
cscli collections install crowdsecurity/http-probing

# 重启引擎以加载新场景
systemctl restart crowdsec
```

### 自定义场景

如果内置场景不满足需求，可以编写自定义场景。场景文件放在 `/etc/crowdsec/scenarios/` 下：

```yaml
# /etc/crowdsec/scenarios/custom-ssh-bf.yaml
type: trigger
name: custom-ssh-bf
description: "自定义 SSH 暴力破解 (5 次/10 秒)"
filter: "evt.Meta.log_type == 'ssh_failed-auth'"
groupby: "evt.Meta.source_ip"
distinct: "evt.Meta.target_user"
reprocess: true
labels:
  type: ssh_bruteforce
  scope: Ip
  behavior: "ssh:bruteforce"
  confidence: 3
  spoofable: 0
# 10 秒窗口内 5 次失败
capacity: 5
leakspeed: "10s"
blackhole: 1m
```

安装后运行 `cscli scenarios reload` 加载。

## Bouncer 类型对比

### iptables Bouncer（推荐通用）

```bash
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type iptables
```

- **原理**：在系统防火墙层用 iptables/nftables 规则封禁恶意 IP
- **优点**：通用，无需反代，所有流量层生效
- **缺点**：封禁发生在流量到达应用之后（已消耗带宽）
- **适用**：没有反代的直连服务，或作为基础封禁层

### Nginx Bouncer

```bash
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type nginx
```

- **原理**：通过 Nginx 模块在反代层返回 403
- **优点**：不消耗后端应用资源，可自定义响应
- **缺点**：需要 Nginx，仅对经过 Nginx 的流量生效
- **适用**：已有 Nginx 反代的 Web 服务

部署后需确保 Nginx 配置加载了模块：

```nginx
# nginx.conf 顶层
load_module modules/ngx_http_crowdsec_module.so;

# server 块内
server {
    crowdsec on;
    crowdsec_sanitize_urls on;
}
```

### Cloudflare Bouncer

```bash
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type cloudflare
```

- **原理**：通过 Cloudflare API 在 CDN 边缘层添加防火墙规则
- **优点**：恶意流量根本不到你服务器，零带宽消耗
- **缺点**：需要 Cloudflare 账户和 API Token，仅对经 CF 代理的域名生效
- **适用**：域名已接入 Cloudflare 的 Web 服务

需要 Cloudflare API Token（权限：Zone.Firewall Rules）。获取地址：`https://dash.cloudflare.com/profile/api-tokens`。

**多层封禁推荐**：iptables（兜底）+ Cloudflare（边缘拦截）双 bouncer，实现纵深防御。

## 告警配置

CrowdSec 支持多种告警通知方式，检测到攻击时实时推送：

### 邮件告警

```bash
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type email
```

需要 SMTP 服务器信息（host、port、用户名、密码）。配置生成后安装到 `/etc/crowdsec/notifications/`。

### Webhook（通用）

```bash
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type webhook
```

向任意 HTTP 端点 POST JSON 告警数据，可对接自建通知系统、钉钉机器人、企业微信等。

### Slack

```bash
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type slack
```

需要 Slack Incoming Webhook URL。配置后 CrowdSec 告警会推送到指定 Slack 频道。

### Discord

```bash
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type discord
```

需要 Discord Webhook URL。适合游戏社区或使用 Discord 的团队。

### 告警模板

告警配置使用 Go template 语法，可用变量：
- `.AlertsCount`：本次告警数量
- `.Alerts`：告警列表，每条含 `.Scenario`、`.Source.IP`、`.Decisions`

## 集中管理：CrowdSec Console

CrowdSec 提供免费的 Central API 和 Web Console，用于多主机集中管理：

1. **注册 Console**：访问 `https://app.crowdsec.net` 注册免费账户
2. **注册机器**：在每台主机运行 `cscli console enroll <ENROLL_KEY>`
3. **集中查看**：在 Console 中查看所有主机的告警、决策、指标
4. **威胁情报共享**：你的封禁决策会上报社区，你也会获得社区的恶意 IP 列表

```bash
# 注册主机到 Console
cscli console enroll YOUR_ENROLL_KEY

# 查看注册状态
cscli console status
```

Console 的价值：
- **多主机统一视图**：一个面板看所有服务器的安全状态
- **威胁情报闭环**：你上报的 IP 会被全球用户共享封禁
- **历史分析**：长期保存告警和决策数据，支持回溯分析

## 与主脚本集成

CrowdSec 部署脚本已集成到主脚本 `vps_security_enhance.sh` 的 B3 菜单（入侵封禁）：

```
B3 入侵封禁
├── 1. Fail2Ban 部署
├── 2. Fail2Ban 状态
├── 3. Fail2Ban 日志
├── 4. 重启 Fail2Ban
├── 5. CrowdSec 完整部署向导   ← 调用 crowdsec_setup.sh
├── 6. CrowdSec 状态           ← 调用 crowdsec_setup.sh --status
├── 7. CrowdSec 审计 (只读)    ← 调用 crowdsec_setup.sh --audit
└── 0. 返回
```

选择 5/6/7 会调用 `scripts/crowdsec_setup.sh` 对应模式。也可以直接运行脚本：

```bash
# 完整向导
sudo ./scripts/crowdsec_setup.sh

# 只读审计（15 项检查）
sudo ./scripts/crowdsec_setup.sh --audit

# 查看状态
sudo ./scripts/crowdsec_setup.sh --status
```

## 只读审计

`--audit` 模式执行 15 项只读检查，不修改任何配置：

| 检查项 | 内容 |
|---|---|
| CS-001 | CrowdSec 已安装 (cscli 可用) |
| CS-002 | crowdsec 服务运行中 |
| CS-003 | crowdsec 服务已启用开机自启 |
| CS-004 | Hub 已更新 |
| CS-005 | 已安装场景集合数量 |
| CS-006 | SSH 暴力破解场景已安装 |
| CS-007 | 已部署至少一个 bouncer |
| CS-008 | firewall/nginx/cloudflare bouncer 运行中 |
| CS-009 | 当前封禁决策数量 |
| CS-010 | 告警通知已配置 |
| CS-011 | 配置文件存在且可读 |
| CS-012 | CrowdSec API 端口 (8080) 监听 |
| CS-013 | Local API 端口 (8081) 盁听 |
| CS-014 | 数据库文件存在 |
| CS-015 | 日志文件存在 |

审计报告保存到 `/var/log/crowdsec-audit/crowdsec-audit-<timestamp>.txt`。

## 故障排查

### Q: CrowdSec 安装后 bouncer 不工作？

检查 bouncer 服务状态和日志：

```bash
systemctl status crowdsec-firewall-bouncer
journalctl -u crowdsec-firewall-bouncer -n 50
```

常见原因：
- bouncer 未注册到 Local API：运行 `cscli bouncers list` 确认
- API 端口不通：检查 8081 端口是否监听
- bouncer 配置中的 API URL 错误：检查 `/etc/crowdsec/bouncers/` 下的配置

### Q: 场景安装了但没有告警？

确认日志源配置正确：

```bash
# 查看当前日志源
cscli acquisitions list

# 测试日志解析
cscli explain -f /var/log/auth.log -type syslog
```

如果解析器无法识别日志格式，场景不会触发。常见原因：
- 日志路径在 `acquis.yaml` 中未配置
- 日志格式与解析器不匹配（如自定义日志格式）
- 场景的 `filter` 条件过严

### Q: Cloudflare bouncer 报 API 错误？

- 确认 API Token 权限包含 `Zone.Firewall Rules`
- 确认 Zone ID 正确（或留空让 bouncer 自动检测）
- 检查 `/etc/crowdsec/bouncers/cloudflare.yaml` 中的 token 是否有效

### Q: CrowdSec 和 Fail2Ban 能共存吗？

可以。两者检测不同的日志、用不同的封禁机制，互不冲突。常见组合：
- Fail2Ban 防 SSH（轻量、快速）
- CrowdSec 防 Web 攻击 + 威胁情报共享（全面、协同）

注意避免两者对同一 IP 重复封禁造成混乱，建议 SSH 用 Fail2Ban、Web 用 CrowdSec 分工。

### Q: 如何查看 CrowdSec 资源占用？

```bash
systemctl status crowdsec
# 或
cscli metrics
# 内存占用
ps -o pid,rss,comm -p $(pgrep crowdsec)
```

CrowdSec 正常运行约占用 85MB RAM，如果异常偏高可能是场景过多或日志量过大。

### Q: 如何清理过期的封禁决策？

```bash
# 查看当前决策
cscli decisions list

# 删除所有决策（释放所有被封 IP）
cscli decisions delete --all

# 删除特定 IP 的决策
cscli decisions delete --ip 1.2.3.4
```

决策有自动过期时间（由场景的 `duration` 定义），通常无需手动清理。

## 速查

```bash
# 安装 CrowdSec
sudo ./scripts/crowdsec_setup.sh --install

# 配置检测场景
sudo ./scripts/crowdsec_setup.sh --scenarios

# 部署 bouncer
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type iptables
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type nginx
sudo ./scripts/crowdsec_setup.sh --bouncer --bouncer-type cloudflare

# 配置告警
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type email
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type slack
sudo ./scripts/crowdsec_setup.sh --alerts --alert-type discord

# Hub 管理
sudo ./scripts/crowdsec_setup.sh --hub

# 状态 / 日志 / 审计
sudo ./scripts/crowdsec_setup.sh --status
sudo ./scripts/crowdsec_setup.sh --logs
sudo ./scripts/crowdsec_setup.sh --audit

# 卸载
sudo ./scripts/crowdsec_setup.sh --uninstall

# 常用 cscli 命令
cscli metrics              # 检测指标
cscli decisions list       # 封禁列表
cscli alerts list          # 告警列表
cscli bouncers list        # bouncer 列表
cscli collections list     # 已安装集合
cscli hub update           # 更新 Hub
cscli hub upgrade          # 升级集合
cscli console enroll KEY   # 注册到 Console
```
