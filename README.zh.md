# VPS 安全增强脚本集 — 从首次登录到应急响应的全链路加固

以安全为核心的交互式 bash 脚本，配套场景驱动手册和速查卡。单文件、零依赖、一条命令启动——配一本真正的手册告诉你"为什么"，不只是"怎么做"。

> 这是一个**活的仓库**：脚本和手册按安全方向持续扩展。当前版本以 2650 行交互式脚本 + 8 章手册 + 4 张速查卡为起点。后续迭代将加入 CIS/STIG 审计、容器/K8s 安全、云平台 CIS 基线、数据库加固、大数据 SSL、零信任、WAF、TLS 生命周期、密钥扫描、基于 CrowdSec 的应急响应。

## 快速开始

```bash
wget -O vps_security_enhance.sh https://raw.githubusercontent.com/0x10debug/vps-security-enhancement-scripts/main/vps_security_enhance.sh && chmod +x vps_security_enhance.sh && ./vps_security_enhance.sh
```

新机器直接选 **`a1` 全量安全初始化**——十分钟内完成：系统升级 → 防火墙 → BBR → Swap → Fail2Ban → 内核加固。

装好全局命令后，任意位置敲 `secure-vps` 即可唤起。

## 脚本功能

脚本（`vps_security_enhance.sh`）按**安全层次**组织，不是按运维流程：

| 分区 | 层次 | 功能 |
|---|---|---|
| **A · 快速通道** | — | 全量安全初始化（更新+防火墙+BBR+Swap+Fail2Ban+内核） |
| **B · 访问安全** | L4 网络 | SSH 加固、防火墙（UFW/Firewalld）、入侵封禁（Fail2Ban + CrowdSec） |
| **C · 纵深防御** | L0-L3 | 基线体检、内核加固、审计与完整性（auditd/AIDE/Rkhunter/Lynis）、密码与权限 |
| **D · 安全运维** | — | 容器安全（Docker/Portainer/Watchtower/1Panel）、安全监控（Uptime Kuma）、网络诊断、系统工具 |
| **E · 应急与恢复** | L6 检测 | 应急检查（被黑排查、登录记录、可疑 cron）、性能与资源（BBR/Swap/跑分） |
| **Z · 维护** | — | 全局命令、自更新 |

### 安全层次路线图

7 层架构（L0 → L6）指导迭代计划。每层映射到专用脚本和手册章节，在 9 日迭代周期内逐步加入：

| 层次 | 范围 | 状态 |
|---|---|---|
| L0 | 合规审计（CIS Benchmark、STIG） | 规划中（Phase 2） |
| L1 | 容器与 Kubernetes 安全 | 规划中（Phase 3） |
| L2 | 云平台 CIS 基线（AWS/GCP/Azure） | 规划中（Phase 4） |
| L3 | 数据安全（数据库加固、大数据 SSL/审计） | 规划中（Phase 5） |
| L4 | 网络与边界（零信任、WAF） | 规划中（Phase 6） |
| L5 | 密钥与证书安全（TLS 生命周期、密钥扫描） | 规划中（Phase 7） |
| L6 | 检测与响应（CrowdSec、应急取证） | CrowdSec 已集成到 B3；完整部署规划中（Phase 8） |

完整分支策略见 [`dev-docs/0015`](https://github.com/0x10debug/vps-security-enhancement-scripts/blob/main/dev-docs/0015-vps-security-enhancement-scripts-branch-strategy.md)。

## 安全设计

### 三条铁律（写在代码里的设计原则）

1. **快照 → 校验 → 回滚**：修改 `sshd_config` / `daemon.json` / `sudoers` 前先做带时间戳的快照；重启服务前先 `sshd -t` / `visudo -cf` 校验；校验不过自动回滚，**永远不把用户锁在门外**。
2. **联动一致性**：更换 SSH 端口时自动同步 Fail2Ban 封禁端口；回滚配置时同样联动。
3. **只读优先**：体检、审计全程不改系统；所有破坏性操作一律二次确认。

### 供应链安全审计

| 风险点 | 状态 | 说明 |
|---|---|---|
| 硬编码密钥 | ✅ 干净 | 无密码、密钥、IP 硬编码 |
| 外部脚本执行 | ⚠️ 已记录 | Docker 安装（`get.docker.com`）、CrowdSec 安装、YABS、bench.sh、NextTrace、IPQuality、融合怪——均来自官方源，均需用户确认 |
| `eval` 使用 | ✅ 安全 | 仅用于包管理器命令（`eval "$PKG_INSTALL foo"`）——无用户输入到达 eval |
| `rm -rf` 使用 | ✅ 有防护 | 仅在 Docker 卸载中，需双重确认 |
| 自更新机制 | ✅ HTTPS | 从 GitHub raw 通过 HTTPS 下载 |
| 输入验证 | ✅ 存在 | 所有交互输入在使用前验证 |
| shellcheck | ✅ 干净 | `-S warning` 级别零警告 |

## 配套手册

8 章场景驱动手册，按安全层次组织，每章遵循"问题 → 排查 → 修复 → 验证"闭环：

| 章节 | 主题 | 安全视角 |
|---|---|---|
| [01](handbook/01-first-login-security.md) | 首次登录安全 | 前 30 分钟：评估与加固 |
| [02](handbook/02-security-baseline.md) | 安全基线 | SSH、防火墙、Fail2Ban/CrowdSec、内核、Docker UFW 绕过、密码策略 |
| [03](handbook/03-incident-response.md) | 应急响应 | "被黑了"前 10 分钟、入侵检测、恢复 |
| [04](handbook/04-security-monitoring.md) | 安全监控 | TLS 过期、SSH 不可达、入侵检测、日志管理 |
| [05](handbook/05-backup-security.md) | 备份安全 | 备份作为安全网：凭证保护、恢复演练 |
| [06](handbook/06-container-security.md) | 容器安全 | Docker UFW 绕过、隔离、资源限制 |
| [07](handbook/07-network-security-diagnostics.md) | 网络安全诊断 | 防火墙、TLS、IP 质量排查 |
| [08](handbook/08-resource-security.md) | 资源安全 | 资源耗尽防护、加密性能 |

## 速查卡

4 张一页纸可打印参考卡：

| 速查卡 | 内容 |
|---|---|
| [security-commands.md](cheatsheet/security-commands.md) | 安全相关命令速查 |
| [container-security-commands.md](cheatsheet/container-security-commands.md) | 容器安全命令 |
| [systemd-commands.md](cheatsheet/systemd-commands.md) | 服务管理、journalctl、targets、timers |
| [security-troubleshooting-tree.md](cheatsheet/security-troubleshooting-tree.md) | 7 棵决策树：SSH 连不上、服务不可达、磁盘满、CPU 高、容器启动失败、网站慢、可疑活动 |

## 脚本 vs 模块化：用哪个？

| 需求 | 用 |
|---|---|
| 快速上手，一条命令，菜单驱动 | **vps_security_enhance.sh**（本 repo） |
| 模块化，CLI 驱动，逐模块控制 | [vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) |
| CIS 基准审计，漂移检测 | [security-audit](https://github.com/0x10debug/security-audit) |

`vps_security_enhance.sh` 和 `vps-bootstrap` 都覆盖 SSH/防火墙/Fail2Ban/内核加固——它们是同一能力的两个入口。脚本面向"我只想搞定"，模块化工具面向"我想控制每一步并与其他工具集成"。

## 0x10debug 完整 VPS 工具套件

- [awesome-vps](https://github.com/0x10debug/awesome-vps) — VPS 工具精选列表
- [vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) — 模块化 VPS 加固 CLI
- [compose-recipes](https://github.com/0x10debug/compose-recipes) — 自托管应用套件
- [network-toolkit](https://github.com/0x10debug/network-toolkit) — 反向代理、SSL、穿透
- [monitor-stack](https://github.com/0x10debug/monitor-stack) — 可用性、性能、告警监控
- [backup-kit](https://github.com/0x10debug/backup-kit) — 加密备份与恢复演练
- [security-audit](https://github.com/0x10debug/security-audit) — CIS Benchmark 审计与漂移检测
- [ai-workstation](https://github.com/0x10debug/ai-workstation) — Ollama 自托管 AI

## 系统要求

- Ubuntu 20.04+ / Debian 10+ / CentOS 7/8 / AlmaLinux / Rocky Linux
- root 权限，建议在纯净系统镜像上运行
- 跑分与测速会产生大量网络请求

## 致谢

评测与探测能力调用：[YABS](https://github.com/masonr/yabs) · [bench.sh](https://bench.sh) · [NextTrace](https://github.com/nxtrace/NTrace-core) · [融合怪](https://github.com/spiritLHLS/ecs) · [IPQuality](https://github.com/xykt/IPQuality) · [Lynis](https://cisofy.com/lynis/) · [Endlessh](https://github.com/skeeto/endlessh)。入侵检测集成 [CrowdSec](https://github.com/crowdsecurity/crowdsec)。应用部署依赖 [Docker](https://docker.com) 与 [1Panel](https://1panel.cn) 官方脚本。

## 许可

[MIT](LICENSE) © 2026 0x10debug
