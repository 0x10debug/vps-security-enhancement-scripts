# VPS 手边书 — VPS 与云计算运维人员的实战手册

完整的 VPS 运维工具包：一个交互式 bash 脚本（服务器加固、诊断、评测），加 8 章场景驱动手册和 4 张可打印速查卡。运维人员需要的一切，一个 repo 搞定。

> 单文件。零依赖。一条命令启动。配一本真正的手册告诉你"为什么"，不只是"怎么做"。

## 快速开始

```bash
wget -O vps_secure.sh https://raw.githubusercontent.com/0x10debug/vps-handbook/main/vps_secure.sh && chmod +x vps_secure.sh && ./vps_secure.sh
```

新机器直接选 **`a1` 全量初始化**——十分钟内完成：系统升级 → 防火墙 → BBR → Swap → Fail2Ban → 内核加固。

装好全局命令后，任意位置敲 `secure-vps` 即可唤起。

## 内容概览

### 脚本（`vps_secure.sh`）

2370 行交互式 bash 工具，覆盖：

| 分区 | 功能 |
|---|---|
| **A · 快速** | 全量初始化、系统更新、工具箱、性能调优、用户管理 |
| **B · 安全** | SSH 加固、防火墙（UFW/Firewalld）、Fail2Ban、纵深防御（内核、密码策略、sudo 审计、自动更新、Rkhunter、AIDE、auditd、Lynis） |
| **C · Docker 与应用** | Docker 引擎、镜像加速、UFW 绕过修复、Portainer、Watchtower、Uptime Kuma、1Panel |
| **D · 诊断与评测** | 实时仪表、YABS 跑分、带宽测速、流媒体解锁、回程路由、IP 质量评分 |
| **Z · 维护** | 全局命令、自更新 |

### 手册（`handbook/`）

8 章场景驱动手册，每章遵循"问题 → 排查 → 修复 → 验证"闭环：

| 章节 | 主题 | 关键场景 |
|---|---|---|
| [01](handbook/01-new-server-setup.md) | 新机开荒 | 首次登录、初始评估、快速初始化、验证清单 |
| [02](handbook/02-security-baseline.md) | 安全基线 | SSH、防火墙、Fail2Ban、内核加固、Docker UFW 绕过、密码策略 |
| [03](handbook/03-docker-ops.md) | Docker 运维 | 安装、镜像加速、UFW 修复、容器管理、清理 |
| [04](handbook/04-network-troubleshoot.md) | 网络故障排查 | "服务不可达"决策树、DNS、路由、带宽、BBR |
| [05](handbook/05-performance-tuning.md) | 性能调优 | BBR、Swap、磁盘 I/O、内存、CPU、Docker 资源限制 |
| [06](handbook/06-backup-migration.md) | 备份与迁移 | 策略选择、Docker 卷备份、服务器迁移、恢复演练 |
| [07](handbook/07-monitoring-alerts.md) | 监控与告警 | Uptime Kuma、完整监控栈、告警渠道、日志管理 |
| [08](handbook/08-incident-response.md) | 应急响应 | "被黑了"前 10 分钟、入侵检测、恢复 |

### 速查卡（`cheatsheet/`）

4 张一页纸可打印参考卡：

| 速查卡 | 内容 |
|---|---|
| [essential-commands.md](cheatsheet/essential-commands.md) | 系统、进程、网络、文件、文本、用户、cron、磁盘、包管理命令 |
| [docker-commands.md](cheatsheet/docker-commands.md) | Docker 与 Docker Compose 命令、单行命令、调试 |
| [systemd-commands.md](cheatsheet/systemd-commands.md) | 服务管理、journalctl、targets、timers、故障排查 |
| [troubleshooting-tree.md](cheatsheet/troubleshooting-tree.md) | 7 棵决策树：SSH 连不上、服务不可达、磁盘满、CPU 高、容器启动失败、网站慢、可疑活动 |

## 安全设计

### 三条铁律（写在代码里的设计原则）

1. **快照 → 校验 → 回滚**：修改 `sshd_config` / `daemon.json` / `sudoers` 前先做带时间戳的快照；重启服务前先 `sshd -t` / `visudo -cf` 校验；校验不过自动回滚，**永远不把用户锁在门外**。
2. **联动一致性**：更换 SSH 端口时自动同步 Fail2Ban 封禁端口；回滚配置时同样联动。
3. **只读优先**：体检、审计全程不改系统；所有破坏性操作一律二次确认。

### 安全审计说明

脚本经过供应链安全审计：

| 风险点 | 状态 | 说明 |
|---|---|---|
| 硬编码密钥 | ✅ 干净 | 无密码、密钥、IP 硬编码 |
| 外部脚本执行 | ⚠️ 已记录 | Docker 安装（`get.docker.com`）、YABS（`yabs.sh`）、bench.sh、NextTrace、IPQuality、融合怪——均来自官方源，均需用户确认 |
| `eval` 使用 | ✅ 安全 | 仅用于包管理器命令（`eval "$PKG_INSTALL foo"`）——无用户输入到达 eval |
| `rm -rf` 使用 | ✅ 有防护 | 仅在 Docker 卸载中，需双重确认 |
| 自更新机制 | ✅ HTTPS | 从 GitHub raw 通过 HTTPS 下载 |
| 输入验证 | ✅ 存在 | 所有交互输入在使用前验证 |

## 脚本 vs 模块化：用哪个？

| 需求 | 用 |
|---|---|
| 快速上手，一条命令，菜单驱动 | **vps_secure.sh**（本 repo） |
| 模块化，CLI 驱动，逐模块控制 | [vps-bootstrap](https://github.com/0x10debug/vps-bootstrap) |
| CIS 基准审计，漂移检测 | [security-audit](https://github.com/0x10debug/security-audit) |

vps_secure.sh 和 vps-bootstrap 都覆盖 SSH/防火墙/Fail2Ban/内核加固——它们是同一能力的两个入口。脚本面向"我只想搞定"，模块化工具面向"我想控制每一步并与其他工具集成"。

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

评测与探测能力调用：[YABS](https://github.com/masonr/yabs) · [bench.sh](https://bench.sh) · [NextTrace](https://github.com/nxtrace/NTrace-core) · [融合怪](https://github.com/spiritLHLS/ecs) · [IPQuality](https://github.com/xykt/IPQuality) · [Lynis](https://cisofy.com/lynis/) · [Endlessh](https://github.com/skeeto/endlessh)。应用部署依赖 [Docker](https://docker.com) 与 [1Panel](https://1panel.cn) 官方脚本。

## 许可

[MIT](LICENSE) © 2026 0x10debug
