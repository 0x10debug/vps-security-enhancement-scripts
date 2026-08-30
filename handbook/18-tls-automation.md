# 第 18 章：TLS 证书自动化

> **场景**：你在一台 VPS 上跑了三个服务——一个博客、一个 API、一个 Grafana 仪表盘。每个都用不同的子域名，每个都需要 HTTPS。你不想每隔三个月手动续期证书，更不想因为证书过期导致服务中断被用户投诉。

## 为什么需要 TLS 自动化

TLS 证书是 HTTPS 的基石。没有有效证书，浏览器会显示安全警告，API 客户端会拒绝连接，搜索引擎会降权。但证书管理是典型的"重要但不紧急"工作——直到过期那天才变成紧急。

手动管理证书的问题：

1. **容易忘记续期**——Let's Encrypt 证书有效期 90 天，商业 CA 通常 1 年。人脑不擅长记住这种周期性任务。
2. **续期需要停机**——传统方式续期需要重启 Web 服务器，如果没有自动化流程，要么手动停机，要么冒险热替换。
3. **多域名管理混乱**——一台 VPS 上跑多个子域名时，每个域名单独管理很快变成噩梦。
4. **故障不可见**——证书续期失败时没有告警，直到用户报告"你的网站打不开了"才知道。

## 工具选型：acme.sh vs certbot

| 维度 | acme.sh | certbot |
|---|---|---|
| 依赖 | 纯 shell，无依赖 | Python + 虚拟环境 |
| 体积 | ~200KB | ~50MB（含依赖） |
| DNS API 支持 | 150+ 提供商 | ~30 插件 |
| 自动续期 | cron | systemd timer |
| ECC 证书 | 原生支持 | 需要额外配置 |
| 撤销/删除 | 内置 | 内置 |
| 适用场景 | VPS 轻量环境 | 有 Python 环境的服务器 |

**推荐**：VPS 场景下优先用 acme.sh——纯 shell 实现，无依赖，DNS API 覆盖最广（包括国内 DNS 提供商）。

## 签发策略

### DNS-01 vs HTTP-01

| 验证方式 | 适用场景 | 优势 | 限制 |
|---|---|---|---|
| DNS-01 | 通配符证书、内网服务、80 端口被占用 | 不需要开放 80 端口，支持通配符 | 需要 DNS API 凭据 |
| HTTP-01 | 单域名、简单部署 | 零配置 | 80 端口必须可用 |

**决策树**：

```
需要通配符证书 (*.example.com)?
├── 是 → DNS-01（唯一选择）
└── 否
    ├── 80 端口可用且不想配置 DNS API → HTTP-01 (standalone)
    └── 80 端口被占用或有 DNS API 凭据 → DNS-01
```

### 密钥类型

| 类型 | 推荐场景 | 性能 | 兼容性 |
|---|---|---|---|
| EC-256 | 通用推荐 | 最快 | 99% 客户端支持 |
| EC-384 | 高安全需求 | 快 | 99% 客户端支持 |
| RSA-2048 | 旧客户端兼容 | 中 | 100% |
| RSA-4096 | 最高 RSA 安全 | 慢 | 100% |

**推荐**：EC-256。除非有明确的旧客户端兼容需求，否则不需要 RSA。

## 部署到反向代理

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/nginx/ssl/example.com/fullchain.cer;
    ssl_certificate_key /etc/nginx/ssl/example.com/example.com.key;

    # 只启用 TLS 1.2 和 1.3
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;

    # 会话缓存
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}
```

acme.sh 自动部署 hook：
```bash
acme.sh --install-cert -d example.com \
    --fullchain-file /etc/nginx/ssl/example.com/fullchain.cer \
    --key-file       /etc/nginx/ssl/example.com/example.com.key \
    --reloadcmd      "nginx -t && systemctl reload nginx"
```

### Caddy

Caddy 内置自动 TLS 管理，通常不需要 acme.sh。但如果需要手动管理证书（例如使用内部 CA）：

```caddyfile
example.com {
    tls /etc/caddy/ssl/example.com/fullchain.cer /etc/caddy/ssl/example.com/example.com.key {
        protocols tls1.2 tls1.3
    }
    reverse_proxy localhost:8080
}
```

### HAProxy

HAProxy 需要将证书和私钥合并为一个 PEM 文件：

```bash
cat fullchain.cer example.com.key > example.com-combined.pem
chmod 600 example.com-combined.pem
```

```haproxy
frontend https
    bind *:443 ssl crt /etc/haproxy/ssl/example.com-combined.pem alpn h2,http/1.1
    http-response set-header Strict-Transport-Security "max-age=63072000"
    default_backend backend
```

## 自动续期

acme.sh 安装后自动添加 cron 任务：

```cron
# 每天凌晨检查并续期即将过期的证书
0 0 * * * /root/.acme.sh/acme.sh --cron --home /root/.acme.sh
```

### 验证自动续期是否工作

```bash
# 查看 cron 任务
crontab -l | grep acme

# 手动触发续期检查
acme.sh --cron

# 查看续期日志
tail -20 /root/.acme.sh/acme.sh.log
```

### 续期失败排查

| 症状 | 可能原因 | 解决方案 |
|---|---|---|
| DNS 验证失败 | DNS API 凭据过期 | 更新环境变量，重新运行 |
| HTTP 验证失败 | 80 端口被占用 | 停止占用 80 端口的服务，或切换到 DNS-01 |
| 续期成功但服务没更新 | reloadcmd 未配置 | 添加 --reloadcmd 参数 |
| 证书目录不存在 | 路径变更 | 检查 --fullchain-file --key-file 路径 |

## 证书监控

### 自动监控脚本

本项目的 `tls_lifecycle.sh --monitor` 会扫描所有证书并报告过期状态：

```bash
# 手动检查
sudo ./scripts/tls_lifecycle.sh --monitor

# 生成 cron 监控脚本
sudo ./scripts/tls_lifecycle.sh --monitor --output ./tls-configs
# 然后: crontab -e
# 0 8 * * * /path/to/tls-monitor-cron.sh
```

### 监控告警级别

| 级别 | 剩余天数 | 颜色 | 动作 |
|---|---|---|---|
| OK | > 30 天 | 绿色 | 无需操作 |
| WARNING | 15-30 天 | 黄色 | 检查自动续期是否正常 |
| CRITICAL | < 15 天 | 红色 | 立即手动续期 |
| EXPIRED | < 0 天 | 红色 | 证书已过期，服务可能中断 |

## TLS 审计

`tls_lifecycle.sh --audit` 执行 13 项只读检查：

| 检查 ID | 检查内容 |
|---|---|
| TLS-001 | acme.sh 已安装 |
| TLS-002 | acme.sh cron 自动续期已配置 |
| TLS-003 | acme.sh 默认 CA 已设置 |
| TLS-004 | 已管理证书数量 |
| TLS-005 | 证书未过期 |
| TLS-006 | 证书密钥强度 (EC-256+ 或 RSA-2048+) |
| TLS-007 | Nginx 启用 TLS 1.3 |
| TLS-008 | Nginx 禁用 TLS 1.0/1.1 |
| TLS-009 | Caddy 自动 TLS 管理 |
| TLS-010 | HSTS 已配置 |
| TLS-011 | acme.sh cron 自动续期已配置 |
| TLS-012 | certbot 自动续期 timer |
| TLS-013 | OCSP Stapling 已配置 |

## 常见问题

### Q: 通配符证书怎么签发？

```bash
acme.sh --issue -d *.example.com -d example.com --dns cloudflare -k ec-256
```

需要 DNS-01 验证。注意通配符证书覆盖 `*.example.com` 但不覆盖 `example.com` 本身，需要同时添加 `-d example.com`。

### Q: 内网服务怎么用 Let's Encrypt 证书？

内网服务无法通过 HTTP-01 验证（外部无法访问内网 80 端口）。使用 DNS-01 验证——只需要 DNS 记录指向公网 IP，不需要服务本身被公网访问。

### Q: 证书签发频率限制？

Let's Encrypt 限制：
- 每个注册域名每周 50 个证书
- 每个证书最多 100 个域名
- 重复证书每月 5 个
- 失败重试每小时 5 次

正常使用不会触发限制。测试时使用 `--staging` 环境避免消耗配额。

### Q: 如何迁移到新服务器？

```bash
# 旧服务器: 导出
acme.sh --info -d example.com  # 查看配置
cp -r /root/.acme.sh/ /backup/

# 新服务器: 导入
cp -r /backup/.acme.sh/ /root/
acme.sh --renew -d example.com --force  # 强制续期以验证新服务器
```

## 与其他工具的协作

| 工具 | 协作方式 |
|---|---|
| network-toolkit | Caddy/Nginx/HAProxy 反代模板配合 TLS 部署 |
| monitor-stack | 证书过期告警集成到监控体系 |
| waf_setup.sh | WAF 需要 TLS 终结，TLS 证书是 WAF 部署的前置条件 |
| zerotrust_setup.sh | 零信任网络中控制面需要 TLS |

## 速查

```bash
# 安装
sudo ./scripts/tls_lifecycle.sh --install

# 签发 (DNS 验证)
sudo ./scripts/tls_lifecycle.sh --issue --domain example.com --dns cloudflare

# 签发 (standalone)
sudo ./scripts/tls_lifecycle.sh --issue --domain example.com --standalone

# 部署到 Nginx
sudo ./scripts/tls_lifecycle.sh --deploy --domain example.com --proxy nginx

# 续期
sudo ./scripts/tls_lifecycle.sh --renew

# 监控
sudo ./scripts/tls_lifecycle.sh --monitor

# 审计
sudo ./scripts/tls_lifecycle.sh --audit
```
