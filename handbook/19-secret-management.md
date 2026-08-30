# 第 19 章：密钥管理与秘密扫描

> **场景**：你把一个新项目推到 GitHub 后，突然发现 `.env` 文件里的数据库密码和 API key 也被推上去了。即使你立刻删除文件并重新提交，密码仍然存在于 git 历史中。任何能 clone 这个仓库的人都能用 `git log -p` 找到你的密码。你需要知道：怎么扫描泄露的密钥、怎么清理历史、怎么防止再次发生。

## 为什么密钥扫描是必要的

密钥泄露是云时代最常见的安全事故之一。根据 GitGuardian 的年度报告，GitHub 上每天有数千个新的密钥泄露事件，且泄露后的密钥在平均 4 小时内就会被攻击者利用。

密钥泄露的典型路径：

1. **误提交**——`.env` 文件、配置文件包含真实密钥，被 `git add .` 一并提交
2. **硬编码**——为了"方便调试"把 API key 直接写在代码里，忘记移除
3. **历史残留**——早期提交了密钥，后来删除了文件，但 git 历史中仍然存在
4. **复制粘贴**——从文档或测试代码中复制了包含真实密钥的片段

## 工具选型：gitleaks vs trufflehog

| 维度 | gitleaks | trufflehog |
|---|---|---|
| 速度 | 快（正则匹配） | 慢（验证每个密钥） |
| 准确率 | 中（有误报） | 高（验证密钥有效性） |
| 验证 | 不验证 | 向 API 发请求验证 |
| Git 历史 | 原生支持 | 原生支持 |
| CI 集成 | 轻量 | 较重 |
| 适用场景 | 快速扫描 + pre-commit | 深度审计 + 泄露确认 |

**推荐组合**：日常用 gitleaks 做快速扫描和 pre-commit 拦截，定期用 trufflehog 做深度验证。

## 扫描策略

### 快速扫描（gitleaks）

```bash
# 扫描当前工作区
sudo ./scripts/secret_scan.sh --scan --path /your/project

# 扫描 git 历史（所有 commit）
sudo ./scripts/secret_scan.sh --scan-git --path /your/project
```

gitleaks 使用 100+ 内置规则检测常见密钥模式：
- AWS Access Key（`AKIA...`）
- GitHub Token（`ghp_...`、`gho_...`）
- GitLab Token（`glpat-...`）
- Slack Token（`xox...`）
- OpenAI API Key（`sk-...`）
- Google API Key（`AIza...`）
- 私钥文件（`-----BEGIN ... PRIVATE KEY-----`）
- 数据库连接字符串
- 通用密码/密钥模式

### 深度扫描（trufflehog）

```bash
# 深度扫描（验证密钥是否仍然有效）
sudo ./scripts/secret_scan.sh --deep --path /your/project
```

trufflehog 会对每个发现的密钥发送验证请求到对应 API：
- AWS key → 尝试调用 STS GetCallerIdentity
- GitHub token → 尝试调用 /user API
- 数据库密码 → 尝试连接

**注意**：验证过程会向外部 API 发送请求。如果密钥已泄露，这不会增加风险（攻击者也在做同样的事）。但如果密钥是误报，验证请求可能触发 API 的异常检测。

### 扫描决策树

```
需要扫描密钥?
├── 日常开发 → gitleaks 快速扫描 (--scan)
├── 代码审计 → gitleaks + trufflehog (--scan + --deep)
├── 怀疑历史泄露 → gitleaks git 历史扫描 (--scan-git)
└── CI/CD 流水线 → gitleaks pre-commit + GitHub Actions
```

## CI/CD 集成

### GitHub Actions

```bash
# 生成 GitHub Actions 配置
sudo ./scripts/secret_scan.sh --ci --output ./ci-configs
# 复制到项目:
cp ci-configs/github-actions/secret-scan.yml .github/workflows/
```

生成的 workflow 在每次 push 和 PR 时自动运行 gitleaks，发现密钥则阻止合并。

### pre-commit hook

```bash
# 生成 pre-commit hook
sudo ./scripts/secret_scan.sh --ci --output ./ci-configs
# 安装:
cp ci-configs/pre-commit-hook.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

pre-commit hook 在每次 `git commit` 前扫描暂存区文件，发现密钥则阻止提交。

### .gitleaksignore

对于已知的误报，添加到 `.gitleaksignore`：

```
# 格式: <fingerprint>
# 从 gitleaks JSON 输出的 "Fingerprint" 字段获取
a1b2c3d4e5f6:src/config/example.ts:42
```

## 密钥泄露应急响应

### 步骤 1：确认泄露范围

```bash
# 扫描 git 历史
sudo ./scripts/secret_scan.sh --scan-git --path /your/project

# 深度验证泄露的密钥是否仍然有效
sudo ./scripts/secret_scan.sh --deep --path /your/project
```

### 步骤 2：立即轮换所有泄露的密钥

**这是最重要的一步。** 不要试图先清理 git 历史——密钥已经泄露，清理历史不能撤销泄露。

| 密钥类型 | 轮换方式 |
|---|---|
| AWS Access Key | IAM 控制台 → 删除旧 key → 创建新 key |
| GitHub Token | Settings → Developer settings → 删除旧 token → 创建新 token |
| 数据库密码 | 修改数据库密码 + 更新所有使用该密码的服务 |
| API Key | 在对应平台重新生成 |
| SSH 私钥 | 生成新密钥对 + 更新 authorized_keys |

### 步骤 3：清理 git 历史

```bash
# 使用 git filter-repo（推荐）
pip install git-filter-repo
git filter-repo --invert-paths --path .env --path config/secrets.yml

# 或使用 BFG Repo-Cleaner
java -jar bfg.jar --delete-files .env
java -jar bfg.jar --replace-text passwords.txt
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

### 步骤 4：通知相关方

- 通知所有有仓库访问权限的人
- 如果仓库是 public，假设密钥已被未知第三方获取
- 更新所有 CI/CD 中的密钥变量
- 检查是否有异常 API 调用（查看云平台日志）

## 密钥管理审计

`secret_scan.sh --audit` 执行 13 项只读检查：

| 检查 ID | 检查内容 |
|---|---|
| SEC-001 | gitleaks 已安装 |
| SEC-002 | trufflehog 已安装 |
| SEC-003 | 敏感文件存在且已在 .gitignore |
| SEC-004 | .gitignore 存在 |
| SEC-005 | .gitignore 包含密钥相关模式 |
| SEC-006 | 未发现硬编码密钥模式 |
| SEC-007 | GitHub Actions 无硬编码密钥 |
| SEC-008 | GitHub Actions 使用 secrets 变量 |
| SEC-009 | pre-commit hook 包含密钥扫描 |
| SEC-010 | .gitleaksignore 存在 |
| SEC-011 | gitleaks.toml 自定义配置存在 |
| SEC-012 | 敏感文件权限 (600/400) |
| SEC-013 | Docker Compose 密钥管理 |

## 密钥管理最佳实践

### 1. 永远不要硬编码密钥

```bash
# ❌ 错误
API_KEY="sk-1234567890abcdef..."

# ✅ 正确
API_KEY="${API_KEY:?API_KEY not set}"
# 从环境变量、.env 文件、或密钥管理服务获取
```

### 2. .env 文件不入库

```gitignore
# .gitignore
.env
.env.*
!.env.example
```

### 3. 使用 .env.example 提供模板

```bash
# .env.example (入库)
DATABASE_URL=postgresql://user:pass@localhost:5432/db
API_KEY=your_api_key_here

# .env (不入库，真实值)
DATABASE_URL=postgresql://admin:s3cr3t@prod-db:5432/myapp
API_KEY=sk-real-key-here
```

### 4. 文件权限

```bash
chmod 600 ~/.env
chmod 600 ~/.ssh/id_rsa
chmod 600 ~/.ssh/id_ed25519
chmod 600 ~/.aws/credentials
```

### 5. Docker secrets

```yaml
# docker-compose.yml
services:
  app:
    environment:
      - DATABASE_PASSWORD_FILE=/run/secrets/db_password
    secrets:
      - db_password

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

## 常见问题

### Q: gitleaks 误报太多怎么办？

1. 将误报添加到 `.gitleaksignore`
2. 在 `gitleaks.toml` 的 `[allowlist]` 中添加路径或正则
3. 对测试文件使用 `# gitleaks:allow` 注释

### Q: git 历史清理后需要 force push 吗？

是的。清理历史会重写所有 commit hash，需要 `git push --force`。确保所有协作者先 pull 旧代码备份本地分支，force push 后重新 clone。

### Q: 密钥泄露后多久内需要轮换？

**立即。** GitHub 的扫描机器人会在密钥推到公开仓库后几分钟内检测到并通知对应平台。AWS 会在 1-2 小时内自动禁用泄露的 key。不要等待，立即轮换。

### Q: 私有仓库也需要密钥扫描吗？

需要。私有仓库的密钥泄露风险虽然低于公开仓库，但仍然存在：
- 协作者离职后仍持有密钥
- 仓库意外改为公开
- 第三方集成（CI/CD、代码分析）获得访问权
- 供应链攻击

## 速查

```bash
# 安装工具
sudo ./scripts/secret_scan.sh --install

# 审计密钥管理
sudo ./scripts/secret_scan.sh --audit

# 快速扫描
sudo ./scripts/secret_scan.sh --scan --path /project

# Git 历史扫描
sudo ./scripts/secret_scan.sh --scan-git --path /project

# 深度验证
sudo ./scripts/secret_scan.sh --deep --path /project

# 生成 CI 配置
sudo ./scripts/secret_scan.sh --ci --output ./ci-configs
```
