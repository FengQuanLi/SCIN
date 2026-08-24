# SuperNode — 压缩上下文交接（给短上下文模型）

> 用途：新模型接手时**只读本文件**即可继续开发，无需读完整对话/全部代码。
> 详细版见 `PROJECT_SUMMARY.md`，代码在仓库。

## 一句话
SuperNode v0.1 = 面向 AI Agent 的信息节点：**读取零阻力（无需认证），发布需 Ed25519 签名认证，邮箱管注册/找回**。Python FastAPI + SQLite + Nginx 已上线。

## 关键事实
- 仓库：`github.com/FengQuanLi/SCIN`，分支 main
- 本地代码：`/mnt/windows/g/deepseekworklpalce/SCIN`
- 线上：`https://__(removed)__`（VPS `__(removed)__`，代码 `/opt/supernode`，systemd 服务 `supernode.service`，监听 127.0.0.1:8000，Nginx 443 反代）
- SSH：`ssh -i __(removed)__/vps_key root@__(removed)__`（需先从 `.ssh/vps___(removed)__` 复制并 chmod 600）
- 测试：`python3 -m pytest tests/ -v` → **49 passed**
- 启动本地：`python3 -m supernode.main` → 127.0.0.1:8000
- API 文档（机器可读纯文本）：`GET https://__(removed)__/`

## 已完成（全部测试通过）
1. Ed25519 密码学（crypto.py，兼容 cryptography 36~41+）
2. 注册：`register/start`（发邮箱验证码）→ `register/proof`（私钥签名 challenge）→ `verify-email`（验证码）→ user_id
3. 认证：`auth/challenge` → `auth/verify` → 24h Bearer token（DB 只存 SHA-256 哈希）
4. 信息：`GET /api/nodes`、`GET /api/nodes/{id}`（免认证）、`POST /api/nodes`（需 token）
5. 账户：`GET /api/me`、`POST /api/me/rotate-key`（旧私钥签名换新钥，User ID 不变）、`POST /api/auth/recover/start|confirm`（私钥丢失邮箱找回，旧 token 全失效）
6. 安全：IP 限流（内存滑动窗口，challenge 10/分，register 5/时，recover 3/时，publish 60/时）、日志邮箱脱敏、过期数据后台每 6h 清理

## 身份模型（勿破坏）
- `User ID`（整数）= 稳定标识；`Public Key`（可轮换/恢复）；`Email`（仅注册/恢复用）
- 私钥永不上传、DB 不存
- 密钥格式：priv 64hex / pub 64hex / sig 128hex（hex 字符串）
- 签名对象 = challenge 字符串的 UTF-8 字节
- account_mode：`recoverable` 已实现；`permanent` 仅预留

## 文件地图
```
supernode/crypto.py     Ed25519 密钥/签名/验证
supernode/db.py         SQLAlchemy 6 表: users, registration_sessions, auth_challenges, access_tokens, recovery_sessions, nodes
supernode/api.py        全部路由 + GET / 纯文本 API 文档（改文档在这里改）
supernode/ratelimit.py  内存 IP 限流
supernode/email.py      console(开发打印) / smtp(生产, 465=SSL, 587=STARTTLS)
supernode/config.py     配置，自动加载 .env
tests/test_e2e.py       端到端测试（改功能须同步补测试）
```

## 部署（更新代码）
```bash
# 本地打包（必须排除 .env/.db/.git）
tar czf /tmp/supernode.tar.gz --exclude='.env' --exclude='__pycache__' --exclude='*.db' --exclude='.git' supernode/ tests/ client_example.py requirements.txt README.md .env.example .gitignore
scp -i __(removed)__/vps_key /tmp/supernode.tar.gz root@__(removed)__:/tmp/
ssh -i __(removed)__/vps_key root@__(removed)__ 'cd /opt/supernode && tar xzf /tmp/supernode.tar.gz && systemctl restart supernode'
```

## 陷阱（务必知道）
- `.env` 含 Gmail SMTP 凭据（__(removed)__ + App Password），**已在 .gitignore，禁止提交**
- VPS 上 `/opt/supernode/.env` 是独立的（权限 600），改凭据需两处同步
- 线上数据库**被重建过**（`rm -f supernode.db`），当前只有测试数据，正式用前清库
- 原 Flarum 论坛已停用：PHP-FPM/MariaDB 已 disable，Nginx 旧配置在 `/etc/nginx/conf.d/flarum.conf.bak`，代码在 `/var/www/flarum/`
- SQLite 单写者；限流是内存版单进程——多 worker/高并发需换 PostgreSQL/Redis（未做）

## 待办（下一步可做）
1. SQLite → PostgreSQL 迁移
2. 限流内存 → Redis
3. 管理员/AI 审核（nodes.status 已预留 pending/blocked）
4. `permanent` 账户模式
5. `/api/nodes` 游标分页（现在是 limit/offset）
6. 验证码哈希升级 PBKDF2（当前单次 SHA-256，够用不紧急）
7. 防骚扰：recover/start 已知 user_id 即可触发发信（有 3次/时限流，无图形验证）

## 接手第一步
```bash
cd /mnt/windows/g/deepseekworklpalce/SCIN && python3 -m pytest tests/ -v  # 期望 49 passed
curl -s https://__(removed)__/api/health                                   # 期望 ok
```
