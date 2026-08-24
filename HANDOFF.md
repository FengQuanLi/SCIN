# SuperNode — 压缩上下文交接（给短上下文模型）

> 用途：新模型接手时**只读本文件**即可继续开发，无需读完整对话/全部代码。
> 详细版见 `PROJECT_SUMMARY.md`，代码在仓库。

## 一句话
SuperNode v0.1 DRY-RUN = 面向 AI Agent 的信息节点：**读取零阻力（匿名），发布需 Ed25519 签名认证，邮箱只在注册那一瞬间防暴力注册**。认证不再签发 token。发布返回随机 stub id，不入库、不写日志、不对外可见。Python FastAPI + SQLite + Nginx 已上线。

## 关键事实
- 仓库：`github.com/FengQuanLi/SCIN`，分支 main（**当前未 commit/push，等用户明确指示**）
- 本地代码：`/mnt/windows/g/deepseekworklpalce/SCIN`
- 线上：`https://__(removed)__`（VPS `__(removed)__`，代码 `/opt/supernode`，systemd 服务 `supernode.service`，监听 127.0.0.1:8000，Nginx 443 反代）
- VPS Python **3.9.25**：所有 .py 文件顶部须保留 `from __future__ import annotations`
- SSH：`ssh -i __(removed)__/vps_key root@__(removed)__`（需先从 `.ssh/vps___(removed)__` 复制并 chmod 600）
- 测试：`python3 -m pytest tests/test_e2e.py -q` → **35 passed**
- 启动本地：`python3 -m supernode.main` → 127.0.0.1:8000
- 远程主页（HTML）：`GET https://__(removed)__/`
- 远程接入页（纯文本）：`GET https://__(removed)__/en.html`
- 一句话提示词（可整段复制）：`GET https://__(removed)__/connect.txt`
- 机器可读 API 文档（纯文本）：`GET https://__(removed)__/api/docs`

## 已完成（v0.1 最终协议，DRY-RUN）
1. Ed25519 密码学（crypto.py，兼容 pynacl / cryptography）
2. **签名作用域 = challenge 字符串的 UTF-8 字节**（不做 `challenge:METHOD:PATH:TIMESTAMP` 之类的扩展）
3. 注册：`register/start{email,public_key}` → `{registration_id(64hex), challenge(32hex)}`；`register/proof{registration_id,signature}`；`verify-email{registration_id,code}` → `{ok, user_id}`。必须按 1→2→3 顺序；倒序 412；challenge 一次性，TTL 15 min；reused 410。
4. 认证：`auth/challenge{user_id}` → `{challenge_id, challenge}`，TTL 5 min，一次性；`auth/verify{challenge_id,signature}` → **`{user_id}` 仅此一个字段**（`AuthVerifyResp` 不再含 token）。
5. **发布 DRY-RUN**：`POST /api/nodes` body `{content(min_length=1), registration_id}` + `Authorization: Bearer <token>`。
   - 校验顺序（互斥，第一个失败即返回）：
     ① 缺 Bearer 头 → 401
     ② `registration_id` 缺失/空 → 422（fastapi.HTTPException(422)）
     ③ token 非法/过期/不存在 → 401（`_token_to_user` 短路）
     ④ `content` 为空 → 422（pydantic min_length=1）
     ⑤ 全部通过 → 201 + 随机 stub id（`secrets.randbelow(10**12)`）
   - 无 Node 行、无 commit、无 logger.info
   - 短路性质：非法 token 场景**简短措辞** 401，不进入后端
6. token 形式（仅 `_token_to_user` 里解析）：
   - `mock-token-<数字>` → 数字部分 = user_id
   - 纯数字字符串 → user_id
   - 64 位 lowercase hex → SHA-256 查 `access_tokens` 表兜底兼容
   - 其他 → 401 "Token 无效或已过期"
7. 恢复（v0.1 空壳）：
   - `POST /api/auth/recover/start` — 做用户存在性检查 + `crypto.generate_challenge()`，**不持久化 challenge 池**
   - `POST /api/auth/recover/confirm` — **只做** 64-hex signature 长度检查
   - 限流 rl_recover=(3, 3600)
8. 速率限制（sliding window 内存版）：
   - `rl_register_start=(5, 3600)` 按 IP
   - `rl_auth_challenge=(10, 60)` 按 IP
   - `rl_publish=(60, 3600)` 按 IP
   - `rl_recover=(3, 3600)` 按 IP
   - `registration_challenge_ttl=300`、`auth_challenge_ttl=300`、`email_code_ttl=900`
   - 超限 → `HTTP 429`
9. 422 实现是 `fastapi.HTTPException(status_code=422, detail=...)`，**不是** pydantic model 拒收
10. HTML 壳 + 纯文本模板全部在 `supernode/html.py`（CSS/JS 用 raw-text 常量，避开 `{{ }}` 转义地狱）
11. AI Agent 接入指引（`/en.html` + `/connect.txt`）按最终协议重写

## 身份模型（勿破坏）
- `user_id`（整数）= 稳定标识；`public_key`（64 hex）= 唯一身份，**一经注册不可变**
- **无 rotate-key 接口**（`POST /api/me/rotate-key` 已删除）
- **无 account_mode**（recoverable/permanent 概念已删除）
- 邮箱只用于一次性注册，不参与日常认证、也不能找回
- 私钥丢失 = 账户永久丢失（Bitcoin 语义），无找回
- 密钥格式：pub 64hex / priv 64hex / sig 128hex (hex 字符串)
- 签名对象 = **仅** challenge 字符串的 UTF-8 字节

## 端点清单（v0.1 最终，恰好 15 个）
```
GET  /                       首页（HTML）
GET  /en.html                纯文本接入手册
GET  /connect.txt            AI Agent 提示词
GET  /api/docs               本页（纯文本）
POST /api/register/start
POST /api/register/proof
POST /api/register/verify-email
POST /api/auth/challenge
POST /api/auth/verify
POST /api/nodes               （DRY-RUN）
GET  /api/nodes
GET  /api/nodes/{id}
GET  /api/me
GET  /api/health
POST /api/auth/recover/start
POST /api/auth/recover/confirm
```

## 文件地图
```
supernode/crypto.py     Ed25519 密钥/签名/验证
supernode/db.py         SQLAlchemy 模型 + access_tokens（仅 SHA-256 兜底使用）
supernode/api.py        全部路由（约 640 行）；create_node 里内嵌 DRY-RUN NOTE
supernode/html.py       HTML 壳 + ONBOARDING_TEMPLATE + AGENT_PROMPT_TEMPLATE + API_DOCS_TEXT
supernode/ratelimit.py  内存 IP 限流（RateLimit 数据类 + get_limiter）
supernode/email.py      console(开发打印) / smtp(生产, 465=SSL, 587=STARTTLS)
supernode/config.py     配置，自动加载 .env（含 4 条 rl defaults）
tests/test_e2e.py       35 条 E2E（改功能须同步补测试）
client_example.py       可执行流程示例（含 mock-token 用法）
.env.example            环境变量模板（可提交）
.env                    本地凭据（已 gitignore，勿提交）
```

## 部署（更新代码，一条 bash 调用搞定 VPS key 暂存）
```bash
bash -e
WORKSPACE=/mnt/windows/g/deepseekworklpalce
cd $WORKSPACE/SCIN
mkdir -p __(removed)__
cp $WORKSPACE/.ssh/vps___(removed)__ __(removed)__/vps_key
chmod 600 __(removed)__/vps_key
rm -f _sn_deploy.tar.gz
tar czf _sn_deploy.tar.gz \
  --exclude='_sn_deploy.tar.gz' --exclude='.env' --exclude='__pycache__' \
  --exclude='*.db' --exclude='.git' --exclude='.pytest_cache' \
  supernode/ tests/ client_example.py requirements.txt README.md HANDOFF.md \
  PROJECT_SUMMARY.md .env.example .gitignore
scp -i __(removed)__/vps_key -o StrictHostKeyChecking=no _sn_deploy.tar.gz root@__(removed)__:/tmp/_sn_deploy.tar.gz
ssh -i __(removed)__/vps_key -o StrictHostKeyChecking=no root@__(removed)__ '
  set -e
  cd /opt/supernode && tar xzf /tmp/_sn_deploy.tar.gz && rm /tmp/_sn_deploy.tar.gz
  systemctl restart supernode && sleep 2 && systemctl is-active supernode
'
```

## 陷阱（务必知道）
- `.env` 含 Gmail SMTP 凭据（__(removed)__ + App Password），**已在 .gitignore，禁止提交**
- VPS 上 `/opt/supernode/.env` 是独立的（权限 600），改凭据需两处同步
- 线上数据库**被重建过**（`rm -f supernode.db`），当前只有测试数据，正式用前清库
- 原 Flarum 论坛已停用：PHP-FPM/MariaDB 已 disable，Nginx 旧配置在 `/etc/nginx/conf.d/flarum.conf.bak`，代码在 `/var/www/flarum/`
- SQLite 单写者；限流是内存版单进程——多 worker/高并发需换 PostgreSQL/Redis（未做）
- **`/tmp` 是临时性的**：每次 bash 调用之间 `__(removed)__` 可能不存在，所以 key 暂存必须在同一条 bash 命令里
- **commit/push 仅当用户明确要求**——当前不 commit

## 用户立场（verbatim）
> "邮箱只是在注册的时候防止暴力注册。一旦注册成功的话，公钥作为唯一的身份，原则上不应该被改掉，改掉以后反而不好"
> "默默地实现，工作，只与提示词/草稿和下一条消息通信"

DRY-RUN NOTE 也需保留在 `create_node` 的 docstring 与 html 文档里：
> "它不来自档案库（配置不算资产）；不写日志、不写库、不对外网络可见。只与提示词/草稿和下一条消息通信。"

## 待办（下一步可做）
1. 把 DRY-RUN stub 换成真正落库的发布（保留 5 步校验顺序与凭据解析）
2. SQLite → PostgreSQL 迁移
3. 限流内存 → Redis
4. 管理员/AI 审核（`nodes.status` 已预留 pending/blocked）
5. `/api/nodes` 游标分页（现在是 limit/offset）
6. 证书/密码哈希升级 PBKDF2
7. `recovered_token` 之类未启用的"新 token 签发"统一**保持清除**，不要回滚
8. 部署时记得清库：`rm -f /opt/supernode/supernode.db` 再来一次（视情况）

## 接手第一步
```bash
cd /mnt/windows/g/deepseekworklpalce/SCIN && python3 -m pytest tests/test_e2e.py -q  # 期望 35 passed
curl -s https://__(removed)__/api/health                                             # 期望 ok
curl -s https://__(removed)__/api/docs | grep -c mock-token   # 期望 ≥ 1
```
