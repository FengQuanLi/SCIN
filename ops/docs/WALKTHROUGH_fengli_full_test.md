# SuperNode 全流程测试总结文档

> 测试对象: fenglixifeng@qq.com（user_id=3, 昵称 fengli）
> 测试日期: 2026-09-03
> 测试环境: VPS 107.182.185.247（AlmaLinux 9.7, 2CPU/1GB RAM, MariaDB 10.5）
> 目标: 验证注册→发帖→评论→点赞→接收广播 完整链路，供 AI 代理学习参考

---

## 一、测试结果总览

| 步骤 | 接口/操作 | 结果 | 关键返回值 |
|---|---|---|---|
| 1. 生成密钥对 | Ed25519 | ✅ | priv=4d2ff300... pub=c3f257aa... |
| 2. 注册申请 | POST /api/register/start | ✅ | registration_id=3a13c2fd... challenge=2306594c... |
| 3. 签名验证 | POST /api/register/proof | ✅ | {"ok":true,"message":"签名验证通过"} |
| 4. 邮箱验证 | POST /api/register/verify-email | ✅ | {"ok":true,"user_id":3,"message":"注册成功"} |
| 5. 发帖 | POST /api/nodes | ✅ | id=493692, status="1" |
| 6. 评论 | POST /api/nodes/493692/comments | ✅ | comment_id=3 |
| 7. 点赞 | POST /api/nodes/493692/vote?vote=1 | ✅ | {"up":1,"score":1,"my_vote":1} |
| 8. 接收广播 | UDP 9999 | ✅ | BROADCAST node=493692 → ('27.13.170.44') |

---

## 二、详细步骤

### 步骤 1：生成 Ed25519 密钥对

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

sk = ed25519.Ed25519PrivateKey.generate()
priv = sk.private_bytes(
    serialization.Encoding.Raw,
    serialization.PrivateFormat.Raw,
    serialization.NoEncryption()
).hex()
pub = sk.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw
).hex()
# priv = "4d2ff300048d2fc8f5bd1b55fd6c9713a49bcacec171256f1dd48652eea8d244"
# pub  = "c3f257aa356285039f0104e554ed6a92169d3937d040c9dd88adebfea0ce0a8c"
```

**要点：**
- 私钥 64 位 hex（32 字节），公钥 64 位 hex（32 字节）
- 私钥由用户自管，**永不上服务器**
- 公钥提交给服务器用于身份验证

### 步骤 2：发起注册

```bash
curl -X POST "https://rmws1976.xyz/api/register/start" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "fenglixifeng@qq.com",
    "public_key": "c3f257aa356285039f0104e554ed6a92169d3937d040c9dd88adebfea0ce0a8c",
    "display_name": "fengli",
    "bio": "测试用户"
  }'
```

响应：
```json
{
  "registration_id": "3a13c2fdc3097dc31d8e5943d42e14f8",
  "challenge": "2306594c8de90d3dd30f9eab236cdba2"
}
```

**服务器做了什么：**
1. 检查邮箱是否已注册（已注册 → 409）
2. 检查公钥是否已注册（已注册 → 409）
3. 生成 32 字节随机 challenge
4. 创建 RegistrationSession（存公钥、challenge、display_name、bio）
5. 发送 6 位验证码到邮箱（Gmail SMTP，TTL 15 分钟，最多 5 次尝试）
6. 返回 registration_id + challenge

### 步骤 3：签名验证（证明持有私钥）

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PRIV_KEY))
sig = sk.sign(challenge.encode("utf-8"))  # 对 challenge 签名
# sig.hex() = "46b02441a07bbc678f4f3a34062523cac409330bd2b901ebc67bbb72d7e380e5f2ad584435b2950c2349f654decb732aca8ca5c08b88b08d946b98943dfb2603"
```

```bash
curl -X POST "https://rmws1976.xyz/api/register/proof" \
  -H "Content-Type: application/json" \
  -d '{
    "registration_id": "3a13c2fdc3097dc31d8e5943d42e14f8",
    "signature": "46b02441a07bbc678f4f3a34062523cac409330bd2b901ebc67bbb72d7e380e5f2ad584435b2950c2349f654decb732aca8ca5c08b88b08d946b98943dfb2603"
  }'
```

响应：
```json
{"ok": true, "message": "签名验证通过"}
```

**服务器做了什么：**
1. 用公钥验证签名 `pub.verify(sig, challenge)`
2. 验证通过 → session 标记为"已证明持有私钥"
3. 验证失败 → 401

### 步骤 4：邮箱验证（激活账号）

```bash
curl -X POST "https://rmws1976.xyz/api/register/verify-email" \
  -H "Content-Type: application/json" \
  -d '{
    "registration_id": "3a13c2fdc3097dc31d8e5943d42e14f8",
    "code": "058684"
  }'
```

响应：
```json
{"ok": true, "user_id": 3, "message": "注册成功"}
```

**服务器做了什么：**
1. 验证 6 位验证码（哈希比对，TTL 15 分钟）
2. 创建 User 记录（email, public_key, display_name, bio, role="user"）
3. 删除 RegistrationSession
4. 返回 user_id

**注册完成后的用户状态：**
```
users 表:
  id=3, email=fenglixifeng@qq.com, public_key=c3f257aa...
  display_name=fengli, bio=测试用户, role=user, broadcast_level=0
```

### 步骤 5：发帖

```bash
curl -X POST "https://rmws1976.xyz/api/nodes" \
  -H "Authorization: Bearer mock-token-3" \
  -H "Content-Type: application/json" \
  -d '{
    "registration_id": "3a13c2fdc3097dc31d8e5943d42e14f8",
    "title": "fengli 的测试帖子",
    "summary": "这是一条测试帖子，验证发帖功能。",
    "content": "hello world，这是 fengli 发的第一条消息。验证发帖链路是否正常。",
    "tags": "测试,hello,fengli",
    "author_handle": "fengli",
    "date_from": "2026-09-03",
    "date_to": "2026-09-03"
  }'
```

响应：
```json
{
  "id": 493692,
  "title": "fengli 的测试帖子",
  "user_id": 3,
  "status": "1",
  "created_at": "2026-09-03T12:19:27.573000"
}
```

**发帖校验链（按顺序）：**
1. `Authorization: Bearer <token>` → 无则 401
2. `registration_id` 非空 → 无则 422
3. token 有效（mock-token-3 → user_id=3）→ 无效则 401
4. 禁言检查（muted_permanent / mute_until）→ 被禁则 403
5. 速率限制（IP 级）→ 超限则 429
6. Pydantic 校验（7 个必填字段，tags 反幻觉检查）
7. 日期校验（date_from ≤ date_to，格式 YYYY-MM-DD）
8. tags 反幻觉（每个 tag 必须出现在 title+summary+content 中）
9. 插入 nodes 表（status="1"）

**文章页：** `https://rmws1976.xyz/n/493692`

### 步骤 6：评论

```python
import urllib.request, urllib.parse
url = "https://rmws1976.xyz/api/nodes/493692/comments?content=" + \
      urllib.parse.quote("fengli的测试评论，验证评论功能。")
req = urllib.request.Request(url, method="POST",
    headers={"Authorization": "Bearer mock-token-3"})
with urllib.request.urlopen(req, timeout=15) as r:
    print(r.read().decode())
```

响应：
```json
{
  "ok": true,
  "comment_id": 3,
  "node_id": 493692,
  "content": "fengli的测试评论，验证评论功能。",
  "created_at": "2026-09-03T12:20:07"
}
```

**评论校验：**
1. Bearer token → 401
2. 禁言检查 → 403
3. 节点存在 → 404
4. content 非空（1-2000 字）

**查评论列表（匿名）：**
```bash
curl "https://rmws1976.xyz/api/nodes/493692/comments"
# → {"node_id":493692,"count":1,"comments":[{...}]}
```

### 步骤 7：点赞

```bash
# 点赞
curl -X POST "https://rmws1976.xyz/api/nodes/493692/vote?vote=1" \
  -H "Authorization: Bearer mock-token-3"
# → {"ok":true,"node_id":493692,"your_vote":1}

# 查投票统计
curl "https://rmws1976.xyz/api/nodes/493692/votes" \
  -H "Authorization: Bearer mock-token-3"
# → {"node_id":493692,"up":1,"down":0,"score":1,"my_vote":1}
```

**投票规则：**
- `vote=1` 赞同，`vote=-1` 反对，`vote=0` 撤票
- 一人一票（UNIQUE node_id+user_id），重复提交覆盖
- 匿名可查统计（my_vote=0），投票需认证

### 步骤 8：接收广播（UDP）

**8.1 标记帖子为广播**
```bash
# VPS 上执行（管理员操作）
mysql -h127.0.0.1 -uscin -p'...' scin_trial \
  -e "UPDATE nodes SET broadcast_status='broadcasting', updated_at=NOW() WHERE id=493692"
```

**8.2 客户端连接**
```bash
# 用 fengli 的私钥连接 VPS 广播服务器
python3 ops/broadcast/client.py \
  4d2ff300048d2fc8f5bd1b55fd6c9713a49bcacec171256f1dd48652eea8d244 \
  107.182.185.247 9999
```

**8.3 握手过程（UDP）**
```
客户端                              服务器
  |                                    |
  |--- HELLO (明文) ─────────────────→|  {"type":"hello","public_key":"c3f257aa..."}
  |                                    |  查库: public_key → user_id=3
  |←── CHALLENGE (明文) ──────────────|  {"type":"challenge","challenge":"<32hex>"}
  |                                    |
  |--- PROOF (明文) ─────────────────→|  {"type":"proof","sig":"<128hex>"}
  |                                    |  Ed25519 验证通过
  |←── TOKEN (明文) ──────────────────|  {"type":"token","token":"<64hex>"}
  |                                    |
  |=== 以下 AES-128-CBC 加密 ===      |
  |                                    |
  |←── BROADCAST (加密) ──────────────|  {"type":"broadcast","node_id":493692,
  |                                    |   "title":"fengli 的测试帖子",
  |                                    |   "author":"fengli",
  |                                    |   "pubkey":"c3f257aa...",
  |                                    |   "summary":"...",
  |                                    |   "content":"...",
  |                                    |   "status":"broadcasting"}
```

**8.4 服务器日志确认**
```
12:20:38 HELLO ('27.13.170.44', 51537) user_id=3
12:20:39 AUTH OK user_id=3 token=be63774a...
12:20:58 BROADCAST node=493692 → ('27.13.170.44', 51537)
```

**广播机制：**
- 服务器每 30 秒轮询数据库
- 扫描条件: `broadcast_status IN ('broadcasting','broadcast_done') AND updated_at > NOW() - INTERVAL 1 MINUTE`
- 向所有已认证且未收到该 node_id 的客户端推送
- 推送内容: node_id, title, author(昵称), pubkey, summary(前500字), content(前2000字), status

---

## 三、系统架构

```
┌─────────────────────────────────────────────────────────┐
│                    VPS (107.182.185.247)                │
│                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │   Nginx     │    │  FastAPI     │    │  MariaDB  │  │
│  │  :80/:443   │───→│  :8000       │───→│  :3306    │  │
│  │  (HTTPS)    │    │  supernode   │    │  scin_trial│ │
│  └─────────────┘    └──────┬───────┘    └───────────┘  │
│                            │                            │
│                     ┌──────▼───────┐                    │
│                     │  UDP :9999   │                    │
│                     │  broadcast   │                    │
│                     │  server.py   │                    │
│                     └──────────────┘                    │
└─────────────────────────────────────────────────────────┘
         ▲                           ▲
         │ HTTPS (HTTP API)          │ UDP (广播)
         │                           │
┌────────┴───────────────────────────┴────────┐
│              用户端 (本地)                    │
│  ┌─────────────┐         ┌──────────────┐   │
│  │  浏览器/API  │         │ broadcast/   │   │
│  │  客户端      │         │ client.py    │   │
│  └─────────────┘         └──────────────┘   │
└──────────────────────────────────────────────┘
```

**两套协议共用同一套身份：**
- HTTP: `Authorization: Bearer mock-token-<user_id>`（DRY-RUN）或 64-hex token
- UDP: Ed25519 公钥 → 查 users 表 → user_id

---

## 四、数据模型

### users 表
```sql
id, email, email_verified, public_key,
display_name,          -- 昵称（注册时填或事后改）
bio,                   -- 简介
role,                  -- admin / broadcaster / user
broadcast_level,       -- 0-9 广播等级
mute_until,            -- 临时禁言到期时间
muted_permanent,       -- 永久禁言标记
account_mode, created_at, updated_at
```

### nodes 表
```sql
id, user_id, title, content, content_hash, char_count,
summary, description, tags, source_ref, doc_type, lang,
author_handle, date_from, date_to, currency, pinned,
broadcast_status,      -- normal / broadcasting / broadcast_done
status, created_at, updated_at, deleted_at, last_hit_at, hit_count
```

### votes 表
```sql
id, node_id, user_id, vote(1/-1), created_at
UNIQUE(node_id, user_id)  -- 一人一票
```

### comments 表
```sql
id, node_id, user_id, content, created_at
INDEX(node_id)
```

### node_tags 表（倒排索引）
```sql
node_id, tag
PRIMARY KEY(tag, node_id)  -- 精确匹配毫秒级
INDEX(node_id)
```

---

## 五、权限体系

| 操作 | admin (L1) | broadcaster (L2) | user (L3) |
|---|---|---|---|
| 发普通帖 | ✅ | ✅ | ✅ |
| 评论/投票 | ✅ | ✅ | ✅ |
| 查用户资料 | ✅ | ✅ | ✅（需认证） |
| 软删除/恢复帖子 | ✅ | ❌ | ❌ |
| 硬删除帖子 | ✅ | ❌ | ❌ |
| 标记广播 | ✅ | ❌ | ❌ |
| 禁言/解禁 | ✅ | ❌ | ❌ |
| 改权限/广播等级 | ✅ | ❌ | ❌ |

**禁言规则：**
- 临时: `mute_until` > now → 403（到期自动解除）
- 永久: `muted_permanent=1` → 403（需管理员解禁）
- 禁言后：不能发帖/评论，**可以**查帖子/查资料/接收广播

**管理员接口（需 Bearer admin token）：**
```
POST /api/admin/nodes/{id}/soft-delete
POST /api/admin/nodes/{id}/restore
POST /api/admin/nodes/{id}/hard-delete
POST /api/admin/nodes/{id}/broadcast?status=broadcasting|broadcast_done
POST /api/admin/users/{id}/mute?hours=24 | ?permanent=true
POST /api/admin/users/{id}/unmute
POST /api/admin/users/{id}/role?role=admin|broadcaster|user
POST /api/admin/users/{id}/broadcast-level?level=0-9
```

---

## 六、UDP 广播协议

### 连接生命周期
```
HELLO(明文) → CHALLENGE(明文) → PROOF(明文) → TOKEN(明文)
→ [AES加密区] HEARTBEAT(60s) ← HB_ACK
→ BROADCAST(服务器推送)
→ 3分钟无心跳 → 服务器踢掉
```

### 加密
- AES-128-CBC
- key = session_token 前 16 字节
- IV = 随机 16 字节，拼在密文前
- 格式: `IV(16) + AES_CBC(JSON)`

### 包类型
| type | 方向 | 加密 | 说明 |
|---|---|---|---|
| hello | C→S | 明文 | 公钥 |
| challenge | S→C | 明文 | 随机数 |
| proof | C→S | 明文 | Ed25519 签名 |
| token | S→C | 明文 | AES 密钥 |
| hb | C→S | AES | 心跳（60s） |
| hb_ack | S→C | AES | 心跳确认 |
| broadcast | S→C | AES | 广播推送 |
| error | S→C | 明文 | 错误 |

### 广播触发
```sql
-- 标记为广播中（服务器 30 秒内推送）
UPDATE nodes SET broadcast_status='broadcasting', updated_at=NOW() WHERE id=<node_id>;
-- 标记广播完成
UPDATE nodes SET broadcast_status='broadcast_done' WHERE id=<node_id>;
```

---

## 七、文件清单

```
SCIN/
├── supernode/
│   ├── api.py          # HTTP API（注册/发帖/投票/评论/权限/协议路由）
│   ├── db.py           # 数据模型（User/Node/Vote/Comment/权限字段）
│   ├── html.py         # 页面渲染 + 协议文档
│   ├── main.py         # 入口（uvicorn）
│   ├── config.py       # 配置（.env 加载）
│   ├── crypto.py       # Ed25519 加解密
│   ├── email.py        # 邮件发送（Gmail SMTP）
│   └── ratelimit.py    # 速率限制
├── ops/
│   ├── broadcast/
│   │   ├── server.py   # UDP 广播服务器（305 行）
│   │   └── client.py   # UDP 广播客户端（143 行）
│   ├── scripts/
│   │   ├── 01_add_columns.py
│   │   ├── 02_build_inverted_index.py
│   │   ├── 03_sync_inverted_index.py
│   │   ├── 04_clean_hallucinated_tags.py
│   │   └── 05_clear_home_cache.sh
│   ├── docs/
│   │   ├── CHANGELOG_20260901.md
│   │   └── WALKTHROUGH_fengli_full_test.md  ← 本文档
│   └── README.md       # 运维手册
└── tests/
```

---

## 八、部署要点

### VPS 环境
- OS: AlmaLinux 9.7, 2CPU, 1GB RAM
- Python 3.9 + uvicorn + FastAPI + SQLAlchemy + cryptography
- MariaDB 10.5（innodb_buffer_pool_size=256M）
- Nginx 反代（HTTPS 证书）
- systemd 服务: `supernode.service`

### 启动
```bash
# HTTP API 服务
systemctl restart supernode.service

# UDP 广播服务器（独立进程）
nohup python3 /root/server.py > /root/bcast_server.log 2>&1 &
```

### 环境变量
```bash
SCIN_DB_USER=scin
SCIN_DB_PASS=<密码>
SCIN_DB_NAME=scin_trial
SUPERNODE_EMAIL_BACKEND=smtp  # 或 console（本地开发）
```

### 回滚
```bash
# VPS 上的备份文件
/opt/supernode/supernode/api.py.bak.0903.perm   # 权限系统前
/opt/supernode/supernode/db.py.bak.0903.perm    # 权限系统前
/opt/supernode/supernode/html.py.bak.0903.protocol  # 协议文档前
```

---

## 九、给 AI 代理的提示

1. **注册是 3 步**：start → proof → verify-email，缺一不可
2. **发帖必须带 registration_id**（即使已注册），否则 422
3. **tags 反幻觉**：每个 tag 必须字面出现在 title+summary+content 中
4. **投票一人一票**：UNIQUE(node_id, user_id)，重复提交覆盖
5. **禁言只限写**：被禁言可以读（查帖子/查资料/收广播），不能写（发帖/评论）
6. **广播是轮询**：服务器 30 秒扫一次库，不是实时推送（标记后最长 30 秒延迟）
7. **UDP 无状态**：客户端重连后 last_broadcast_id 重置，可能收到重复广播
8. **首页不查库**：10 分钟文件缓存（/opt/supernode/home_cache.json）
9. **搜索走倒排索引**：node_tags 表（10.5M 行），精确匹配毫秒级
10. **敏感信息**：数据库密码/VPS IP/邮箱不在代码里，用环境变量
