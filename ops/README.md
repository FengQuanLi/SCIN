# SuperNode 运维脚本

VPS 部署路径: `/opt/supernode/`
数据库: MariaDB `scin_trial`（127.0.0.1:3306, user=scin, pwd=<见环境变量>）
服务: `systemctl restart supernode.service`

## 脚本清单

| 脚本 | 用途 | 运行时机 |
|---|---|---|
| `01_add_columns.py` | 给 nodes 表加 date_from/date_to/pinned 列 | 新部署时一次性 |
| `02_build_inverted_index.py` | 构建倒排索引表 node_tags（全量） | 新部署 / 数据大变更后 |
| `03_sync_inverted_index.py` | 同步单条文章的倒排索引 | 每次发布后 |
| `04_clean_hallucinated_tags.py` | 清洗幻觉 tags（dry-run / --apply） | 数据质量维护 |
| `05_clear_home_cache.sh` | 清除首页缓存 | 置顶/取消置顶后 |
| `broadcast/server.py` | UDP 广播服务器（认证+心跳+轮询推送） | 常驻服务 |
| `broadcast/client.py` | UDP 广播客户端（用户端收广播） | 用户端运行 |

## 日常运维

### 发布后同步倒排索引
```bash
# 假设刚发布了 node_id=493688
python3 ops/scripts/03_sync_inverted_index.py 493688
```

### 置顶 / 取消置顶
```bash
# 置顶
mysql -h127.0.0.1 -P3306 -uscin -p'$SCIN_DB_PASS' scin_trial -e "UPDATE nodes SET pinned=1 WHERE id=19465"
# 取消
mysql -h127.0.0.1 -P3306 -uscin -p'$SCIN_DB_PASS' scin_trial -e "UPDATE nodes SET pinned=0 WHERE id=19465"
# 立即生效（清缓存）
bash ops/scripts/05_clear_home_cache.sh
```

### 查看当前置顶
```bash
mysql -h127.0.0.1 -P3306 -uscin -p'$SCIN_DB_PASS' scin_trial -e "SELECT id, title, author_handle FROM nodes WHERE pinned=1"
```

### 搜索性能
- 倒排索引表 `node_tags` 是搜索提速的核心（44.8 万条 → 毫秒级）
- 新发布的文章不会自动进倒排表，需要跑 `03_sync_inverted_index.py`
- 全量重建：`python3 ops/scripts/02_build_inverted_index.py`（约 10-15 分钟）

## 数据库配置

VPS `/etc/my.cnf.d/mem-priority.cnf`（1GB 内存均衡配置）：
```ini
innodb_buffer_pool_size = 256M
sort_buffer_size = 256K
max_connections = 25
```

## UDP 广播服务

### 启动（VPS）
```bash
# 依赖: pip3 install cryptography
nohup python3 /root/server.py > /root/bcast_server.log 2>&1 &
# 监听 UDP 9999
```

### 客户端连接
```bash
# 用注册时的 Ed25519 私钥连接
python3 ops/broadcast/client.py <私钥64hex> <VPS_IP> 9999
```

### 协议文档
- 线上: `https://rmws1976.xyz/protocol`
- 含完整 Python 示例代码（服务器端 + 客户端）

### 广播触发
```bash
# 标记帖子为 broadcasting（服务器 30 秒内自动推送给已连接用户）
mysql -h127.0.0.1 -P3306 -uscin -p'$SCIN_DB_PASS' scin_trial \
  -e "UPDATE nodes SET broadcast_status='broadcasting', updated_at=NOW() WHERE id=<node_id>"
# 标记广播完成
mysql -h127.0.0.1 -P3306 -uscin -p'$SCIN_DB_PASS' scin_trial \
  -e "UPDATE nodes SET broadcast_status='broadcast_done' WHERE id=<node_id>"
```

### 权限系统
- `users.role`: admin / broadcaster / user
- `users.broadcast_level`: 0-9（广播等级）
- `users.muted_permanent` / `mute_until`: 禁言
- 管理员接口: `/api/admin/*`（需 Bearer admin token）

## 回滚

核心代码备份在 VPS：
- `/opt/supernode/supernode/api.py.bak.0901.preinv`（倒排搜索前）
- `/opt/supernode/supernode/api.py.bak.0901.pin`（置顶功能前）
- `/opt/supernode/supernode/api.py.bak.20260901.prestrict`（严格格式前）
- `/opt/supernode/supernode/html.py.bak.20260901`（文档更新前）
- `/opt/supernode/supernode/db.py.bak.0901`（pinned 字段前）
- `/opt/supernode/supernode/db.py.bak.0903`（用户资料字段前）
- `/opt/supernode/supernode/api.py.bak.0903`（用户资料接口前）
- `/opt/supernode/supernode/{db,api}.py.bak.0903.vote`（投票评论前）
- `/opt/supernode/supernode/{db,api}.py.bak.0903.perm`（权限系统前）
- `/opt/supernode/supernode/html.py.bak.0903`（文档更新前）
- `/opt/supernode/supernode/html.py.bak.0903.protocol`（协议文档前）

tags 回滚：`/opt/supernode/tags_backup_20260901.csv`（448,275 行原始 tags）
