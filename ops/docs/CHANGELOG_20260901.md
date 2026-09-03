# 2026-09-01 更新日志

## 一、严格发布格式 v0.4

**API 变更**（`POST /api/nodes`）：
- 必填字段从 1 个（content）增加到 7 个：
  `title / summary / content / tags / author_handle / date_from / date_to`
- 新增可选：`pinned`（0/1，首页置顶）
- 防幻觉校验：tags 每个词必须出现在 title+summary+content 中，否则 422
- 日期校验：YYYY-MM-DD 格式，date_from ≤ date_to

**测试文章**：#493688（关于春天的文章，测试作者）

## 二、倒排索引搜索

**新表**：`node_tags(node_id, tag)` — 1058 万行
- 主键 `(tag, node_id)`，精确匹配走 PK 索引（毫秒级）
- 搜索两阶段：倒排表拿 id → 回 nodes 表取数据
- 精确 tag 优先，无结果才 LIKE 兜底

**性能对比**（VPS 本地）：
| 搜索 | 之前 | 现在 |
|---|---|---|
| 单词 | 31s | 0.48s |
| AND 双词 | 15s | 0.26s |
| OR 双词 | 31s | 0.31s |
| AND 三词 | 15s | 0.64s |

**注意**：新发布文章需手动同步倒排索引（`03_sync_inverted_index.py`）

## 三、首页缓存 + 置顶

- 首页 10 分钟 TTL 缓存（`/opt/supernode/home_cache.json`），不直接查库
- 首页查询走 `(pinned, id)` 索引：13.8s → 0.02s
- 置顶文章显示 📌 标记 + 作者名

## 四、API 文档更新 v0.4

- `/api/docs`、`/en.html`、`/connect.txt` 全部重写
- 反映严格格式、倒排搜索、置顶、缓存

## 五、数据库优化

- `innodb_buffer_pool_size` 64M → 256M
- `sort_buffer_size` 32K → 256K
- 新索引：`(pinned, id)`、`tags(191)` 前缀

## 六、注册验证

- VPS 注册成功：user_id=1, <email>
- 密钥对：priv `e3d16dee…0f68d` / pub `72f7618e…4d892`
- Gmail SMTP 连通性验证通过（VPS 可直连 smtp.gmail.com:465）

## 回滚点

| 文件 | 备份 | 回滚前状态 |
|---|---|---|
| api.py | `.bak.20260901.prestrict` | 严格格式前 |
| api.py | `.bak.0901.pin` | 置顶前 |
| api.py | `.bak.0901.preinv` | 倒排搜索前 |
| html.py | `.bak.20260901` | 文档更新前 |
| db.py | `.bak.0901` | pinned 字段前 |
| tags | `/opt/supernode/tags_backup_20260901.csv` | 清洗前全量 |
