#!/usr/bin/env python3
"""增量同步倒排索引：只处理指定 id 范围（发布后调用）。
用法: python3 ops/scripts/03_sync_inverted_index.py <node_id> [host] [port] [user] [password] [db]
示例: python3 ops/scripts/03_sync_inverted_index.py 493688
"""
import sys, pymysql

if len(sys.argv) < 2:
    print("用法: python3 03_sync_inverted_index.py <node_id> [host] [port] [user] [password] [db]")
    sys.exit(1)

node_id = int(sys.argv[1])
args = sys.argv[2:]
host = args[0] if len(args) > 0 else "127.0.0.1"
port = int(args[1]) if len(args) > 1 else 3306
user = args[2] if len(args) > 2 else "scin"
pwd  = args[3] if len(args) > 3 else os.environ.get("SCIN_DB_PASS", "change_me")
db   = args[4] if len(args) > 4 else "scin_trial"

conn = pymysql.connect(host=host, port=port, user=user, password=pwd, db=db, charset="utf8mb4")
cur = conn.cursor()
cur.execute("SELECT tags FROM nodes WHERE id = %s", (node_id,))
row = cur.fetchone()
if not row:
    print(f"node {node_id} 不存在")
    sys.exit(1)
# 先删旧的
cur.execute("DELETE FROM node_tags WHERE node_id = %s", (node_id,))
# 再插新的
for t in (row[0] or "").split(","):
    t = t.strip()
    if t:
        cur.execute("INSERT IGNORE INTO node_tags (node_id, tag) VALUES (%s, %s)", (node_id, t))
conn.commit()
print(f"node {node_id} 倒排索引已同步: {row[0]}")
conn.close()
