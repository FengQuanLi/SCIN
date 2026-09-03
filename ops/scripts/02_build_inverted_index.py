#!/usr/bin/env python3
"""构建倒排索引表 node_tags（tag, node_id）。
44.8 万条 tags 约需 10-15 分钟（1GB 内存 VPS）。
用法: python3 ops/scripts/02_build_inverted_index.py [host] [port] [user] [password] [db]
"""
import sys, time, pymysql

args = sys.argv[1:]
host = args[0] if len(args) > 0 else "127.0.0.1"
port = int(args[1]) if len(args) > 1 else 3306
user = args[2] if len(args) > 2 else "scin"
pwd  = args[3] if len(args) > 3 else os.environ.get("SCIN_DB_PASS", "change_me")
db   = args[4] if len(args) > 4 else "scin_trial"

conn = pymysql.connect(host=host, port=port, user=user, password=pwd, db=db,
                       charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor)
cur = conn.cursor()

t0 = time.time()
cur.execute("DROP TABLE IF EXISTS node_tags")
cur.execute("""CREATE TABLE node_tags (
    node_id BIGINT UNSIGNED NOT NULL,
    tag VARCHAR(200) NOT NULL,
    PRIMARY KEY (tag, node_id),
    KEY idx_node (node_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
conn.commit()
print(f"表已创建: {time.time()-t0:.1f}s", flush=True)

t0 = time.time()
BATCH = 3000
last_id = 0
total = 0
while True:
    cur.execute("""SELECT id, tags FROM nodes
                   WHERE id > %s AND status IN ('1','approved') AND deleted_at IS NULL
                   ORDER BY id LIMIT %s""", (last_id, BATCH))
    rows = cur.fetchall()
    if not rows:
        break
    last_id = rows[-1]["id"]
    inserts = []
    for r in rows:
        for t in (r["tags"] or "").split(","):
            t = t.strip()
            if t:
                inserts.append((r["id"], t))
    if inserts:
        cur.executemany("INSERT IGNORE INTO node_tags (node_id, tag) VALUES (%s, %s)", inserts)
        conn.commit()
        total += len(inserts)
    if (last_id // BATCH) % 30 == 0:
        print(f"... id={last_id} rows={total} {time.time()-t0:.0f}s", flush=True)

print(f"完成: {total} tag 行, {time.time()-t0:.0f}s", flush=True)
conn.close()
