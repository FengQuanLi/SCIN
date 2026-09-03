#!/usr/bin/env python3
"""全库清洗幻觉 tags：tag 必须是 title+summary+content 的子串才保留。
先 dry-run（默认），加 --apply 才真正执行。
用法: python3 ops/scripts/04_clean_hallucinated_tags.py [--apply] [host] [port] [user] [password] [db]
"""
import sys, time, pymysql

apply = "--apply" in sys.argv
sys.argv.remove("--apply") if apply else None
args = sys.argv[1:]
host = args[0] if len(args) > 0 else "127.0.0.1"
port = int(args[1]) if len(args) > 1 else 3306
user = args[2] if len(args) > 2 else "scin"
pwd  = args[3] if len(args) > 3 else os.environ.get("SCIN_DB_PASS", "change_me")
db   = args[4] if len(args) > 4 else "scin_trial"

conn = pymysql.connect(host=host, port=port, user=user, password=pwd, db=db, charset="utf8mb4",
                       cursorclass=pymysql.cursors.DictCursor)
cur = conn.cursor()

t0 = time.time()
last_id = 0
total_rows = 0
total_dropped = 0
emptied = []
BATCH = 5000

while True:
    cur.execute("""SELECT id, title, summary, content, tags FROM nodes
                   WHERE id > %s ORDER BY id LIMIT %s""", (last_id, BATCH))
    rows = cur.fetchall()
    if not rows:
        break
    last_id = rows[-1]["id"]
    for r in rows:
        total_rows += 1
        corpus = (r["title"] or "") + "\n" + (r["summary"] or "") + "\n" + (r["content"] or "")
        old_tags = [t.strip() for t in (r["tags"] or "").split(",") if t.strip()]
        kept = [t for t in old_tags if t in corpus]
        dropped = len(old_tags) - len(kept)
        if dropped > 0:
            total_dropped += dropped
            new_tags = ",".join(kept)
            if not new_tags:
                emptied.append(r["id"])
            if apply:
                cur.execute("UPDATE nodes SET tags = %s WHERE id = %s", (new_tags, r["id"]))
    if apply:
        conn.commit()
    if (last_id // BATCH) % 20 == 0:
        print(f"... id={last_id} rows={total_rows} dropped={total_dropped} {time.time()-t0:.0f}s", flush=True)

mode = "APPLIED" if apply else "DRY-RUN"
print(f"\n[{mode}] 完成: {total_rows} 行扫描, {total_dropped} 个幻觉 tag 被{'清除' if apply else '标记'}, "
      f"{len(emptied)} 行 tags 变空, {time.time()-t0:.0f}s")
if emptied:
    print(f"  tags 变空的 node id: {emptied[:20]}{'...' if len(emptied)>20 else ''}")
conn.close()
