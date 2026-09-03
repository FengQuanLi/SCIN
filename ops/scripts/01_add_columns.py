#!/usr/bin/env python3
"""一次性 DDL：为 nodes 表加 date_from / date_to / pinned 列。
用法: python3 ops/scripts/01_add_columns.py [host] [port] [user] [password] [db]
默认: 127.0.0.1 3306 scin <SCIN_DB_PASS> scin_trial
"""
import sys, pymysql

args = sys.argv[1:]
host = args[0] if len(args) > 0 else "127.0.0.1"
port = int(args[1]) if len(args) > 1 else 3306
user = args[2] if len(args) > 2 else "scin"
pwd  = args[3] if len(args) > 3 else os.environ.get("SCIN_DB_PASS", "change_me")
db   = args[4] if len(args) > 4 else "scin_trial"

conn = pymysql.connect(host=host, port=port, user=user, password=pwd, db=db)
cur = conn.cursor()
cur.execute("SHOW COLUMNS FROM nodes")
cols = {r[0] for r in cur.fetchall()}

additions = [
    ("date_from", "ALTER TABLE nodes ADD COLUMN date_from VARCHAR(11) NOT NULL DEFAULT '' AFTER author_handle"),
    ("date_to",   "ALTER TABLE nodes ADD COLUMN date_to   VARCHAR(11) NOT NULL DEFAULT '' AFTER date_from"),
    ("pinned",    "ALTER TABLE nodes ADD COLUMN pinned    TINYINT(1)  NOT NULL DEFAULT 0 AFTER currency"),
]
for name, sql in additions:
    if name in cols:
        print(f"  {name}: 已存在，跳过")
    else:
        print(f"  {name}: 执行中...")
        cur.execute(sql)
        conn.commit()
        print(f"  {name}: 完成")

conn.close()
print("DDL 完成")
