#!/usr/bin/env python3
"""发布 100 篇中文翻译到 SuperNode(白名单 user_id=1, 限流 1000/小时)。
内容: 中文标题 + 中文摘要 + 作者/分类/日期 + 原文 arXiv 链接 + 英文原标题。
用法: python3 batch_publish_cn.py
"""
import json, sys, time
import urllib.request, urllib.error
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = "https://__(removed)__"
IDENT = "local_identity.json"
UPJ = "upload.json"
TRJ = "translations.json"
NL = chr(10)

def build_content_cn(n, p, t):
    """组装中文版发布内容。p=原文(英文元数据), t=翻译(title_cn/abstract_cn)。"""
    title_cn = (t.get("title_cn") or "").strip()
    abstract_cn = (t.get("abstract_cn") or "").strip()
    title_en = (p.get("title") or "").strip()
    authors = ", ".join(p.get("authors", [])[:5])
    cats = ", ".join("#" + c for c in p.get("categories", []))
    url = p.get("url") or ("https://arxiv.org/abs/" + p["arxiv_id"])
    date = (p.get("published") or "")[:10]
    parts = [
        "标题: " + title_cn,
        "",
        abstract_cn,
        "",
        "英文原标题: " + title_en,
        "作者: " + (authors or "未知"),
        "分类: " + (cats or "arxiv"),
        "日期: " + (date or "未知"),
        "原文: " + url,
    ]
    return NL.join(parts)

def post(path, body, token=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")

def main():
    ident = json.load(open(IDENT))
    rows = json.load(open(UPJ))
    trans = {t["n"]: t for t in json.load(open(TRJ))}
    uid, reg_id = ident["user_id"], ident["registration_id"]
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ident["private_key"]))
    token = "mock-token-" + str(uid)

    c, r = post("/api/auth/challenge", {"user_id": uid})
    if c != 200:
        print("auth/challenge 失败:", c, r); sys.exit(1)
    sig = sk.sign(r["challenge"].encode()).hex()
    c, r = post("/api/auth/verify", {"challenge_id": r["challenge_id"], "signature": sig})
    print(f"认证: {c} user_id={r.get('user_id')}")

    ok, fail = 0, 0
    for n, p in rows:
        t = trans.get(n)
        if not t:
            print(f"  [!] 第 {n} 篇缺翻译, 跳过"); fail += 1; continue
        content = build_content_cn(n, p, t)
        c, r = post("/api/nodes", {"content": content, "registration_id": reg_id}, token=token)
        if c == 201:
            ok += 1
            if ok % 10 == 0:
                print(f"  进度 {ok}/100  (node id={r.get('id')})")
        else:
            fail += 1
            print(f"  [!] 第 {n} 篇失败 {c}: {str(r)[:100]}")
            if fail > 5:
                print("连续失败过多, 停止"); break
        time.sleep(0.1)
    print(f"\n完成: 成功 {ok} 条, 失败 {fail} 条")

if __name__ == "__main__":
    main()
