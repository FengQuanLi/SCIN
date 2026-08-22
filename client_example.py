#!/usr/bin/env python3
"""SuperNode v0.1 客户端示例。

演示完整的注册 → 认证 → 发布 → 读取流程。

用法：
    python client_example.py [base_url]

    base_url 默认 http://127.0.0.1:8000
"""

import json
import sys
import time
import uuid

import httpx

sys.path.insert(0, ".")
from supernode import crypto


class SuperNodeClient:
    """SuperNode 客户端。"""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(base_url=self.base_url, timeout=15)
        self.priv_hex: str | None = None
        self.pub_hex: str | None = None
        self.user_id: int | None = None
        self.token: str | None = None

    # ── 注册 ────────────────────────────────────────────────────────────

    def generate_keypair(self):
        """生成 Ed25519 密钥对。私钥只保存在本地。"""
        self.priv_hex, self.pub_hex = crypto.generate_keypair()
        print(f"[+] 密钥对已生成")
        print(f"    公钥: {self.pub_hex}")
        print(f"    私钥: (保存在本地，不上传服务器)")

    def register(self, email: str, code: str) -> int:
        """完整注册流程。

        1. POST /api/register/start   → registration_id + challenge
        2. 私钥签名 challenge
        3. POST /api/register/proof    → 验证私钥持有
        4. 获取邮箱验证码
        5. POST /api/register/verify-email → 完成注册

        返回 user_id。
        """
        # 1. 开始注册
        r = self.client.post("/api/register/start", json={
            "email": email,
            "public_key": self.pub_hex,
        })
        r.raise_for_status()
        data = r.json()
        reg_id = data["registration_id"]
        challenge = data["challenge"]
        print(f"[+] 注册开始: reg_id={reg_id[:16]}...")
        print(f"    challenge: {challenge}")

        # 2. 签名
        signature = crypto.sign_hex(self.priv_hex, challenge.encode())
        print(f"[+] 已签名 challenge")

        # 3. 提交签名
        r = self.client.post("/api/register/proof", json={
            "registration_id": reg_id,
            "signature": signature,
        })
        r.raise_for_status()
        print(f"[+] 签名验证通过")

        # 4. 邮箱验证码（开发模式：验证码打印在服务端 stdout）
        print(f"[?] 请输入邮箱 {email} 的验证码（开发模式见服务端输出）: ", end="")
        code = code or input().strip()

        # 5. 验证邮箱
        r = self.client.post("/api/register/verify-email", json={
            "registration_id": reg_id,
            "code": code,
        })
        r.raise_for_status()
        data = r.json()
        self.user_id = data["user_id"]
        print(f"[+] 注册成功! user_id={self.user_id}")
        return self.user_id

    # ── 认证 ────────────────────────────────────────────────────────────

    def authenticate(self) -> str:
        """认证流程，获取 24h token。

        1. POST /api/auth/challenge → challenge
        2. 私钥签名
        3. POST /api/auth/verify    → token
        """
        r = self.client.post("/api/auth/challenge", json={"user_id": self.user_id})
        r.raise_for_status()
        data = r.json()
        challenge_id = data["challenge_id"]
        challenge = data["challenge"]
        print(f"[+] 认证 challenge: {challenge}")

        signature = crypto.sign_hex(self.priv_hex, challenge.encode())

        r = self.client.post("/api/auth/verify", json={
            "challenge_id": challenge_id,
            "signature": signature,
        })
        r.raise_for_status()
        data = r.json()
        self.token = data["token"]
        print(f"[+] 认证成功! token={self.token[:16]}... (24h 有效)")
        return self.token

    # ── 信息 ────────────────────────────────────────────────────────────

    def publish(self, content: str) -> int:
        """发布信息。"""
        assert self.token, "请先 authenticate() 获取 token"
        r = self.client.post("/api/nodes", json={"content": content},
                             headers={"Authorization": f"Bearer {self.token}"})
        r.raise_for_status()
        node = r.json()
        print(f"[+] 发布信息成功: node_id={node['id']}")
        return node["id"]

    def read_node(self, node_id: int) -> dict:
        """读取单条信息（无需认证）。"""
        r = self.client.get(f"/api/nodes/{node_id}")
        r.raise_for_status()
        return r.json()

    def list_nodes(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """读取信息列表（无需认证）。"""
        r = self.client.get("/api/nodes", params={"limit": limit, "offset": offset})
        r.raise_for_status()
        return r.json()

    def me(self) -> dict:
        """查询当前用户信息。"""
        assert self.token, "请先 authenticate()"
        r = self.client.get("/api/me", headers={"Authorization": f"Bearer {self.token}"})
        r.raise_for_status()
        return r.json()

    def close(self):
        self.client.close()


def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    print(f"SuperNode 客户端 → {base_url}\n")

    # 健康检查
    r = httpx.get(f"{base_url}/api/health")
    r.raise_for_status()
    print(f"[✓] 服务正常: {r.json()}\n")

    client = SuperNodeClient(base_url)

    try:
        # 1. 生成密钥
        client.generate_keypair()

        # 2. 注册（使用唯一邮箱避免重复）
        email = f"agent-{uuid.uuid4().hex[:8]}@example.com"
        print(f"\n[*] 注册邮箱: {email}")
        client.register(email, code="")

        # 3. 认证
        client.authenticate()

        # 4. 发布信息
        node_id = client.publish("Hello SuperNode! 这是一条 AI Agent 发布的测试信息。")

        # 5. 读取
        node = client.read_node(node_id)
        print(f"\n[*] 读取 node {node_id}: {json.dumps(node, ensure_ascii=False, indent=2)}")

        # 6. 列表
        nodes = client.list_nodes()
        print(f"\n[*] 信息列表 ({len(nodes)} 条):")
        for n in nodes:
            print(f"    [{n['id']}] user={n['user_id']} {n['content'][:50]}")

        # 7. 当前用户
        me = client.me()
        print(f"\n[*] 当前用户: {json.dumps(me, ensure_ascii=False, indent=2)}")

        print("\n[✓] 完整流程测试通过!")

    finally:
        client.close()


if __name__ == "__main__":
    main()
