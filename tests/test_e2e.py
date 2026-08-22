"""SuperNode v0.1 端到端测试。

覆盖完整流程：
    注册 (start → proof → verify-email)
    → 认证 (challenge → verify → token)
    → 发布信息 (POST /api/nodes)
    → 读取信息 (GET /api/nodes, GET /api/nodes/{id})
    → 账户查询 (GET /api/me)
"""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from supernode import crypto
from supernode.api import create_app
from supernode.config import Settings


@pytest.fixture()
def client():
    """每个测试用独立的临时数据库。"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        email_backend="console",
    )
    app = create_app(settings)
    with TestClient(app) as c:
        yield c, settings
    os.unlink(db_path)





@pytest.fixture()
def patched_client(monkeypatch):
    """可预测验证码的测试客户端。"""
    captured_codes = {}

    def fake_send(settings, to_email, code):
        captured_codes[to_email] = code
        from supernode.email import EmailResult
        return EmailResult(ok=True, code=code)

    monkeypatch.setattr("supernode.api.email_svc.send_verification_code", fake_send)

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        email_backend="console",
    )
    app = create_app(settings)
    with TestClient(app) as c:
        yield c, settings, captured_codes
    os.unlink(db_path)


def do_register(client_tuple, email="test@example.com"):
    """完整注册流程，返回 (user_id, priv_hex, pub_hex)。"""
    c, _, codes = client_tuple
    priv, pub = crypto.generate_keypair()

    # 1. 开始注册
    r = c.post("/api/register/start", json={"email": email, "public_key": pub})
    assert r.status_code == 200, f"register/start 失败: {r.text}"
    data = r.json()
    reg_id = data["registration_id"]
    challenge = data["challenge"]

    # 2. 签名验证
    sig = crypto.sign_hex(priv, challenge.encode())
    r = c.post("/api/register/proof", json={"registration_id": reg_id, "signature": sig})
    assert r.status_code == 200, f"register/proof 失败: {r.text}"

    # 3. 邮箱验证码
    code = codes[email]
    r = c.post("/api/register/verify-email", json={"registration_id": reg_id, "code": code})
    assert r.status_code == 200, f"register/verify-email 失败: {r.text}"
    user_id = r.json()["user_id"]

    return user_id, priv, pub


def do_auth(client_tuple, user_id, priv_hex):
    """认证流程，返回 token。"""
    c, _, _ = client_tuple
    r = c.post("/api/auth/challenge", json={"user_id": user_id})
    assert r.status_code == 200, f"auth/challenge 失败: {r.text}"
    data = r.json()
    challenge_id = data["challenge_id"]
    challenge = data["challenge"]

    sig = crypto.sign_hex(priv_hex, challenge.encode())
    r = c.post("/api/auth/verify", json={"challenge_id": challenge_id, "signature": sig})
    assert r.status_code == 200, f"auth/verify 失败: {r.text}"
    return r.json()["token"]


class TestRegister:
    def test_full_registration(self, patched_client):
        user_id, priv, pub = do_register(patched_client)
        assert user_id >= 1

    def test_invalid_email(self, patched_client):
        c, _, _ = patched_client
        r = c.post("/api/register/start", json={"email": "not-an-email", "public_key": "aa" * 32})
        assert r.status_code == 400

    def test_invalid_public_key(self, patched_client):
        c, _, _ = patched_client
        r = c.post("/api/register/start", json={"email": "ok@test.com", "public_key": "bad"})
        assert r.status_code == 400

    def test_duplicate_email(self, patched_client):
        do_register(patched_client, email="dup@test.com")
        c, _, _ = patched_client
        _, pub = crypto.generate_keypair()
        r = c.post("/api/register/start", json={"email": "dup@test.com", "public_key": pub})
        assert r.status_code == 409

    def test_bad_signature_proof(self, patched_client):
        c, _, _ = patched_client
        priv, pub = crypto.generate_keypair()
        r = c.post("/api/register/start", json={"email": "sig@test.com", "public_key": pub})
        reg_id = r.json()["registration_id"]
        challenge = r.json()["challenge"]
        # 用错误的私钥签名
        other_priv, _ = crypto.generate_keypair()
        sig = crypto.sign_hex(other_priv, challenge.encode())
        r = c.post("/api/register/proof", json={"registration_id": reg_id, "signature": sig})
        assert r.status_code == 401

    def test_challenge_reuse(self, patched_client):
        """Challenge 只能用一次。"""
        c, _, _ = patched_client
        priv, pub = crypto.generate_keypair()
        r = c.post("/api/register/start", json={"email": "reuse@test.com", "public_key": pub})
        data = r.json()
        reg_id = data["registration_id"]
        sig = crypto.sign_hex(priv, data["challenge"].encode())
        r1 = c.post("/api/register/proof", json={"registration_id": reg_id, "signature": sig})
        assert r1.status_code == 200
        # 第二次使用同一 challenge
        r2 = c.post("/api/register/proof", json={"registration_id": reg_id, "signature": sig})
        assert r2.status_code == 410

    def test_wrong_email_code(self, patched_client):
        c, _, codes = patched_client
        priv, pub = crypto.generate_keypair()
        r = c.post("/api/register/start", json={"email": "code@test.com", "public_key": pub})
        reg_id = r.json()["registration_id"]
        sig = crypto.sign_hex(priv, r.json()["challenge"].encode())
        c.post("/api/register/proof", json={"registration_id": reg_id, "signature": sig})
        # 错误验证码
        r = c.post("/api/register/verify-email", json={"registration_id": reg_id, "code": "000000"})
        assert r.status_code == 401

    def test_email_code_max_attempts(self, patched_client):
        c, _, codes = patched_client
        priv, pub = crypto.generate_keypair()
        r = c.post("/api/register/start", json={"email": "max@test.com", "public_key": pub})
        reg_id = r.json()["registration_id"]
        sig = crypto.sign_hex(priv, r.json()["challenge"].encode())
        c.post("/api/register/proof", json={"registration_id": reg_id, "signature": sig})
        # 超过最大尝试次数
        for _ in range(5):
            c.post("/api/register/verify-email", json={"registration_id": reg_id, "code": "000000"})
        r = c.post("/api/register/verify-email", json={"registration_id": reg_id, "code": "000000"})
        assert r.status_code == 429

    def test_verify_email_before_proof(self, patched_client):
        """先验证邮箱再提交签名 → 应被拒绝。"""
        c, _, codes = patched_client
        priv, pub = crypto.generate_keypair()
        r = c.post("/api/register/start", json={"email": "order@test.com", "public_key": pub})
        reg_id = r.json()["registration_id"]
        code = codes["order@test.com"]
        r = c.post("/api/register/verify-email", json={"registration_id": reg_id, "code": code})
        assert r.status_code == 412

    def test_nonexistent_registration(self, patched_client):
        c, _, _ = patched_client
        r = c.post("/api/register/proof", json={"registration_id": "nonexistent", "signature": "aa" * 64})
        assert r.status_code == 404


class TestAuth:
    def test_full_auth_flow(self, patched_client):
        user_id, priv, _ = do_register(patched_client, email="auth@test.com")
        token = do_auth(patched_client, user_id, priv)
        assert len(token) == 64  # 32 bytes hex

    def test_bad_signature_auth(self, patched_client):
        user_id, _, _ = do_register(patched_client, email="authbad@test.com")
        c, _, _ = patched_client
        r = c.post("/api/auth/challenge", json={"user_id": user_id})
        data = r.json()
        # 用错误私钥签名
        other_priv, _ = crypto.generate_keypair()
        sig = crypto.sign_hex(other_priv, data["challenge"].encode())
        r = c.post("/api/auth/verify", json={"challenge_id": data["challenge_id"], "signature": sig})
        assert r.status_code == 401

    def test_challenge_replay(self, patched_client):
        user_id, priv, _ = do_register(patched_client, email="replay@test.com")
        c, _, _ = patched_client
        r = c.post("/api/auth/challenge", json={"user_id": user_id})
        data = r.json()
        sig = crypto.sign_hex(priv, data["challenge"].encode())
        r1 = c.post("/api/auth/verify", json={"challenge_id": data["challenge_id"], "signature": sig})
        assert r1.status_code == 200
        # 重放
        r2 = c.post("/api/auth/verify", json={"challenge_id": data["challenge_id"], "signature": sig})
        assert r2.status_code == 410

    def test_nonexistent_user(self, patched_client):
        c, _, _ = patched_client
        r = c.post("/api/auth/challenge", json={"user_id": 99999})
        assert r.status_code == 404


class TestNodes:
    def test_publish_and_read(self, patched_client):
        user_id, priv, _ = do_register(patched_client, email="node@test.com")
        token = do_auth(patched_client, user_id, priv)
        c, _, _ = patched_client

        # 发布
        r = c.post("/api/nodes", json={"content": "Hello SuperNode!"}, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 201, r.text
        node = r.json()
        assert node["content"] == "Hello SuperNode!"
        assert node["user_id"] == user_id
        node_id = node["id"]

        # 读取单条（无需认证）
        r = c.get(f"/api/nodes/{node_id}")
        assert r.status_code == 200
        assert r.json()["content"] == "Hello SuperNode!"

        # 读取列表（无需认证）
        r = c.get("/api/nodes")
        assert r.status_code == 200
        items = r.json()
        assert len(items) == 1
        assert items[0]["content"] == "Hello SuperNode!"

    def test_publish_requires_auth(self, patched_client):
        c, _, _ = patched_client
        r = c.post("/api/nodes", json={"content": "no auth"})
        assert r.status_code == 401

    def test_publish_invalid_token(self, patched_client):
        c, _, _ = patched_client
        r = c.post("/api/nodes", json={"content": "bad token"}, headers={"Authorization": "Bearer faketoken"})
        assert r.status_code == 401

    def test_publish_empty_content(self, patched_client):
        user_id, priv, _ = do_register(patched_client, email="empty@test.com")
        token = do_auth(patched_client, user_id, priv)
        c, _, _ = patched_client
        r = c.post("/api/nodes", json={"content": ""}, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 422  # pydantic min_length=1

    def test_multiple_nodes(self, patched_client):
        user_id, priv, _ = do_register(patched_client, email="multi@test.com")
        token = do_auth(patched_client, user_id, priv)
        c, _, _ = patched_client

        for i in range(5):
            r = c.post("/api/nodes", json={"content": f"node {i}"}, headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 201

        r = c.get("/api/nodes")
        assert len(r.json()) == 5

    def test_get_nonexistent_node(self, patched_client):
        c, _, _ = patched_client
        r = c.get("/api/nodes/99999")
        assert r.status_code == 404


class TestMe:
    def test_get_me(self, patched_client):
        user_id, priv, pub = do_register(patched_client, email="me@test.com")
        token = do_auth(patched_client, user_id, priv)
        c, _, _ = patched_client
        r = c.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["user_id"] == user_id
        assert data["email"] == "me@test.com"
        assert data["public_key"] == pub
        assert data["account_mode"] == "recoverable"

    def test_get_me_requires_auth(self, patched_client):
        c, _, _ = patched_client
        r = c.get("/api/me")
        assert r.status_code == 401


class TestHealth:
    def test_health(self, patched_client):
        c, _, _ = patched_client
        r = c.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
