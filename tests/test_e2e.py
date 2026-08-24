"""SuperNode v0.1 端到端测试。

覆盖完整流程：
    注册 (start → challenge + 签名 proof → verify-email → user_id)
    → 认证 (challenge → 签名 verify → user_id，新协议不签发 token)
    → 发布信息 (POST /api/nodes, DRY-RUN：不落库、不写日志，凭据独立于档案库)
    → 账户查询 (GET /api/me)
    → 错误路径 (no-auth 401 / bad-token 401 / 缺 registration_id 422 / 空内容 422)
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
    # 重置速率限制器，避免跨测试状态泄漏
    from supernode.ratelimit import get_limiter
    get_limiter()._hits.clear()

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
    data = r.json()
    assert "token" not in data  # 新协议：认证不签发 token
    return data["user_id"]


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
        returned_uid = do_auth(patched_client, user_id, priv)
        assert returned_uid == user_id

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


def _register_and_auth(client_tuple, email):
    """注册 + 认证，返回 (user_id, mock_token, reg_id)。

    mock_token = mock-token-<user_id>（DRY-RUN 模拟凭据，与档案库无关）；
    reg_id 是任意非空 64 位 hex（与 User 行无关，DRY-RUN 不发起出站请求）。
    """
    import secrets as _secrets
    user_id, priv, _ = do_register(client_tuple, email=email)
    do_auth(client_tuple, user_id, priv)
    mock_token = f"mock-token-{user_id}"
    reg_id = _secrets.token_hex(16)
    return user_id, mock_token, reg_id


class TestNodes:
    def test_publish_requires_auth(self, patched_client):
        """① 无凭据 → 401，一轮之内短路，不进入任何检查。"""
        c, _, _ = patched_client
        r = c.post("/api/nodes", json={"content": "no auth", "registration_id": "aa" * 32})
        assert r.status_code == 401

    def test_publish_missing_registration_id(self, patched_client):
        """② 有凭据但缺 registration_id → 422，不是凭据问题。"""
        user_id, mock_token, _ = _register_and_auth(patched_client, "noreg@test.com")
        c, _, _ = patched_client
        r = c.post("/api/nodes",
                   json={"content": "no reg id"},
                   headers={"Authorization": f"Bearer {mock_token}"})
        assert r.status_code == 422

    def test_publish_invalid_token(self, patched_client):
        """③ 凭据格式不匹配任何合法口径 → 401，不进入后端。"""
        user_id, mock_token, reg_id = _register_and_auth(patched_client, "badtoken@test.com")
        c, _, _ = patched_client
        # faketoken{i} 既不是 mock-token-*、也不是纯数字、更不是 64 位 hex
        r = c.post("/api/nodes",
                   json={"content": "bad token", "registration_id": reg_id},
                   headers={"Authorization": "Bearer faketoken00000"})
        assert r.status_code == 401

    def test_publish_empty_content(self, patched_client):
        """④ 合法凭据 + 真 registration_id，但内容为空 → 422（pydantic min_length=1）。"""
        user_id, mock_token, reg_id = _register_and_auth(patched_client, "empty@test.com")
        c, _, _ = patched_client
        r = c.post("/api/nodes",
                   json={"content": "", "registration_id": reg_id},
                   headers={"Authorization": f"Bearer {mock_token}"})
        assert r.status_code == 422

    def test_multiple_nodes_persist(self, patched_client):
        """落库：同 user_id 连续 5 次发布，每次 201 + 真实自增 id，列表能读到 5 条。"""
        user_id, mock_token, reg_id = _register_and_auth(patched_client, email="multi@test.com")
        c, _, _ = patched_client

        ids = []
        for i in range(5):
            r = c.post("/api/nodes",
                       json={"content": f"node {i}", "registration_id": reg_id},
                       headers={"Authorization": f"Bearer {mock_token}"})
            assert r.status_code == 201, f"第 {i+1} 次应 201: {r.text}"
            data = r.json()
            assert data["user_id"] == user_id
            assert data["status"] == "approved"
            ids.append(data["id"])

        # id 应互不相同（真实自增，不是随机 stub）
        assert len(set(ids)) == 5
        # 列表能读到 5 条（已落库）
        r = c.get("/api/nodes")
        assert r.status_code == 200
        assert len(r.json()) == 5
        # 第 6 次同样 201，绝不 500
        r = c.post("/api/nodes",
                   json={"content": "one more", "registration_id": reg_id},
                   headers={"Authorization": f"Bearer {mock_token}"})
        assert r.status_code == 201

    def test_publish_id_is_readable(self, patched_client):
        """落库：发布返回的 id，GET /api/nodes/{id} 应 200 能读回（已落库）。"""
        user_id, mock_token, reg_id = _register_and_auth(patched_client, email="stubid@test.com")
        c, _, _ = patched_client
        r = c.post("/api/nodes",
                   json={"content": "real node", "registration_id": reg_id},
                   headers={"Authorization": f"Bearer {mock_token}"})
        assert r.status_code == 201
        node_id = r.json()["id"]
        # 同一 id 对应的后端 GET 应 200（已落库）
        r2 = c.get(f"/api/nodes/{node_id}")
        assert r2.status_code == 200
        assert r2.json()["content"] == "real node"

    def test_get_nonexistent_node(self, patched_client):
        c, _, _ = patched_client
        r = c.get("/api/nodes/99999")
        assert r.status_code == 404


class TestMe:
    def test_get_me(self, patched_client):
        user_id, priv, pub = do_register(patched_client, email="me@test.com")
        do_auth(patched_client, user_id, priv)  # 走一遍认证
        c, _, _ = patched_client
        # DRY-RUN：凭据独立于档案库；/api/me 不验证真实 token（mock token 即可）
        r = c.get("/api/me", headers={"Authorization": f"Bearer mock-token-{user_id}"})
        assert r.status_code == 200
        data = r.json()
        assert data["user_id"] == user_id
        assert data["email"] == "me@test.com"
        assert data["public_key"] == pub
        assert "account_mode" not in data  # 已移除；公钥不可变，email 只用于一次性注册反暴力

    def test_get_me_requires_auth(self, patched_client):
        c, _, _ = patched_client
        r = c.get("/api/me")
        assert r.status_code == 401


class TestRecover:
    def test_recover_start_unknown_user(self, patched_client):
        """不存在的 user_id → 404。"""
        c, _, _ = patched_client
        r = c.post("/api/auth/recover/start", json={"user_id": 999999})
        assert r.status_code == 404

    def test_recover_start_unique_user(self, patched_client):
        """存在的用户 → 200 返回 challenge。"""
        user_id, _, _ = do_register(patched_client, email="recstart@test.com")
        c, _, _ = patched_client
        r = c.post("/api/auth/recover/start", json={"user_id": user_id})
        assert r.status_code == 200
        data = r.json()
        assert "challenge" in data
        assert len(data["challenge"]) == 32  # 16 字节 hex

    def test_recover_confirm_bad_signature(self, patched_client):
        """短签名 → 422。"""
        c, _, _ = patched_client
        r = c.post("/api/auth/recover/confirm", json={"challenge_id": -1, "signature": "deadbeef"})
        assert r.status_code == 422

    def test_recover_confirm_good_signature(self, patched_client):
        """合法 64-hex 签名 → 200，不签发 token。"""
        import secrets as _secrets
        c, _, _ = patched_client
        sig = _secrets.token_hex(64)
        r = c.post("/api/auth/recover/confirm", json={"challenge_id": -1, "signature": sig})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True


class TestRateLimit:
    def test_auth_challenge_rate_limit(self, patched_client):
        """超过 10 次/分钟应返回 429。"""
        user_id, priv, _ = do_register(patched_client, email="rl@test.com")
        c, _, _ = patched_client

        # 前 10 次应成功
        for i in range(10):
            r = c.post("/api/auth/challenge", json={"user_id": user_id})
            assert r.status_code == 200, f"第 {i+1} 次应成功: {r.text}"

        # 第 11 次应被限流
        r = c.post("/api/auth/challenge", json={"user_id": user_id})
        assert r.status_code == 429

    def test_register_rate_limit(self, patched_client):
        """超过 5 次/小时应返回 429。"""
        c, _, _ = patched_client
        priv, pub = crypto.generate_keypair()

        for i in range(5):
            email = f"rl{i}@test.com"
            r = c.post("/api/register/start", json={"email": email, "public_key": pub})
            assert r.status_code == 200, f"第 {i+1} 次应成功: {r.text}"

        # 第 6 次应被限流
        r = c.post("/api/register/start", json={"email": "rl5@test.com", "public_key": pub})
        assert r.status_code == 429


class TestHealth:
    def test_health(self, patched_client):
        c, _, _ = patched_client
        r = c.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestPages:
    """新增的人工首页 / AI 接入指南 / 纯文本 API 文档路由。"""

    def test_root_home_empty(self, patched_client):
        """空库时，首页应渲染 200 + HTML + 空态占位。"""
        c, _, _ = patched_client
        r = c.get("/")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "SuperNode" in r.text
        assert "最新动态" in r.text
        assert "还没有信息" in r.text
        assert "/en.html" in r.text
        assert "/api/docs" in r.text

    def test_home_shows_latest_set_nodes(self, patched_client):
        """有节点时，首页应显示最新 3 条，顺序按 ID 倒序。
        节点通过 ORM 直接插入（发布接口是 DRY-RUN，不落库），仅验证首页渲染逻辑。"""
        c, settings, _ = patched_client
        from supernode.db import Base, Node, create_db_engine, create_session_factory

        engine = create_db_engine(settings)
        SessionLocal = create_session_factory(engine)
        db = SessionLocal()
        try:
            for i in range(1, 6):
                db.add(Node(user_id=997, content=f"home post {i}", status="approved"))
            db.commit()
        finally:
            db.close()
            engine.dispose()
        r = c.get("/")
        # 最新 3 条：home post 5, 4, 3（id 降序）
        assert "home post 5" in r.text
        assert "home post 4" in r.text
        assert "home post 3" in r.text
        assert "home post 2" not in r.text
        assert "home post 1" not in r.text

    def test_onboarding_en_html_plaintext(self, patched_client):
        "/en.html 返回纯文本 AI 接入指南。"
        c, _, _ = patched_client
        r = c.get("/en.html")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]
        assert "/api/register/start" in r.text
        assert "/api/auth/challenge" in r.text
        assert "/api/nodes" in r.text
        assert "/api/docs" in r.text

    def test_connect_txt_agent_prompt(self, patched_client):
        c, _, _ = patched_client
        r = c.get("/connect.txt")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]
        # Agent prompt 应该是简短的，且提及 base URL 与 en.html 链接
        assert "/en.html" in r.text
        assert len(r.text) < 2000

    def test_api_docs_moved_from_root(self, patched_client):
        """/api/docs 保留原文；根路径不再返回该文档。"""
        c, _, _ = patched_client
        r = c.get("/api/docs")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]
        assert "SuperNode API v0.1" in r.text
        # 这些旧端点文档必须完整送达
        for kw in ("/api/register/start", "/api/auth/challenge", "/api/nodes", "HTTP 429"):
            assert kw in r.text, f"missing {kw}"
        # 根路径返回 HTML 而非纯文本
        rh = c.get("/")
        assert "text/html" in rh.headers["content-type"]
