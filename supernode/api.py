"""SuperNode API 路由。

第一版 API（对应设计文档第 18 节）：
    注册:  POST /api/register/start
           POST /api/register/proof
           POST /api/register/verify-email
    认证:  POST /api/auth/challenge
           POST /api/auth/verify
    信息:  GET  /api/nodes
           GET  /api/nodes/{id}
           POST /api/nodes
    账户:  GET  /api/me
"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import timedelta

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import crypto, email as email_svc
from .config import Settings
from .db import (
    AccessToken,
    AuthChallenge,
    Base,
    Node,
    RegistrationSession,
    User,
    create_db_engine,
    create_session_factory,
    hash_token,
    hash_email_code,
    init_db,
    utcnow,
    verify_email_code,
)

logger = logging.getLogger("supernode.api")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# ── 依赖注入 ────────────────────────────────────────────────────────────────

_settings: Settings | None = None
_engine = None
_SFactory = None


def _get_settings() -> Settings:
    global _settings
    if _settings is None:
        from .config import get_settings
        _settings = get_settings()
    return _settings


def _get_db() -> Session:
    db = _SFactory()
    try:
        yield db
    finally:
        db.close()


# ── 请求/响应模型 ──────────────────────────────────────────────────────────


class RegisterStartReq(BaseModel):
    email: str
    public_key: str


class RegisterStartResp(BaseModel):
    registration_id: str
    challenge: str


class RegisterProofReq(BaseModel):
    registration_id: str
    signature: str


class RegisterProofResp(BaseModel):
    ok: bool
    message: str = ""


class RegisterVerifyEmailReq(BaseModel):
    registration_id: str
    code: str


class RegisterVerifyEmailResp(BaseModel):
    ok: bool
    user_id: int | None = None
    message: str = ""


class AuthChallengeReq(BaseModel):
    user_id: int


class AuthChallengeResp(BaseModel):
    challenge_id: int
    challenge: str


class AuthVerifyReq(BaseModel):
    challenge_id: int
    signature: str


class AuthVerifyResp(BaseModel):
    token: str
    user_id: int


class NodeCreateReq(BaseModel):
    content: str = Field(..., min_length=1)


class NodeOut(BaseModel):
    id: int
    content: str
    user_id: int
    created_at: str
    status: str

    model_config = {"from_attributes": True}


# ── 内部工具 ──────────────────────────────────────────────────────────────


def _check_session_active(session: RegistrationSession, purpose: str) -> None:
    """检查注册会话是否仍活跃（未过期、未消费）。"""
    now = utcnow()
    if session.challenge_expires_at < now:
        raise HTTPException(status_code=410, detail="注册会话已过期，请重新开始注册")
    if session.challenge_used and purpose == "proof":
        raise HTTPException(status_code=410, detail="Challenge 已被使用")


def _get_registered_user(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def _extract_bearer(request: Request) -> str | None:
    """从 Authorization 头提取 Bearer token。"""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):]
    return None


def _token_to_user(db: Session, token: str) -> User:
    """用 token 查找用户，过期或不存在则 401。"""
    thash = hash_token(token)
    now = utcnow()
    token_row = db.scalar(
        select(AccessToken).where(AccessToken.token_hash == thash, AccessToken.expires_at > now)
    )
    if token_row is None:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")
    user = db.get(User, token_row.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="用户不存在")
    return user


# ── 应用工厂 ──────────────────────────────────────────────────────────────


def create_app(settings: Settings | None = None) -> FastAPI:
    """构建 FastAPI 应用。"""
    global _settings, _engine, _SFactory

    if settings is not None:
        _settings = settings
    else:
        _settings = _get_settings()

    _engine = create_db_engine(_settings)
    _SFactory = create_session_factory(_engine)
    init_db(_engine)

    app = FastAPI(
        title="SuperNode API",
        description="面向 AI Agent 的低阻力信息节点 v0.1",
        version="0.1.0",
    )

    # ── 注册 ────────────────────────────────────────────────────────────

    @app.post("/api/register/start", response_model=RegisterStartResp)
    def register_start(req: RegisterStartReq, db: Session = Depends(_get_db)):
        """注册开始：提交邮箱 + 公钥，服务器返回 registration_id 和 challenge。"""
        # 1. 验证邮箱格式
        if not EMAIL_RE.match(req.email):
            raise HTTPException(status_code=400, detail="邮箱格式无效")

        # 2. 验证公钥格式
        if not crypto.is_valid_public_key_hex(req.public_key):
            raise HTTPException(status_code=400, detail="公钥格式无效（应为 64 位 hex，32 字节 Ed25519 公钥）")

        # 3. 检查邮箱是否已注册
        if _get_registered_user(db, req.email) is not None:
            raise HTTPException(status_code=409, detail="该邮箱已注册")

        # 4. 生成 registration session + challenge
        registration_id = secrets.token_hex(16)
        challenge = crypto.generate_challenge()
        now = utcnow()
        session = RegistrationSession(
            id=registration_id,
            email=req.email,
            public_key=req.public_key,
            challenge=challenge,
            challenge_expires_at=now + timedelta(seconds=_settings.registration_challenge_ttl),
        )
        db.add(session)
        db.commit()

        # 5. 发送邮箱验证码
        code = email_svc.generate_email_code(_settings.email_code_length)
        send_result = email_svc.send_verification_code(_settings, req.email, code)
        if not send_result.ok:
            db.delete(session)
            db.commit()
            raise HTTPException(status_code=502, detail=f"邮件发送失败: {send_result.error}")

        # 6. 保存验证码哈希
        session.email_code_hash = hash_email_code(code)
        session.email_code_expires_at = now + timedelta(seconds=_settings.email_code_ttl)
        session.email_code_attempts = 0
        db.commit()

        logger.info("注册开始: email=%s reg_id=%s", req.email, registration_id)
        return RegisterStartResp(registration_id=registration_id, challenge=challenge)

    @app.post("/api/register/proof", response_model=RegisterProofResp)
    def register_proof(req: RegisterProofReq, db: Session = Depends(_get_db)):
        """提交私钥对 challenge 的签名，证明持有私钥。"""
        session = db.get(RegistrationSession, req.registration_id)
        if session is None:
            raise HTTPException(status_code=404, detail="注册会话不存在")

        _check_session_active(session, "proof")
        if session.challenge_used:
            raise HTTPException(status_code=410, detail="Challenge 已被使用")

        # 用注册时提交的公钥验证签名
        ok = crypto.verify_hex(session.public_key, session.challenge.encode(), req.signature)
        if not ok:
            raise HTTPException(status_code=401, detail="签名验证失败")

        # 标记 challenge 已消费
        session.challenge_used = True
        session.challenge_verified = True
        db.commit()

        logger.info("注册签名验证通过: email=%s", session.email)
        return RegisterProofResp(ok=True, message="签名验证通过")

    @app.post("/api/register/verify-email", response_model=RegisterVerifyEmailResp)
    def register_verify_email(req: RegisterVerifyEmailReq, db: Session = Depends(_get_db)):
        """提交邮箱验证码，完成注册。

        需要同时满足：
        - 邮箱验证码正确
        - Challenge-Response 签名验证已通过
        """
        session = db.get(RegistrationSession, req.registration_id)
        if session is None:
            raise HTTPException(status_code=404, detail="注册会话不存在")

        now = utcnow()

        # 1. 验证码过期检查
        if session.email_code_expires_at is None or session.email_code_expires_at < now:
            raise HTTPException(status_code=410, detail="邮箱验证码已过期")

        # 2. 尝试次数限制
        if session.email_code_attempts >= _settings.email_code_max_attempts:
            raise HTTPException(status_code=429, detail="验证码尝试次数过多，请重新注册")

        # 3. 验证验证码
        if not verify_email_code(session.email_code_hash, req.code):
            session.email_code_attempts += 1
            db.commit()
            raise HTTPException(
                status_code=401,
                detail=f"验证码错误（剩余尝试次数: {_settings.email_code_max_attempts - session.email_code_attempts}）",
            )

        # 4. 检查签名验证是否已通过
        if not session.challenge_verified:
            raise HTTPException(status_code=412, detail="尚未完成私钥签名验证，请先调用 /api/register/proof")

        # 5. 邮箱已注册检查（防并发重复注册）
        if _get_registered_user(db, session.email) is not None:
            raise HTTPException(status_code=409, detail="该邮箱已注册")

        # 6. 创建用户
        user = User(
            email=session.email,
            email_verified=True,
            public_key=session.public_key,
            account_mode="recoverable",
        )
        db.add(user)
        db.flush()  # 获取 user.id

        # 7. 清理注册会话
        db.delete(session)
        db.commit()

        logger.info("注册完成: user_id=%d email=%s", user.id, user.email)
        return RegisterVerifyEmailResp(ok=True, user_id=user.id, message="注册成功")

    # ── 认证 ────────────────────────────────────────────────────────────

    @app.post("/api/auth/challenge", response_model=AuthChallengeResp)
    def auth_challenge(req: AuthChallengeReq, db: Session = Depends(_get_db)):
        """请求认证 challenge。"""
        user = db.get(User, req.user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")

        challenge = crypto.generate_challenge()
        now = utcnow()
        ch = AuthChallenge(
            user_id=user.id,
            challenge=challenge,
            purpose="auth",
            expires_at=now + timedelta(seconds=_settings.auth_challenge_ttl),
        )
        db.add(ch)
        db.commit()

        return AuthChallengeResp(challenge_id=ch.id, challenge=challenge)

    @app.post("/api/auth/verify", response_model=AuthVerifyResp)
    def auth_verify(req: AuthVerifyReq, db: Session = Depends(_get_db)):
        """提交签名，验证身份，签发 24h token。"""
        ch = db.get(AuthChallenge, req.challenge_id)
        if ch is None:
            raise HTTPException(status_code=404, detail="Challenge 不存在")

        now = utcnow()
        if ch.expires_at < now:
            raise HTTPException(status_code=410, detail="Challenge 已过期")
        if ch.used:
            raise HTTPException(status_code=410, detail="Challenge 已被使用")

        user = db.get(User, ch.user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")

        # Ed25519 验证
        ok = crypto.verify_hex(user.public_key, ch.challenge.encode(), req.signature)
        if not ok:
            raise HTTPException(status_code=401, detail="签名验证失败")

        # 标记 challenge 已消费
        ch.used = True
        db.add(ch)

        # 签发 token（只存哈希）
        token = secrets.token_hex(_settings.token_bytes)
        token_row = AccessToken(
            user_id=user.id,
            token_hash=hash_token(token),
            expires_at=now + timedelta(seconds=_settings.token_ttl),
        )
        db.add(token_row)
        db.commit()

        logger.info("认证成功: user_id=%d", user.id)
        return AuthVerifyResp(token=token, user_id=user.id)

    # ── 信息 ────────────────────────────────────────────────────────────

    @app.get("/api/nodes", response_model=list[NodeOut])
    def list_nodes(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        db: Session = Depends(_get_db),
    ):
        """获取公开信息列表（无需认证）。"""
        rows = db.scalars(
            select(Node)
            .where(Node.status == "approved")
            .order_by(Node.created_at.desc(), Node.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return [
            NodeOut(
                id=n.id,
                content=n.content,
                user_id=n.user_id,
                created_at=n.created_at.isoformat(),
                status=n.status,
            )
            for n in rows
        ]

    @app.get("/api/nodes/{node_id}", response_model=NodeOut)
    def get_node(node_id: int, db: Session = Depends(_get_db)):
        """获取单条信息（无需认证）。"""
        node = db.get(Node, node_id)
        if node is None or node.status not in ("approved", "pending"):
            raise HTTPException(status_code=404, detail="信息不存在")
        return NodeOut(
            id=node.id,
            content=node.content,
            user_id=node.user_id,
            created_at=node.created_at.isoformat(),
            status=node.status,
        )

    @app.post("/api/nodes", response_model=NodeOut, status_code=201)
    def create_node(req: NodeCreateReq, request: Request, db: Session = Depends(_get_db)):
        """发布信息（需要 Bearer token）。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")

        user = _token_to_user(db, token)

        if len(req.content) > _settings.node_content_max_length:
            raise HTTPException(
                status_code=400,
                detail=f"内容过长（最大 {_settings.node_content_max_length} 字符）",
            )

        node = Node(
            user_id=user.id,
            content=req.content,
            status="approved",  # v0.1 默认全部通过，预留审核字段
        )
        db.add(node)
        db.commit()
        db.refresh(node)

        logger.info("发布信息: user_id=%d node_id=%d", user.id, node.id)
        return NodeOut(
            id=node.id,
            content=node.content,
            user_id=node.user_id,
            created_at=node.created_at.isoformat(),
            status=node.status,
        )

    # ── 账户 ────────────────────────────────────────────────────────────

    @app.get("/api/me")
    def get_me(request: Request, db: Session = Depends(_get_db)):
        """获取当前认证用户信息。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")
        user = _token_to_user(db, token)
        return {
            "user_id": user.id,
            "email": user.email,
            "public_key": user.public_key,
            "account_mode": user.account_mode,
            "email_verified": user.email_verified,
            "created_at": user.created_at.isoformat(),
        }

    @app.get("/api/health")
    def health():
        """健康检查。"""
        return {"status": "ok", "version": "0.1.0"}

    return app


# ── 默认应用实例 ──────────────────────────────────────────────────────────

app = create_app()
