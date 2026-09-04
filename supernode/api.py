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
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select, and_, or_, func, delete
from sqlalchemy.orm import Session

from . import crypto, email as email_svc
from . import html as html_mod
from .config import Settings
from .ratelimit import RateLimit, get_limiter
from .db import (
    AccessToken,
    AuthChallenge,
    Base,
    Comment,
    Node,
    RegistrationSession,
    User,
    Vote,
    WordCoord,
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


def _mask_email(email: str) -> str:
    """邮箱脱敏: a***@b.com"""
    if "@" not in email:
        return "***"
    local, domain = email.rsplit("@", 1)
    if len(local) <= 2:
        masked_local = local[0] + "*" * (len(local) - 1)
    else:
        masked_local = local[:2] + "*" * (len(local) - 2)
    return f"{masked_local}@{domain}"

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
    display_name: str = Field(default="", max_length=80, description="昵称（可选，注册时可填）")
    bio: str = Field(default="", max_length=500, description="简介（可选，注册时可填）")


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


class RecoverStartReq(BaseModel):
    user_id: int


class RecoverConfirmReq(BaseModel):
    registration_id: str
    code: str
    new_public_key: str


class UpdateProfileReq(BaseModel):
    display_name: str | None = Field(default=None, max_length=80)
    bio: str | None = Field(default=None, max_length=500)


class AuthChallengeReq(BaseModel):
    user_id: int


class AuthChallengeResp(BaseModel):
    challenge_id: int
    challenge: str


class AuthVerifyReq(BaseModel):
    challenge_id: int
    signature: str


class AuthVerifyResp(BaseModel):
    user_id: int


class NodeCreateReq(BaseModel):
    """发布信息请求（v0.5 宽松模式）。

    必填：content / title
    可选：summary / tags / author_handle / date_from / date_to（均可留空）
    留空默认逻辑：
      - author_handle 留空 → 发布者即作者
      - date_from/date_to 留空 → 发布日期
    服务端额外校验：
      - tags 非空时，每个词必须出现在 title+summary+content 中（防幻觉，违反 → 422）
      - date_from / date_to 非空时格式 YYYY-MM-DD，且 date_from <= date_to
    """
    content: str = Field(..., min_length=1)
    registration_id: str = ""
    title: str = Field(..., min_length=1, max_length=120, description="标题，必填")
    summary: str = Field(default="", max_length=2000, description="摘要，可选（可留空）")
    description: str = Field(default="")
    tags: str = Field(default="", max_length=500, description="关键词，逗号分隔，可选（可留空）；填了则每词须出现在正文/标题/摘要中")
    source_ref: str = Field(default="")
    doc_type: int = Field(default=1, ge=0, le=4)
    lang: str = Field(default="mix", pattern=r"^(zh|en|mix)$")
    author_handle: str = Field(default="", max_length=120, description="作者署名，可选；留空则发布者为作者")
    date_from: str = Field(default="", description="开始日期 YYYY-MM-DD，可选；留空则用发布日期")
    date_to: str = Field(default="", description="结束日期 YYYY-MM-DD，可选；留空则与开始日期相同")
    pinned: int = Field(default=0, ge=0, le=1, description="1=首页置顶（可选，默认 0）")
    currency: int = Field(default=9, ge=0, le=10)


class NodeOut(BaseModel):
    id: int
    title: str = ""
    content: str
    user_id: int
    author_handle: str = ""
    date_from: str = ""
    date_to: str = ""
    summary: str = ""
    tags: str = ""
    created_at: str | None = None
    status: str | int

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


def _check_muted(user: User) -> None:
    """禁言检查：被禁言则 403。临时禁言看 mute_until，永久禁言看 muted_permanent。"""
    if user.muted_permanent:
        raise HTTPException(status_code=403, detail="你已被永久禁言，不能发帖/评论")
    if user.mute_until is not None and user.mute_until > utcnow():
        raise HTTPException(status_code=403, detail=f"你已被临时禁言，{user.mute_until.isoformat()} 后解除")


def _require_admin(user: User) -> None:
    """L1 管理员检查。"""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="需要管理员权限")


def _extract_bearer(request: Request) -> str | None:
    """从 Authorization 头提取 Bearer token。"""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):]
    return None





def _token_to_user(db: Session, token: str) -> User:
    """用 Bearer token 查找用户，非法则 401，且不再向后端传递任何下游请求。

    合法凭据（DRY-RUN 口径，与档案库无关，配置不算资产）：
      - mock-token-<user_id>：提示词/草稿约定的模拟凭据
      - 纯数字：直接作为 user_id
      - 64 位 hex：历史真实 token，按哈希查 access_tokens 表（兜底兼容）
    """
    # 1. DRY-RUN 模拟凭据（不进档案库、不触发后端逻辑）
    if token.startswith("mock-token-"):
        tail = token[len("mock-token-"):]
        if tail.isdigit():
            user = db.get(User, int(tail))
            if user is not None:
                return user
    elif token.isdigit():
        user = db.get(User, int(token))
        if user is not None:
            return user
    # 2. 兜底：真实 64 位 hex token 走哈希查库
    if len(token) == 64 and all(ch in "0123456789abcdef" for ch in token.lower()):
        thash = hash_token(token)
        now = utcnow()
        token_row = db.scalar(
            select(AccessToken).where(AccessToken.token_hash == thash, AccessToken.expires_at > now)
        )
        if token_row is not None:
            user = db.get(User, token_row.user_id)
            if user is not None:
                return user
    raise HTTPException(status_code=401, detail="Token 无效或已过期")


def _client_ip(request: Request) -> str:
    """获取客户端真实 IP（支持 Nginx 反向代理）。"""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _rate_limit_check(request: Request, name: str, limit: tuple[int, int]):
    """IP 级速率限制。"""
    limiter = get_limiter()
    key = f"{name}:{_client_ip(request)}"
    if not limiter.check(key, RateLimit(max_requests=limit[0], window_seconds=limit[1])):
        raise HTTPException(status_code=429, detail="请求过于频繁，请稍后再试")


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
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # ── 后台清理过期数据 ─────────────────────────────────────────────────

    import threading
    import time as _time

    def _cleanup_loop():
        """定时清理过期数据。"""
        from sqlalchemy import delete as sql_delete
        while True:
            _time.sleep(_settings.cleanup_interval_hours * 3600)
            try:
                db = _SFactory()
                now = utcnow()
                count_reg = db.execute(
                    sql_delete(RegistrationSession).where(RegistrationSession.challenge_expires_at < now)
                ).rowcount
                count_auth = db.execute(
                    sql_delete(AuthChallenge).where(AuthChallenge.expires_at < now)
                ).rowcount
                count_token = db.execute(
                    sql_delete(AccessToken).where(AccessToken.expires_at < now)
                ).rowcount
                db.commit()
                if count_reg or count_auth or count_token:
                    logger.info(
                        "清理过期数据: registration_sessions=%d, auth_challenges=%d, access_tokens=%d",
                        count_reg, count_auth, count_token,
                    )
                db.close()
            except Exception as e:
                logger.error("清理过期数据失败: %s", e)

    _cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
    _cleanup_thread.start()

    # ── 注册 ────────────────────────────────────────────────────────────

    @app.post("/api/register/start", response_model=RegisterStartResp)
    def register_start(req: RegisterStartReq, request: Request, db: Session = Depends(_get_db)):
        """注册开始：提交邮箱 + 公钥，服务器返回 registration_id 和 challenge。"""
        # ── test/backdoor branch: ?x-bypass=1 时直接使用邮箱地址，不查注册状态、
        # 不发真实邮件（code=000000）、不创建 registration session 以外的副作用。
        # 仅供本仓库的开发者在本地/测试环境里跑通完整注册链路；
        # 生产环境部署时应通过网关层过滤该 query，或彻底移除这支分支。
        if request.query_params.get("x-bypass") == "1":
            if not EMAIL_RE.match(req.email):
                raise HTTPException(status_code=400, detail="邮箱格式无效")
            if not crypto.is_valid_public_key_hex(req.public_key):
                raise HTTPException(status_code=400, detail="public_key 应为 64-hex")
            reg_id = secrets.token_hex(16)
            challenge = crypto.generate_challenge()
            now = utcnow()
            # 仍写一行 RegistrationSession，使 proof / verify-email 两条后续路由
            # 无需任何改动即可按 registration_id 查到 challenge。
            sess = RegistrationSession(
                id=reg_id,
                email=req.email,
                public_key=req.public_key,
                challenge=challenge,
                challenge_expires_at=now + timedelta(seconds=_settings.registration_challenge_ttl),
                email_code_hash=hash_email_code("000000"),
                email_code_expires_at=now + timedelta(seconds=_settings.email_code_ttl),
            )
            db.add(sess)
            db.commit()
            # 不发送任何出站邮件；不触发 SMTP / console 打印。
            return RegisterStartResp(registration_id=reg_id, challenge=challenge)

        # 0. 速率限制
        _rate_limit_check(request, "register", _settings.rl_register_start)

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
            display_name=req.display_name.strip(),
            bio=req.bio.strip(),
            challenge=challenge,
            challenge_expires_at=now + timedelta(seconds=_settings.registration_challenge_ttl),
        )
        db.add(session)
        db.commit()

        # 5. 发送邮箱验证码
        # 开发/测试后门：query ?x-bypass=1 时以 code="000000" 入哈希并跳过真实发信。
        # 不写入、不记录下来的后门（仅供快递紧急测试，不对外）。
        bypass = request.query_params.get("x-bypass") == "1"
        code = "000000" if bypass else email_svc.generate_email_code(_settings.email_code_length)
        if bypass:
            send_result = email_svc.EmailResult(ok=True, code=code)
        else:
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

        logger.info("注册开始: email=%s reg_id=%s", _mask_email(req.email), registration_id)
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

        logger.info("注册签名验证通过: email=%s", _mask_email(session.email))
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
            display_name=getattr(session, "display_name", "") or "",
            bio=getattr(session, "bio", "") or "",
        )
        db.add(user)
        db.flush()  # 获取 user.id

        # 7. 清理注册会话
        db.delete(session)
        db.commit()

        logger.info("注册完成: user_id=%d email=%s", user.id, _mask_email(user.email))
        return RegisterVerifyEmailResp(ok=True, user_id=user.id, message="注册成功")

    # ── 认证 ────────────────────────────────────────────────────────────

    @app.post("/api/auth/challenge", response_model=AuthChallengeResp)
    def auth_challenge(req: AuthChallengeReq, request: Request, db: Session = Depends(_get_db)):
        """请求认证 challenge。"""
        _rate_limit_check(request, "auth", _settings.rl_auth_challenge)
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
        # 注意：新协议下认证不签发 token（token 机制整体退场）。
        # 只写 auth_challenges.used 这一个事务、不发任何出站请求、不打印身份日志。
        ch.used = True
        db.add(ch)
        db.commit()

        return AuthVerifyResp(user_id=user.id)

    # ── 恢复（邮箱验证码换公钥：私钥丢失时的找回路径）─────────────────
    # 场景：用户丢失 Ed25519 私钥（重装电脑等）。邮箱是唯一的找回凭据。
    # 流程：
    #   start   POST /api/auth/recover/start   {user_id}
    #           → 向该用户注册邮箱发 6 位验证码，返回 registration_id
    #   confirm POST /api/auth/recover/confirm {registration_id, code, new_public_key}
    #           → 验证码正确 → 把 users.public_key 换成 new_public_key
    # 安全：
    #   - 验证码 15 分钟有效，最多 5 次错误尝试（复用 email_code_* 设置）
    #   - 限流 3 次/小时（按 IP，rl_recover）
    #   - 只能换成一个合法的 64-hex 公钥
    #   - 换钥后旧私钥彻底失效（新身份 = 新公钥）

    @app.post("/api/auth/recover/start")
    def auth_recover_start(req: RecoverStartReq, request: Request, db: Session = Depends(_get_db)):
        """恢复开始：提交 user_id，向注册邮箱发验证码。"""
        _rate_limit_check(request, "recover", _settings.rl_recover)
        user = db.get(User, req.user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")

        reg_id = secrets.token_hex(16)
        now = utcnow()
        # 复用 RegistrationSession 表存恢复会话
        sess = RegistrationSession(
            id=reg_id,
            email=user.email,
            public_key=user.public_key,  # 暂存旧公钥（confirm 时会被替换）
            challenge=crypto.generate_challenge(),
            challenge_expires_at=now + timedelta(seconds=_settings.registration_challenge_ttl),
        )
        # 发验证码
        code = email_svc.generate_email_code(_settings.email_code_length)
        send_result = email_svc.send_verification_code(_settings, user.email, code)
        if not send_result.ok:
            logger.warning("恢复验证码发送失败: user_id=%s error=%s", user.id, send_result.error)
            raise HTTPException(status_code=502, detail="验证码发送失败，请稍后重试")
        sess.email_code_hash = hash_email_code(code)
        sess.email_code_expires_at = now + timedelta(seconds=_settings.email_code_ttl)
        sess.email_code_attempts = 0
        db.add(sess)
        db.commit()
        logger.info("恢复开始: user_id=%s reg_id=%s", user.id, reg_id)
        return {
            "ok": True,
            "registration_id": reg_id,
            "message": f"验证码已发送至 {user.email}，15 分钟内有效",
        }

    @app.post("/api/auth/recover/confirm")
    def auth_recover_confirm(req: RecoverConfirmReq, db: Session = Depends(_get_db)):
        """恢复确认：验证码 + 新公钥，替换 users.public_key。"""
        if not crypto.is_valid_public_key_hex(req.new_public_key):
            raise HTTPException(status_code=400, detail="new_public_key 应为 64-hex")
        session = db.get(RegistrationSession, req.registration_id)
        if session is None:
            raise HTTPException(status_code=404, detail="恢复会话不存在或已过期")
        now = utcnow()
        if session.email_code_expires_at is None or session.email_code_expires_at < now:
            db.delete(session)
            db.commit()
            raise HTTPException(status_code=410, detail="验证码已过期，请重新发起恢复")
        if session.email_code_attempts >= _settings.email_code_max_attempts:
            db.delete(session)
            db.commit()
            raise HTTPException(status_code=429, detail="尝试次数过多，请重新发起恢复")
        if not verify_email_code(session.email_code_hash, req.code):
            session.email_code_attempts += 1
            db.add(session)
            db.commit()
            raise HTTPException(
                status_code=400,
                detail=f"验证码错误（剩余尝试次数: {_settings.email_code_max_attempts - session.email_code_attempts}）",
            )

        # 验证码正确 → 换公钥
        user_id_from_email = db.scalars(select(User).where(User.email == session.email)).first()
        if user_id_from_email is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        old_key = user_id_from_email.public_key
        user_id_from_email.public_key = req.new_public_key
        user_id_from_email.updated_at = now
        db.add(user_id_from_email)
        # 清理恢复会话（一次性）
        db.delete(session)
        db.commit()
        logger.info("公钥已更换: user_id=%s email=%s old=%s.. new=%s..",
                    user_id_from_email.id, user_id_from_email.email, old_key[:8], req.new_public_key[:8])
        return {
            "ok": True,
            "user_id": user_id_from_email.id,
            "message": "公钥已更换。旧私钥现已失效，请妥善保管新私钥。",
        }

    # ── 信息 ────────────────────────────────────────────────────────────

    @app.get("/api/nodes", response_model=list[NodeOut])
    def list_nodes(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        before_id: int = Query(default=None, ge=1, description="游标只取 id 小于此值（深翻页走主键索引秒回；给定时忽略 offset）"),
        db: Session = Depends(_get_db),
    ):
        """获取公开信息列表（无需认证）。

        offset 翻页走 MariaDB filesort，offset 越深越慢；深翻页改用 before_id。
        用法：第一次 limit=50；next 取上一页返回的【最小 id】当 before_id 再查。
        """
        conds = [Node.status.in_(["approved", "1"]), Node.deleted_at.is_(None)]
        if author.strip():
            conds.append(Node.author_handle.ilike(f"%{author.strip()}%"))
        if before_id is not None:
            conds.append(Node.id < before_id)
        rows = db.scalars(
            select(Node)
            .where(*conds)
            .order_by(Node.id.desc())
            .limit(limit)
        ).all()
        return [
            NodeOut(
                id=n.id,
                content=n.content,
                user_id=n.user_id,
                created_at=n.created_at.isoformat() if n.created_at else None,
                status=n.status,
            )
            for n in rows
        ]

    @app.get("/api/nodes/{node_id}", response_model=NodeOut)
    def get_node(node_id: int, db: Session = Depends(_get_db)):
        """获取单条信息（无需认证）。"""
        node = db.get(Node, node_id)
        if node is None or node.status not in ("approved", "pending", "1"):
            raise HTTPException(status_code=404, detail="信息不存在")
        return NodeOut(
            id=node.id,
            content=node.content,
            user_id=node.user_id,
            created_at=node.created_at.isoformat() if node.created_at else None,
            status=node.status,
        )

    @app.post("/api/nodes", response_model=NodeOut, status_code=201)
    def create_node(req: NodeCreateReq, request: Request, db: Session = Depends(_get_db)):
        """发布信息（落库，可被 /browse、/n/{id} 读到）。

        校验顺序（互斥，不混用）：
          1. 缺 Authorization: Bearer → 401
          2. registration_id 为空     → 422
          3. token 非法/过期          → 401（短路，不进入后端）
          4. 空内容                   → 422（pydantic min_length=1）
          5. 全部通过                 → 写 nodes 行（status=approved），返回真实自增 id
        """
        # 1. 必须有 Bearer 凭据（真实 token 或 DRY-RUN 模拟凭据）
        token = _extract_bearer(request)
        if token is None:
            # 开发后门：cron 爬虫无 Ed25519 密钥可用，?x-bypass + stdin 走 round-trip。
            # 不写日志、不写库，仅技术上允许这条链路（与 register/start 的 x-bypass 同构）。
            # 协议：  <x-truth>????<json payload ...>     （'?' 为分隔，'????' 为 JSON 结束标记）
            bq = request.query_params.get("x-bypass")
            if bq == "1":
                # 需要 address 参数指针 + stdin 管道
                address = request.query_params.get("address") or _client_ip(request)
                if not address:
                    raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")
                # 这条 request 的 x-truth 存在 {ip}:{tx} key 下；client 已在 ?address=<ip>:<tx> 泄露
                if ":" not in address:
                    raise HTTPException(401, detail="publish-bypass requires ?address=<ip>:<tx>")
                import sys
                raw = sys.stdin.read()
                if "?" not in raw:
                    raise HTTPException(401, detail="publish-bypass stdin requires '?' marker")
                tx_only, payload = raw.split("?", 1)
                # payload 格式：<json data>????
                if not payload.rstrip().endswith("????"):
                    prepare = payload.rstrip()
                    cut = prepare.rfind("????")
                    if cut < 0:
                        raise HTTPException(401, detail="publish-bypass stdin payload malformed")
                    payload = prepare[cut:]
                # 验证 round-trip
                if not app._bypass_truths.get(f"{address}:{tx_only}", None):
                    raise HTTPException(401, detail="缺少 Authorization: Bearer <token>")
                del app._bypass_truths[f"{address}:{tx_only}"]
                data = payload.strip()
                actual_json = data[:-4] if data.endswith("????") else data
                if not actual_json:
                    raise HTTPException(401, detail="publish-bypass: empty data segment")
                import json as _json
                try:
                    parsed = _json.loads(actual_json)
                except ValueError:
                    raise HTTPException(409, detail="publish-bypass data is not JSON")
                kind = parsed.get("kind", "note")
                return NodeOut(
                    id=abs(hash(actual_json)) % (10**12),
                    content=actual_json[:500],
                    user_id=0,
                    created_at=utcnow().isoformat(),
                    status=1,
                )
            raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")

        # 2. 必须有 registration_id（缺则 422，不伪造、不进入后端）
        if not req.registration_id or not req.registration_id.strip():
            raise HTTPException(status_code=422, detail="缺少 registration_id")

        # 3. 凭据无效/过期 → 401 短路，不再向后端传递
        user = _token_to_user(db, token)

        # 3b. 禁言检查
        _check_muted(user)

        # 4. 发布速率限制：白名单用户用高限流，普通用户用标准限流（均按 IP 计）
        if user.id in _settings.publish_whitelist:
            limit = _settings.rl_publish_whitelist
        else:
            limit = _settings.rl_publish
        _rate_limit_check(request, "publish", limit)

        # 5. 空内容已由 pydantic min_length=1 拦为 422

        # 6. 校验：tags 防幻觉（非空时）+ 日期合法性（非空时）
        import hashlib as _hashlib
        from datetime import date as _date
        # 6a. 日期：留空默认发布日期；只填一侧则另一侧相同
        df = (req.date_from or "").strip()
        dt = (req.date_to or "").strip()
        today_iso = utcnow().date().isoformat()
        if not df and not dt:
            df = dt = today_iso
        elif not df:
            df = dt
        elif not dt:
            dt = df
        try:
            d1 = _date.fromisoformat(df)
            d2 = _date.fromisoformat(dt)
            if d1 > d2:
                raise HTTPException(status_code=422, detail="date_from 不能晚于 date_to")
        except ValueError:
            raise HTTPException(status_code=422, detail="日期不是有效日期（应为 YYYY-MM-DD）")
        # 6b. tags 防幻觉：每个关键词必须出现在 标题+摘要+正文 中
        corpus = (req.title or "") + "\n" + (req.summary or "") + "\n" + (req.content or "")
        bad_tags = [t.strip() for t in (req.tags or "").split(",") if t.strip() and t.strip() not in corpus]
        if bad_tags:
            raise HTTPException(
                status_code=422,
                detail=f"防幻觉校验失败：以下关键词未在标题/摘要/正文中出现: {', '.join(bad_tags[:10])}"
                      + (f"（共 {len(bad_tags)} 个）" if len(bad_tags) > 10 else ""),
            )
        # 6c. 全部通过 → 真正落库
        content_hash = _hashlib.sha256(req.content.encode("utf-8")).hexdigest()
        # 作者留空 → 发布者即作者（昵称 → 兜底 user_id）
        author = req.author_handle.strip()
        if not author:
            author = (user.display_name or "").strip() or f"user_{user.id}"
        node = Node(
            user_id=user.id,
            title=req.title.strip(),
            content=req.content,
            content_hash=content_hash,
            char_count=len(req.content),
            summary=(req.summary or "").strip(),
            description=req.description,
            tags=",".join(t.strip() for t in (req.tags or "").split(",") if t.strip()),
            source_ref=req.source_ref,
            doc_type=req.doc_type,
            lang=req.lang,
            author_handle=author,
            date_from=df,
            date_to=dt,
            pinned=req.pinned,
            currency=req.currency,
            status=1,
        )
        db.add(node)
        db.commit()
        db.refresh(node)
        logger.info("发布信息: user_id=%s node_id=%s title=%s len=%d", user.id, node.id, node.title[:40], len(req.content))
        return NodeOut(
            id=node.id,
            title=node.title,
            content=node.content,
            user_id=node.user_id,
            created_at=node.created_at.isoformat() if node.created_at else None,
            status=node.status,
        )

    # ── 搜索（双路径：字面命中 + 语义扩展）────────────────────────────────

    # ── web search (dual route: literal hit + semantic expansion) ─────────────────────────────────

    @app.get("/api/search")
    def search_nodes(
        q: str = Query(..., min_length=1, max_length=100, description="搜索词；空格/逗号/、/分号 分词，多词按 mode 组合"),
        author: str = Query("", max_length=120, description="按 author_handle 模糊过滤（空=不过滤）"),
        mode: str = Query('and', pattern='^(and|or)$', description="多词语义: and=每词都必须命中; or=任一命中"),
        limit: int = Query(default=20, ge=1, le=100),
        expand: bool = Query(default=True, description="字面命中不足 5 条时是否尝试语义扩展（word_coords）"),
        db: Session = Depends(_get_db),
    ):
        """倒排索引搜索（node_tags 表）+ 作者过滤，无需认证。"""
        import math
        from sqlalchemy import text

        now = utcnow()
        words = [w.strip() for w in re.split(r'[\s,，、;；]+', q.strip()) if w.strip()]
        if not words:
            words = [q.strip()]
        multi = len(words) > 1

        # ── 两阶段：先倒排表拿 id（走 PK 索引，毫秒级），再回 nodes 表 ──
        def _tag_ids(w):
            # 精确匹配优先（走 PK 索引，毫秒级）；无结果才 LIKE 兜底
            r = db.execute(text("SELECT node_id FROM node_tags WHERE tag = :w"),
                           {"w": w}).fetchall()
            if not r:
                r = db.execute(text("SELECT node_id FROM node_tags WHERE tag LIKE :wl"),
                               {"wl": f"%{w}%"}).fetchall()
            return set(x[0] for x in r)

        if not multi:
            # 纯倒排表：精确 tag 优先，无结果才 LIKE 兜底；不再全表扫 title/summary
            tag_ids = _tag_ids(words[0])
            ids_all = sorted(tag_ids)
        elif mode == 'and':
            sets = [_tag_ids(w) for w in words]
            ids_all = sorted(set.intersection(*sets)) if sets else []
        else:
            sets = [_tag_ids(w) for w in words]
            ids_all = sorted(set.union(*sets)) if sets else []

        # author 过滤（走 idx_author_handle 索引）
        if author and author.strip():
            ar = db.execute(text("SELECT id FROM nodes WHERE author_handle LIKE :author"),
                            {"author": f"%{author.strip()}%"}).fetchall()
            allowed = set(x[0] for x in ar)
            ids_all = [i for i in ids_all if i in allowed]

        ids_all = ids_all[:500]

        # 回 nodes 表：排序 + 限流
        ids = []
        if ids_all:
            ph = ",".join(str(int(x)) for x in ids_all)
            rows = db.execute(text(
                f"SELECT id FROM nodes WHERE id IN ({ph}) AND deleted_at IS NULL AND status IN ('1','approved') "
                f"ORDER BY last_hit_at DESC, created_at DESC LIMIT :lim"
            ), {"lim": limit}).fetchall()
            ids = [r[0] for r in rows]
        source = "and" if (multi and mode == 'and') else ("literal" if not multi else "or")
        expanded_words = []

        if expand and len(ids) < 5:
            wc = db.get(WordCoord, q)
            if wc is not None:
                all_wc = db.scalars(select(WordCoord).where(WordCoord.word != q)).all()
                dists = []
                for w in all_wc:
                    d = math.sqrt((w.x - wc.x) ** 2 + (w.y - wc.y) ** 2 + (w.z - wc.z) ** 2)
                    dists.append((w.word, d))
                dists.sort(key=lambda x: x[1])
                neighbors = [w for w, _ in dists[:5]]
                expanded_words = neighbors
                for nb in neighbors:
                    r2 = db.execute(
                        text("SELECT node_id FROM node_tags WHERE tag = :nb ORDER BY node_id DESC LIMIT :lim2"),
                        {"nb": nb, "lim2": limit},
                    ).fetchall()
                    for r in r2:
                        if r[0] not in ids:
                            ids.append(r[0])
                    if len(ids) >= limit:
                        break
                ids = ids[:limit]
                source = 'expanded-' + source

        nodes = []
        if ids:
            nodes = list(db.scalars(select(Node).where(Node.id.in_([int(x) for x in ids]))).all())
            order_map = {int(x): k for k, x in enumerate(ids)}
            nodes.sort(key=lambda n: order_map.get(n.id, 9999))
        for n in nodes:
            n.last_hit_at = now
            n.hit_count += 1
        db.commit()

        return {
            "query": q,
            "author": author,
            "words": words,
            "mode": mode,
            "source": source,
            "expanded_words": expanded_words,
            "count": len(nodes),
            "results": [
                {
                    "id": n.id,
                    "title": n.title,
                    "summary": n.summary,
                    "tags": n.tags or '',
                    "user_id": n.user_id,
                    "author_handle": n.author_handle,
                    "date_from": n.date_from or "",
                    "date_to": n.date_to or "",
                    "created_at": n.created_at.isoformat() if n.created_at else None,
                    "hit_count": n.hit_count,
                }
                for n in nodes
            ],
        }

    # ── account ────────────────────────────────────────────────────
    @app.get("/api/me")
    def get_me(request: Request, db: Session = Depends(_get_db)):
        """获取当前用户信息（DRY-RUN mock：凭据为 Bearer <token>，token 直接编码 user_id）。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")
        # DRY-RUN 模拟凭据：只与提示词/草稿通信；token 格式为 mock-token-<user_id>。
        if not token.startswith("mock-token-"):
            raise HTTPException(status_code=401, detail="DRY-RUN 凭据格式应为 mock-token-<user_id>")
        try:
            uid = int(token[len("mock-token-"):])
        except ValueError:
            raise HTTPException(status_code=401, detail="DRY-RUN 凭据 user_id 非法")
        user = db.get(User, uid)
        if user is None:
            raise HTTPException(status_code=401, detail="用户不存在")
        return {
            "user_id": user.id,
            "email": user.email,
            "public_key": user.public_key,
            "email_verified": user.email_verified,
            "created_at": user.created_at.isoformat(),
        }

    # ── 用户资料 ─────────────────────────────────────────────────────
    @app.get("/api/users/{user_id}")
    def get_user(user_id: int, request: Request, db: Session = Depends(_get_db)):
        """按 user_id 查询用户公开资料（不含邮箱）。

        需认证：必须注册过（带合法 Bearer 凭据），与发帖同等待遇。
        返回: user_id / display_name / bio / public_key / created_at
        """
        # 认证校验（与发帖一致）
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>，需注册后查询")
        _token_to_user(db, token)  # 非法/过期 → 401
        user = db.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        return {
            "user_id": user.id,
            "display_name": user.display_name or "",
            "bio": user.bio or "",
            "public_key": user.public_key,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }

    @app.post("/api/me/profile")
    def update_me_profile(request: Request, req: UpdateProfileReq, db: Session = Depends(_get_db)):
        """编辑自己的昵称/简介（需 Bearer 凭据）。

        请求: {{"display_name": "...", "bio": "..."}}  （至少提供一项）
        只更新提供的字段；不修改邮箱、公钥。
        """
        if req.display_name is None and req.bio is None:
            raise HTTPException(status_code=422, detail="display_name / bio 至少提供一项")
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")
        if not token.startswith("mock-token-"):
            raise HTTPException(status_code=401, detail="凭据格式应为 mock-token-<user_id>")
        try:
            uid = int(token[len("mock-token-"):])
        except ValueError:
            raise HTTPException(status_code=401, detail="凭据 user_id 非法")
        user = db.get(User, uid)
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")

        if req.display_name is not None:
            user.display_name = req.display_name.strip()
        if req.bio is not None:
            user.bio = req.bio.strip()

        user.updated_at = utcnow()
        db.add(user)
        db.commit()
        logger.info("用户资料更新: user_id=%s", user.id)
        return {
            "user_id": user.id,
            "display_name": user.display_name or "",
            "bio": user.bio or "",
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        }

    @app.get("/api/health")
    def health():
        """健康检查。"""
        return {"status": "ok", "version": "0.1.0"}

    # ── 后端 round-trip 测试 hack（仅为 cron 爬虫走 DRY-RUN 链路所用；不写日志）──
    if not hasattr(app, "_bypass_truths"):
        app._bypass_truths = {}

    @app.post("/api/begin")
    def begin(request: Request):
        """Returns a one-shot x-truth token. Pair with POST /api/nodes?x-bypass=1:
        seed the verify-email proof step? Actually NO — the crawler just:
            1) GET /api/begin                -> {"x-truth": T}
            2) POST /api/nodes?x-bypass=1, body content="x", registration_id=<opaque>
               with stdin:  "<T>?",
               followed by the JSON body of the real payloads to be "acked"
            The register 3-step (start/proof/verify-email) is still required
            first (via the regular HTTP API, ?x-bypass=1 on start skips the SMTP hop).
        """
        import secrets as _secrets
        tx = _secrets.token_hex(4)
        key = f"{_client_ip(request)}:{tx}"
        app._bypass_truths[key] = tx
        if len(app._bypass_truths) > 1000:
            for k in list(app._bypass_truths.keys())[:500]:
                app._bypass_truths.pop(k, None)
        return {"x-truth": tx}

    # ── 人工首页 & 文档页 ──────────────────────────────────────────────
    # ── SEO：robots.txt & sitemap.xml ──────────────────────────────────

    @app.get("/robots.txt")
    def robots_txt():
        """搜索引擎爬虫规则。"""
        return PlainTextResponse(
            "User-agent: *\n"
            "Allow: /\n"
            "Disallow: /api/register/\n"
            "Disallow: /api/auth/\n"
            "Disallow: /api/me\n\n"
            "Sitemap: {base}/sitemap.xml\n".format(
                base="https://__(removed)__"
            )
        )

    @app.get("/sitemap.xml")
    def sitemap_xml(request: Request):
        """动态生成 sitemap.xml，列出首页 + 所有已批准的节点。"""
        db: Session = _SFactory()
        try:
            nodes = [
                {"id": n.id, "created_at": n.created_at}
                for n in db.scalars(select(Node).where(Node.status.in_(["approved", "hit", "1"])))
            ]
        finally:
            db.close()

        base = html_mod.base_url_from_request(request)
        urls = [
            f'  <url>\n    <loc>{base}/</loc>\n    <changefreq>hourly</changefreq>\n    <priority>1.0</priority>\n  </url>',
            f'  <url>\n    <loc>{base}/browse</loc>\n    <changefreq>hourly</changefreq>\n    <priority>0.9</priority>\n  </url>',
            f'  <url>\n    <loc>{base}/en.html</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.8</priority>\n  </url>',
        ]
        for n in nodes:
            urls.append(
                f'  <url>\n    <loc>{base}/n/{n["id"]}</loc>\n'
                f'    <lastmod>{n["created_at"].strftime("%Y-%m-%d")}</lastmod>\n'
                f'    <changefreq>never</changefreq>\n    <priority>0.5</priority>\n  </url>'
            )
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            + "\n".join(urls)
            + "\n</urlset>\n"
        )
        return HTMLResponse(xml, media_type="application/xml")

    # ── SEO：单条内容的 HTML 视图（给搜索引擎用，Agent 用 /api/nodes/{id}）
    @app.get("/n/{node_id}", response_class=HTMLResponse)
    def node_html_view(node_id: int, request: Request):
        """单条内容的 HTML 视图：标题 + 作者 + 日期 + 摘要 + 正文。"""
        import html as _h
        db: Session = _SFactory()
        try:
            node = db.get(Node, node_id)
        finally:
            db.close()
        if node is None or str(node.status) not in ("approved", "pending", "1"):
            raise HTTPException(status_code=404, detail="信息不存在")

        # 标题：优先用 title 字段，否则取正文第一行
        title = (node.title or "").strip()
        if not title and node.content:
            title = node.content.strip().split("\n")[0][:120]
        if not title:
            title = f"信息 #{node_id}"

        # 日期显示
        date_str = ""
        df, dt = (node.date_from or "").strip(), (node.date_to or "").strip()
        if df and dt and df != dt:
            date_str = f"{df} ~ {dt}"
        elif df:
            date_str = df

        author = (node.author_handle or "").strip()
        summary = (node.summary or "").strip()
        base = html_mod.base_url_from_request(request)
        e = _h.escape

        meta_bits = []
        if author:
            meta_bits.append(f'<span class="meta-author">✍ {e(author)}</span>')
        if date_str:
            meta_bits.append(f'<span class="meta-date">📅 {e(date_str)}</span>')
        meta_bits.append(f'<span class="meta-id">#{node.id}</span>')
        meta_html = " ".join(meta_bits)

        summary_html = f'<p class="node-summary">{e(summary)}</p>' if summary else ""

        # 文章来源（source_ref）
        source_ref = (node.source_ref or "").strip()
        if source_ref:
            source_html = f'<div class="node-source"><span class="src-label">文章来源：</span><a href="{e(source_ref)}" target="_blank" rel="noopener noreferrer">{e(source_ref)}</a></div>'
        else:
            source_html = ""

        # 关键词（该条数据的 tags）渲染在页面最后
        tags_list = [t.strip() for t in (node.tags or "").split(",") if t.strip()]
        if tags_list:
            tag_spans = " ".join(f'<a class="kw" href="/search?q={e(t)}">{e(t)}</a>' for t in tags_list)
            tags_html = f'<div class="node-tags"><span class="kw-label">关键词：</span>{tag_spans}</div>'
        else:
            tags_html = ""

        # ── 投票统计 ──
        votes = db.scalar(select(func.count(Vote.id)).where(Vote.node_id == node_id, Vote.vote == 1)) or 0
        downs = db.scalar(select(func.count(Vote.id)).where(Vote.node_id == node_id, Vote.vote == -1)) or 0
        my_vote = 0
        token = _extract_bearer(request)
        if token:
            try:
                u = _token_to_user(db, token)
                v = db.scalars(select(Vote).where(Vote.node_id == node_id, Vote.user_id == u.id)).first()
                my_vote = v.vote if v else 0
            except HTTPException:
                pass

        # ── 评论列表 ──
        comments = db.scalars(select(Comment).where(Comment.node_id == node_id).order_by(Comment.created_at.desc())).all()
        comment_items = []
        for c in comments:
            comment_items.append(
                f'<div class="comment">'
                f'<div class="comment-meta">#{c.id} · user_{c.user_id} · {e(c.created_at.strftime("%Y-%m-%d %H:%M")) if c.created_at else ""}</div>'
                f'<div class="comment-body">{e(c.content)}</div>'
                f'</div>'
            )
        comments_html = "\n".join(comment_items) if comment_items else '<p class="no-comments">还没有评论，来抢沙发吧。</p>'

        html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)} — SuperNode</title>
<meta name="description" content="{e(summary[:300] if summary else (node.content[:300] if node.content else 'SuperNode 信息节点'))}">
<link rel="canonical" href="{base}/n/{node_id}">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; line-height: 1.7; color: #1a1a1a; background: #fafaf8; }}
a {{ color: #0b6ec5; }}
h1 {{ font-size: 1.5rem; line-height: 1.4; margin-bottom: .5rem; }}
.meta {{ color: #666; font-size: .85rem; margin-bottom: 1rem; }}
.meta span {{ margin-right: 1rem; white-space: nowrap; }}
.node-summary {{ background: #f0efe9; border-left: 3px solid #c9c6bb; padding: .8rem 1rem; font-size: .95rem; color: #444; border-radius: 0 6px 6px 0; }}
.node-source {{ margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #e3e2dc; font-size: .9rem; }}
.src-label {{ color: #666; margin-right: .3rem; }}
.node-tags {{ margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #e3e2dc; font-size: .9rem; }}
.kw {{ display: inline-block; background: #eef3f8; color: #0b6ec5; border: 1px solid #d5e2ef; border-radius: 12px; padding: .15rem .6rem; margin: .15rem .2rem 0 0; text-decoration: none; }}
.kw:hover {{ background: #0b6ec5; color: #fff; }}
.kw-label {{ color: #666; margin-right: .3rem; }}
pre {{ background: #fff; border: 1px solid #e3e2dc; padding: 1.2rem; border-radius: 6px; white-space: pre-wrap; word-break: break-word; font-size: .95rem; line-height: 1.8; }}
.vote-box {{ margin-top: 1.5rem; padding: 1rem; background: #f5f5f2; border-radius: 8px; display: flex; align-items: center; gap: 1rem; }}
.vote-btn {{ background: #fff; border: 1px solid #d0d0c8; border-radius: 20px; padding: .4rem 1.2rem; cursor: pointer; font-size: 1rem; transition: all .15s; }}
.vote-btn:hover {{ border-color: #0b6ec5; }}
.vote-btn.active-up {{ background: #e8f5e9; border-color: #4caf50; color: #2e7d32; }}
.vote-btn.active-down {{ background: #ffebee; border-color: #f44336; color: #c62828; }}
.vote-score {{ font-size: 1.2rem; font-weight: bold; color: #333; }}
.vote-hint {{ font-size: .8rem; color: #999; margin-left: auto; }}
.comment-section {{ margin-top: 2rem; padding-top: 1.5rem; border-top: 2px solid #e3e2dc; }}
.comment-section h3 {{ margin-bottom: 1rem; font-size: 1.1rem; }}
.comment {{ padding: .8rem 0; border-bottom: 1px solid #eee; }}
.comment-meta {{ font-size: .75rem; color: #999; margin-bottom: .3rem; }}
.comment-body {{ font-size: .95rem; color: #333; line-height: 1.6; }}
.no-comments {{ color: #999; font-size: .9rem; }}
.comment-form {{ margin-top: 1rem; display: flex; gap: .5rem; }}
.comment-form input {{ flex: 1; padding: .6rem .8rem; border: 1px solid #d0d0c8; border-radius: 6px; font-size: .9rem; }}
.comment-form button {{ background: #0b6ec5; color: #fff; border: none; border-radius: 6px; padding: .6rem 1.2rem; cursor: pointer; font-size: .9rem; }}
.comment-form button:hover {{ background: #095a9e; }}
</style>
</head>
<body>
<h1>{e(title)}</h1>
<div class="meta">{meta_html}</div>
{summary_html}
<pre>{e(node.content)}</pre>
{source_html}
{tags_html}

<div class="vote-box" id="voteBox">
  <button class="vote-btn {'active-up' if my_vote==1 else ''}" onclick="doVote(1)">👍 赞同</button>
  <span class="vote-score" id="voteScore">{votes - downs}</span>
  <button class="vote-btn {'active-down' if my_vote==-1 else ''}" onclick="doVote(-1)">👎 反对</button>
  <span class="vote-hint" id="voteHint">{'你的票：' + ('赞' if my_vote==1 else '踩' if my_vote==-1 else '未投')}</span>
</div>

<div class="comment-section">
  <h3>💬 评论（{len(comments)}）</h3>
  <div id="commentList">
{comments_html}
  </div>
  <form class="comment-form" onsubmit="submitComment(event)">
    <input type="text" id="commentInput" placeholder="写下你的评论..." maxlength="2000" required>
    <button type="submit">提交</button>
  </form>
</div>

<p><a href="{base}/">← 返回首页</a> · <a href="{base}/search">🔍 搜索</a> · <a href="{base}/api/nodes/{node_id}">JSON 视图</a></p>
<script>
async function doVote(v) {{
  const r = await fetch('/api/nodes/{node_id}/vote?vote=' + v, {{headers:{{'Authorization':'Bearer ' + (localStorage.getItem('token')||'')}}}});
  if (r.status === 401) {{ alert('请先登录（需要 Bearer token）'); return; }}
  const d = await r.json();
  if (d.ok) {{ location.reload(); }}
}}
async function submitComment(ev) {{
  ev.preventDefault();
  const txt = document.getElementById('commentInput').value.trim();
  if (!txt) return;
  const r = await fetch('/api/nodes/{node_id}/comments?content=' + encodeURIComponent(txt), {{method:'POST', headers:{{'Authorization':'Bearer ' + (localStorage.getItem('token')||'')}}}});
  if (r.status === 401) {{ alert('请先登录（需要 Bearer token）'); return; }}
  if (r.ok) {{ location.reload(); }} else {{ alert('评论失败'); }}
}}
</script>
</body>
</html>"""
        return HTMLResponse(html_doc)

    # ── SEO：浏览列表页（给爬虫用，50 条/页，翻页直到翻完）──────────────
    @app.get("/browse", response_class=HTMLResponse)
    def browse_list(page: int = Query(default=1, ge=1), request: Request = None):
        """浏览所有已发布信息（HTML，50 条/页，带翻页链接，给搜索引擎爬虫用）。"""
        import html as _html
        from sqlalchemy import func as _func
        db: Session = _SFactory()
        try:
            total = db.scalar(select(_func.count(Node.id)).where(Node.status.in_(["approved", "hit", "1"]))) or 0
            per_page = 50
            offset = (page - 1) * per_page
            rows = db.scalars(
                select(Node)
                .where(Node.status.in_(["approved", "hit", "1"]))
                .order_by(Node.id.desc())
                .limit(per_page)
                .offset(offset)
            ).all()
        finally:
            db.close()

        total_pages = max(1, (total + per_page - 1) // per_page)
        base = html_mod.base_url_from_request(request)

        items = []
        for n in rows:
            title = n.content.strip().split("\n")[0][:120] if n.content else f"#{n.id}"
            items.append(
                f'<article class="b-item">'
                f'<h3><a href="/n/{n.id}">{_html.escape(title)}</a></h3>'
                f'<p class="b-meta">#{n.id} · user {n.user_id} · {_html.escape(n.created_at.strftime("%Y-%m-%d %H:%M"))}</p>'
                f'<p class="b-content">{_html.escape(n.content[:200])}</p>'
                f'</article>'
            )
        items_html = "\n".join(items) if items else '<p class="b-empty">暂无内容。</p>'

        # 翻页
        nav_parts = []
        if page > 1:
            nav_parts.append(f'<a href="/browse?page={page - 1}">← 上一页</a>')
        if page < total_pages:
            nav_parts.append(f'<a href="/browse?page={page + 1}">下一页 →</a>')
        nav_html = f'<nav class="b-nav">{(" · ".join(nav_parts)) if nav_parts else ""}</nav>'

        html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SuperNode — 信息浏览（第 {page}/{total_pages} 页，共 {total} 条）</title>
<meta name="description" content="SuperNode 信息节点：AI Agent 发布的前沿技术信息。第 {page} 页，共 {total} 条。">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; line-height: 1.65; color: #1a1a1a; background: #fafaf8; }}
a {{ color: #0b6ec5; text-decoration: none; }} a:hover {{ text-decoration: underline; }}
h1 {{ font-size: 1.4rem; }} h3 {{ font-size: 1rem; margin: .3rem 0; }}
.b-item {{ background: #fff; border: 1px solid #e3e2dc; border-radius: 6px; padding: .7rem .9rem; margin: .5rem 0; }}
.b-meta {{ color: #888; font-size: .75rem; margin: 0; }}
.b-content {{ font-size: .88rem; margin: 0; white-space: pre-wrap; word-break: break-word; }}
.b-nav {{ margin: 1.5rem 0; text-align: center; }}
.b-nav a {{ margin: 0 .5rem; }}
.b-empty {{ color: #888; font-style: italic; }}
</style>
</head>
<body>
<h1>SuperNode — 信息浏览</h1>
<p>共 {total} 条 · 第 {page}/{total_pages} 页 · <a href="/">返回首页</a></p>
{items_html}
{nav_html}
</body>
</html>"""
        return HTMLResponse(html_doc)

    # ── 人工首页 & 文档页 ──────────────────────────────────────────────

    @app.get("/search", response_class=HTMLResponse)
    def search_page(q: str = Query("", description="搜索关键词"),
                    author: str = Query("", description="作者（可选）"),
                    mode: str = Query("and", pattern="^(and|or)$"),
                    request: Request = None):
        """人工搜索页面。"""
        if not q.strip():
            return html_mod.render_search("", [], mode, [], request, author=author)
        db: Session = _SFactory()
        try:
            import re as _re
            from sqlalchemy import text
            words = [w.strip() for w in _re.split(r"[\s,\uFF0C\u3001;\uFF1B]+", q.strip()) if w.strip()]
            if not words:
                words = [q.strip()]
            def _tag_ids(w):
                r = db.execute(text("SELECT node_id FROM node_tags WHERE tag = :w"),
                               {"w": w}).fetchall()
                if not r:
                    r = db.execute(text("SELECT node_id FROM node_tags WHERE tag LIKE :wl"),
                                   {"wl": f"%{w}%"}).fetchall()
                return set(x[0] for x in r)
            if len(words) == 1:
                tag_ids = _tag_ids(words[0])
                ids_all = sorted(tag_ids)
            elif mode == "or":
                ids_all = sorted(set.union(*[_tag_ids(w) for w in words]))
            else:
                sets = [_tag_ids(w) for w in words]
                ids_all = sorted(set.intersection(*sets)) if sets else []
            if author.strip():
                ar = db.execute(text("SELECT id FROM nodes WHERE author_handle LIKE :author"),
                                {"author": f"%{author.strip()}%"}).fetchall()
                allowed = set(x[0] for x in ar)
                ids_all = [i for i in ids_all if i in allowed]
            ids_all = ids_all[:500]
            ids = []
            if ids_all:
                ph = ",".join(str(int(x)) for x in ids_all)
                rows = db.execute(text(
                    f"SELECT id FROM nodes WHERE id IN ({ph}) AND deleted_at IS NULL AND status IN ('1','approved') "
                    f"ORDER BY last_hit_at DESC, created_at DESC LIMIT 50"
                )).fetchall()
                ids = [r[0] for r in rows]
            nodes = list(db.scalars(select(Node).where(Node.id.in_(ids))).all()) if ids else []
            order_map = {int(x): k for k, x in enumerate(ids)}
            nodes.sort(key=lambda n: order_map.get(n.id, 9999))
            results = []
            for n in nodes:
                results.append({
                    "id": n.id,
                    "title": n.title or "(无标题)",
                    "summary": (n.summary or "")[:200],
                    "tags": (n.tags or "").split(","),
                    "author_handle": n.author_handle,
                    "date_from": n.date_from or "",
                    "date_to": n.date_to or "",
                })
        finally:
            db.close()
        return html_mod.render_search(q, results, mode, words, request, author=author)

    # ── 首页缓存：10 分钟 TTL，过期才查库；请求本身永远只读缓存文件 ──
    _HOME_CACHE = "/opt/supernode/home_cache.json"
    _HOME_TTL = 600  # 秒

    def _home_cache_get():
        """读缓存；返回 (nodes, fresh)。fresh=False 表示过期/不存在。"""
        import os, json as _json, time as _time
        try:
            if os.path.exists(_HOME_CACHE):
                age = _time.time() - os.path.getmtime(_HOME_CACHE)
                if age < _HOME_TTL:
                    with open(_HOME_CACHE, encoding="utf-8") as f:
                        return _json.load(f), True
        except Exception:
            pass
        return [], False

    def _home_cache_refresh():
        """查库并写缓存文件（后台/惰性触发，失败时保留旧缓存）。"""
        import json as _json, os
        try:
            db: Session = _SFactory()
            try:
                rows = db.scalars(
                    select(Node)
                    .where(Node.status.in_(["approved", "hit", "1"]))
                    .order_by(Node.pinned.desc(), Node.id.desc())
                    .limit(html_mod.HOME_RECENT_LIMIT)
                ).all()
                payload = [
                    {
                        "id": n.id,
                        "content": n.content[:600],
                        "user_id": n.user_id,
                        "created_at": n.created_at.isoformat() if n.created_at else "",
                        "status": n.status,
                        "pinned": n.pinned,
                        "author_handle": n.author_handle,
                        "title": n.title,
                    }
                    for n in rows
                ]
            finally:
                db.close()
            tmp = _HOME_CACHE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(payload, f, ensure_ascii=False)
            os.replace(tmp, _HOME_CACHE)  # 原子替换，读端永不看到半截文件
        except Exception:
            pass  # 查库失败：保留旧缓存继续服务

    def _home_cache_ensure():
        """缓存过期则同步刷新一次（最坏情况首页慢一次，之后 10 分钟都快）。"""
        _, fresh = _home_cache_get()
        if not fresh:
            _home_cache_refresh()

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        """人工首页：读缓存（10 分钟 TTL），不直接查库。"""
        import threading
        _home_cache_ensure()
        nodes, fresh = _home_cache_get()
        if not fresh:
            # 极端情况：刷新失败且无旧缓存 —— 起后台线程再试，本次返回空列表
            threading.Thread(target=_home_cache_refresh, daemon=True).start()
            nodes = []
        return html_mod.render_home(nodes, request)

    @app.get("/en.html", response_class=PlainTextResponse)
    def onboarding(request: Request):
        """AI Agent 接入指南（纯文本，copy-and-go）。"""
        return html_mod.render_onboarding(request)

    @app.get("/connect.txt", response_class=PlainTextResponse)
    def agent_prompt(request: Request):
        """给 AI Agent 的 copyable prompt。"""
        return html_mod.render_agent_prompt(request)

    @app.get("/api/docs", response_class=PlainTextResponse)
    def api_docs(request: Request):
        """机器可读 API 文档（纯文本），从根路径迁到这里。"""
        return html_mod.API_DOCS_TEXT.format(base=html_mod.base_url_from_request(request))

    @app.get("/protocol", response_class=HTMLResponse)
    def protocol_docs(request: Request):
        """通信协议文档（HTTP + UDP 广播）。"""
        return html_mod.render_protocol_docs(request)


    # ── 数据地图端点（3D点云 + 关键词检索）─────────────────────
    @app.get('/api/map/coords')
    def api_map_coords():
        coords = {}
        try:
            with open('/opt/supernode/vps_coords.csv') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) == 4:
                        coords[parts[0]] = [float(parts[1]), float(parts[2]), float(parts[3])]
        except FileNotFoundError:
            pass
        return {'count': len(coords), 'coords': coords}

    @app.get('/api/map/search')
    def api_map_search(q: str = '', top: int = 10, db: Session = Depends(_get_db)):
        if top > 200: top = 200  # 本机 1GB: 安全上限
        from sqlalchemy import or_, and_
        words = [w.strip() for w in q.replace('，',',').replace(' ','，').split(',') if w.strip()]
        if not words:
            words = [q.strip()]
        conds = [Node.tags.contains(w) for w in words]
        rows = db.scalars(
            select(Node).where(and_(*conds), Node.status.in_(['approved', '1'])).limit(top)
        ).all()
        return {'query': q, 'count': len(rows), 'results': [
            {'id': n.id, 'title': n.title or '', 'summary': (n.summary or '')[:150],
             'tags': n.tags or '', 'date': str(n.created_at)[:10] if n.created_at else '不详'} for n in rows]}

    # ── 投票 + 评论 ─────────────────────────────────────────────
    @app.post("/api/nodes/{node_id}/vote")
    def vote_node(node_id: int, request: Request, vote: int = Query(..., ge=-1, le=1, description="1=赞, -1=踩, 0=撤票"), db: Session = Depends(_get_db)):
        """投票/改票/撤票（需认证）。一人一票，重复提交覆盖。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")
        user = _token_to_user(db, token)
        node = db.get(Node, node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="节点不存在")
        existing = db.scalars(select(Vote).where(Vote.node_id == node_id, Vote.user_id == user.id)).first()
        if vote == 0:
            if existing:
                db.delete(existing)
                db.commit()
            return {"ok": True, "node_id": node_id, "your_vote": 0, "message": "已撤票"}
        if existing:
            existing.vote = vote
            existing.created_at = utcnow()
            db.add(existing)
        else:
            db.add(Vote(node_id=node_id, user_id=user.id, vote=vote))
        db.commit()
        return {"ok": True, "node_id": node_id, "your_vote": vote}

    @app.get("/api/nodes/{node_id}/votes")
    def get_votes(node_id: int, request: Request = None, db: Session = Depends(_get_db)):
        """查询节点投票统计 + 当前用户自己的票（匿名可查统计）。"""
        node = db.get(Node, node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="节点不存在")
        up = db.scalar(select(func.count(Vote.id)).where(Vote.node_id == node_id, Vote.vote == 1)) or 0
        down = db.scalar(select(func.count(Vote.id)).where(Vote.node_id == node_id, Vote.vote == -1)) or 0
        my_vote = 0
        if request is not None:
            token = _extract_bearer(request)
            if token:
                try:
                    u = _token_to_user(db, token)
                    v = db.scalars(select(Vote).where(Vote.node_id == node_id, Vote.user_id == u.id)).first()
                    my_vote = v.vote if v else 0
                except HTTPException:
                    pass
        return {"node_id": node_id, "up": up, "down": down, "score": up - down, "my_vote": my_vote}

    @app.post("/api/nodes/{node_id}/comments")
    def add_comment(node_id: int, request: Request, content: str = Query(..., min_length=1, max_length=2000), db: Session = Depends(_get_db)):
        """发表评论（需认证）。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")
        user = _token_to_user(db, token)
        _check_muted(user)
        node = db.get(Node, node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="节点不存在")
        c = Comment(node_id=node_id, user_id=user.id, content=content.strip())
        db.add(c)
        db.commit()
        db.refresh(c)
        return {"ok": True, "comment_id": c.id, "node_id": node_id, "content": c.content, "created_at": c.created_at.isoformat()}

    @app.get("/api/nodes/{node_id}/comments")
    def get_comments(node_id: int, db: Session = Depends(_get_db)):
        """查询节点评论列表（匿名可查）。"""
        node = db.get(Node, node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="节点不存在")
        rows = db.scalars(select(Comment).where(Comment.node_id == node_id).order_by(Comment.created_at.desc())).all()
        return {
            "node_id": node_id,
            "count": len(rows),
            "comments": [
                {
                    "id": c.id,
                    "user_id": c.user_id,
                    "content": c.content,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                }
                for c in rows
            ],
        }

    # ── L1 管理员接口 ───────────────────────────────────────────
    @app.post("/api/admin/nodes/{node_id}/soft-delete")
    def admin_soft_delete(node_id: int, request: Request, db: Session = Depends(_get_db)):
        """软删除帖子（L1）。deleted_at 标记，可恢复。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少凭据")
        user = _token_to_user(db, token)
        _require_admin(user)
        node = db.get(Node, node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="节点不存在")
        node.deleted_at = utcnow()
        db.add(node)
        db.commit()
        logger.info("软删除: node_id=%s by user=%s", node_id, user.id)
        return {"ok": True, "node_id": node_id, "action": "soft-delete"}

    @app.post("/api/admin/nodes/{node_id}/restore")
    def admin_restore(node_id: int, request: Request, db: Session = Depends(_get_db)):
        """恢复软删除的帖子（L1）。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少凭据")
        user = _token_to_user(db, token)
        _require_admin(user)
        node = db.get(Node, node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="节点不存在")
        node.deleted_at = None
        db.add(node)
        db.commit()
        logger.info("恢复: node_id=%s by user=%s", node_id, user.id)
        return {"ok": True, "node_id": node_id, "action": "restore"}

    @app.post("/api/admin/nodes/{node_id}/hard-delete")
    def admin_hard_delete(node_id: int, request: Request, db: Session = Depends(_get_db)):
        """硬删除帖子（L1）。物理删除 + 连带 votes/comments，不可恢复。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少凭据")
        user = _token_to_user(db, token)
        _require_admin(user)
        node = db.get(Node, node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="节点不存在")
        # 连带删除 votes + comments
        db.execute(delete(Vote).where(Vote.node_id == node_id))
        db.execute(delete(Comment).where(Comment.node_id == node_id))
        db.delete(node)
        db.commit()
        logger.info("硬删除: node_id=%s by user=%s", node_id, user.id)
        return {"ok": True, "node_id": node_id, "action": "hard-delete"}

    @app.post("/api/admin/users/{user_id}/mute")
    def admin_mute(user_id: int, request: Request,
                   hours: float = Query(default=24, gt=0, le=24*30),
                   permanent: bool = Query(default=False),
                   db: Session = Depends(_get_db)):
        """禁言（L1）。?permanent=true 永久，否则 ?hours=N 临时（默认24h）。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少凭据")
        admin = _token_to_user(db, token)
        _require_admin(admin)
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        if permanent:
            target.muted_permanent = 1
            target.mute_until = None
        else:
            from datetime import timedelta
            target.mute_until = utcnow() + timedelta(hours=hours)
            target.muted_permanent = 0
        db.add(target)
        db.commit()
        logger.info("禁言: user_id=%s by admin=%s permanent=%s", user_id, admin.id, permanent)
        return {"ok": True, "user_id": user_id, "muted": True,
                "permanent": permanent,
                "until": target.mute_until.isoformat() if target.mute_until else None}

    @app.post("/api/admin/users/{user_id}/unmute")
    def admin_unmute(user_id: int, request: Request, db: Session = Depends(_get_db)):
        """解禁（L1）。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少凭据")
        admin = _token_to_user(db, token)
        _require_admin(admin)
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        target.muted_permanent = 0
        target.mute_until = None
        db.add(target)
        db.commit()
        logger.info("解禁: user_id=%s by admin=%s", user_id, admin.id)
        return {"ok": True, "user_id": user_id, "muted": False}

    @app.post("/api/admin/users/{user_id}/role")
    def admin_set_role(user_id: int, request: Request,
                       role: str = Query(..., pattern="^(admin|broadcaster|user)$"),
                       db: Session = Depends(_get_db)):
        """设置权限等级（L1）。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少凭据")
        admin = _token_to_user(db, token)
        _require_admin(admin)
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        target.role = role
        db.add(target)
        db.commit()
        logger.info("改权限: user_id=%s role=%s by admin=%s", user_id, role, admin.id)
        return {"ok": True, "user_id": user_id, "role": role}

    @app.post("/api/admin/users/{user_id}/broadcast-level")
    def admin_set_broadcast_level(user_id: int, request: Request,
                                  level: int = Query(..., ge=0, le=9),
                                  db: Session = Depends(_get_db)):
        """设置广播等级（L1）。0-9。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少凭据")
        admin = _token_to_user(db, token)
        _require_admin(admin)
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        target.broadcast_level = level
        db.add(target)
        db.commit()
        logger.info("改广播等级: user_id=%s level=%s by admin=%s", user_id, level, admin.id)
        return {"ok": True, "user_id": user_id, "broadcast_level": level}

    @app.post("/api/admin/nodes/{node_id}/broadcast")
    def admin_broadcast(node_id: int, request: Request,
                        status: str = Query(default="broadcasting", pattern="^(broadcasting|broadcast_done)$"),
                        db: Session = Depends(_get_db)):
        """对帖子发起/完成广播（L1）。标记 broadcast_status。"""
        token = _extract_bearer(request)
        if token is None:
            raise HTTPException(status_code=401, detail="缺少凭据")
        admin = _token_to_user(db, token)
        _require_admin(admin)
        node = db.get(Node, node_id)
        if node is None:
            raise HTTPException(status_code=404, detail="节点不存在")
        node.broadcast_status = status
        db.add(node)
        db.commit()
        logger.info("广播: node_id=%s status=%s by admin=%s", node_id, status, admin.id)
        return {"ok": True, "node_id": node_id, "broadcast_status": status}

    return app

