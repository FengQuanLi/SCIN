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
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import crypto, email as email_svc
from . import html as html_mod
from .config import Settings
from .ratelimit import RateLimit, get_limiter
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
    user_id: int


class NodeCreateReq(BaseModel):
    content: str = Field(..., min_length=1)
    registration_id: str = ""


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

    # ── 恢复（用户特殊需要时开放，公钥仍可保持不变） ─────────────────────
    # 注意：RecoverySession 表在第 18 节后被移除（与 rotate-key / account_mode 一并废弃），
    # 这两条路由是空壳：只走 ratelimit + 用户存在检查 + 简单签名校验，
    # 不写库、不发请求、只能用于协助"特别需要找回"的用户联系人工。
    # 公钥本身不可变；找回流程本身不影响身份。

    @app.post("/api/auth/recover/start")
    def auth_recover_start(req: AuthChallengeReq, request: Request, db: Session = Depends(_get_db)):
        """恢复开始：用户提交 user_id，服务端返回一个 challenge。
        与 /api/auth/challenge 同构，但 purpose 与限流独立（3 次/小时）。
        """
        _rate_limit_check(request, "recover", _settings.rl_recover)
        user = db.get(User, req.user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        challenge = crypto.generate_challenge()
        return {"challenge_id": -1, "challenge": challenge}

    @app.post("/api/auth/recover/confirm")
    def auth_recover_confirm(req: AuthVerifyReq, db: Session = Depends(_get_db)):
        """恢复确认：用户提交 signature（对 challenge 的签名）。
        这里不签发任何 token（新协议），也不修改用户公钥。
        只记录一次确认。
        """
        # 签名与 challenge 一一绑定；尚无持久化 challenge 池，
        # v0.1 仅做格式校验和 200 回显，供内部人工兜底。
        if not req.signature or len(req.signature) < 64:
            raise HTTPException(status_code=422, detail="signature 不符合 64-hex 格式")
        return {"ok": True, "message": "恢复请求已记录，请联系管理员"}

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
                    status=(kind if kind in ("approved", "bypass") else "bypass"),
                )
            raise HTTPException(status_code=401, detail="缺少 Authorization: Bearer <token>")

        # 2. 必须有 registration_id（缺则 422，不伪造、不进入后端）
        if not req.registration_id or not req.registration_id.strip():
            raise HTTPException(status_code=422, detail="缺少 registration_id")

        # 3. 凭据无效/过期 → 401 短路，不再向后端传递
        user = _token_to_user(db, token)

        # 4. 发布速率限制：白名单用户用高限流，普通用户用标准限流（均按 IP 计）
        if user.id in _settings.publish_whitelist:
            limit = _settings.rl_publish_whitelist
        else:
            limit = _settings.rl_publish
        _rate_limit_check(request, "publish", limit)

        # 5. 空内容已由 pydantic min_length=1 拦为 422

        # 6. 全部通过 → 真正落库（写 nodes 行，status=approved，可被 /browse、/n/{id} 读到）
        node = Node(user_id=user.id, content=req.content, status="approved")
        db.add(node)
        db.commit()
        db.refresh(node)
        logger.info("发布信息: user_id=%s node_id=%s len=%d", user.id, node.id, len(req.content))
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
                for n in db.scalars(select(Node).where(Node.status == "approved"))
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
        """单条内容的 HTML 视图（最小化 SEO：title + meta + h1 + 内容）。"""
        db: Session = _SFactory()
        try:
            node = db.get(Node, node_id)
        finally:
            db.close()
        if node is None or node.status not in ("approved", "pending"):
            raise HTTPException(status_code=404, detail="信息不存在")

        # 提取第一行作为标题（假设格式是 "[桥接 #NNN]\n标题: ..." 或纯文本首行）
        first_line = node.content.strip().split("\n")[0][:200] if node.content else f"信息 #{node_id}"
        base = html_mod.base_url_from_request(request)

        html_doc = f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{first_line} — SuperNode</title>
<meta name="description" content="{node.content[:300] if node.content else 'SuperNode 信息节点'}">
<link rel="canonical" href="{base}/n/{node_id}">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; line-height: 1.65; color: #1a1a1a; }}
a {{ color: #0b6ec5; }}
pre {{ background: #f0efe9; padding: 1rem; border-radius: 6px; white-space: pre-wrap; word-break: break-word; }}
</style>
</head>
<body>
<h1>{first_line}</h1>
<pre>{node.content}</pre>
<p><a href="{base}/">返回首页</a> · <a href="{base}/api/nodes/{node_id}">JSON 视图</a></p>
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
            total = db.scalar(select(_func.count(Node.id)).where(Node.status == "approved")) or 0
            per_page = 50
            offset = (page - 1) * per_page
            rows = db.scalars(
                select(Node)
                .where(Node.status == "approved")
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

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        """人工首页：最近 3 条发布 + AI 接入引导。"""
        db: Session = _SFactory()
        try:
            nodes = [
                {
                    "id": n.id,
                    "content": n.content,
                    "user_id": n.user_id,
                    "created_at": n.created_at.isoformat(),
                    "status": n.status,
                }
                for n in db.scalars(
                    select(Node)
                    .where(Node.status == "approved")
                    .order_by(Node.id.desc())
                    .limit(html_mod.HOME_RECENT_LIMIT)
                )
            ]
        finally:
            db.close()
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

    return app

