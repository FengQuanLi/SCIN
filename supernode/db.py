"""SuperNode 数据库模型与连接。

使用 SQLAlchemy 2.x，支持 SQLite（开发）/ MariaDB（生产）双栈。

表结构：
    users, registration_sessions, auth_challenges, access_tokens,
    nodes（知识库文章表，扁平结构）, word_coords（词→3维坐标表）
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Float,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)
from .config import Settings


def utcnow() -> datetime:
    """当前 UTC 时间（naive，SQLite 友好）。"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_token(token: str) -> str:
    """Token 安全哈希。数据库只存哈希，不存明文。"""
    return hashlib.sha256(token.encode()).hexdigest()


def hash_email_code(code: str) -> str:
    """邮箱验证码哈希（加盐，防离线爆破）。"""
    salt = secrets.token_hex(8)
    digest = hashlib.sha256((salt + code).encode()).hexdigest()
    return f"{salt}${digest}"


def verify_email_code(stored: str, code: str) -> bool:
    """验证邮箱验证码。"""
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hashlib.sha256((salt + code).encode()).hexdigest() == stored.split("$", 1)[1]


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    public_key: Mapped[str] = mapped_column(String(64), nullable=False)  # 32 bytes hex
    display_name: Mapped[str] = mapped_column(String(80), nullable=False, default="")  # 昵称
    bio: Mapped[str] = mapped_column(String(500), nullable=False, default="")  # 简介
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="user")  # admin/broadcaster/user
    broadcast_level: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)  # 0-9
    mute_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)  # 临时禁言到期
    muted_permanent: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)  # 永久禁言
    account_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="recoverable")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    nodes: Mapped[list["Node"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class RegistrationSession(Base):
    __tablename__ = "registration_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # registration_id
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    public_key: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    bio: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    challenge: Mapped[str] = mapped_column(String(64), nullable=False)
    challenge_expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    challenge_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    challenge_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    email_code_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    email_code_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    email_code_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    email_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    challenge: Mapped[str] = mapped_column(String(64), nullable=False)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, default="auth")
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class AccessToken(Base):
    __tablename__ = "access_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class Node(Base):
    """知识库文章/知识条目（扁平结构，无 domain / belongs_to）。

    对应《SCIN知识库技术实现方案 v0.2》第 4.1 节，19 字段。
    """

    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, default=0, index=True)

    # ── 必填（发布方提供）──
    title: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    content: Mapped[str] = mapped_column(Text, nullable=False)

    # ── 服务端计算 ──
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    char_count: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)

    # ── 推荐可空（渐进式完善）──
    summary: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    tags: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    source_ref: Mapped[str] = mapped_column(Text, nullable=False, default="")
    doc_type: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)  # 0=论文 1=文章 2=代码 3=FAQ 4=笔记
    lang: Mapped[str] = mapped_column(String(3), nullable=False, default="mix")
    author_handle: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    date_from: Mapped[str] = mapped_column(String(11), nullable=False, default="")
    date_to: Mapped[str] = mapped_column(String(11), nullable=False, default="")
    currency: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=9)  # 9=未评估
    pinned: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)  # 1=首页置顶
    broadcast_status: Mapped[str] = mapped_column(String(20), nullable=False, default="normal")  # normal/broadcasting/broadcast_done

    # ── 状态 ──
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="approved")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # ── 命中统计 ──
    last_hit_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    user: Mapped["User"] = relationship(back_populates="nodes")


class Vote(Base):
    """投票：用户对某节点的赞同/反对（一人一票，可改票）。"""

    __tablename__ = "votes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    vote: Mapped[int] = mapped_column(SmallInteger, nullable=False)  # 1=赞, -1=踩
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        UniqueConstraint("node_id", "user_id", name="uq_node_user"),
    )


class Comment(Base):
    """评论：用户对某节点的评论。"""

    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(String(2000), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class WordCoord(Base):
    """词 → 3 维坐标（PCA 降维结果，离线生成，供语义扩展搜索用）。

    对应《SCIN知识库技术实现方案 v0.2》第 4.2 节。
    """

    __tablename__ = "word_coords"

    word: Mapped[str] = mapped_column(String(100), primary_key=True)
    x: Mapped[float] = mapped_column(Float, nullable=False)
    y: Mapped[float] = mapped_column(Float, nullable=False)
    z: Mapped[float] = mapped_column(Float, nullable=False)
    freq: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


def create_db_engine(settings: Settings):
    """创建 SQLAlchemy engine。"""
    return create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
        echo=False,
    )


def create_session_factory(engine):
    """创建 session factory。"""
    return sessionmaker(bind=engine, expire_on_commit=False)


def init_db(engine):
    """建表。"""
    Base.metadata.create_all(engine)
