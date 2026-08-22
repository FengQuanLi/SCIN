"""SuperNode 数据库模型与连接。

使用 SQLAlchemy 2.x + SQLite。

表结构（对应设计文档第 15 节）：
    users, registration_sessions, auth_challenges, access_tokens, nodes
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
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
    account_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="recoverable")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    nodes: Mapped[list["Node"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class RegistrationSession(Base):
    __tablename__ = "registration_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # registration_id
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    public_key: Mapped[str] = mapped_column(String(64), nullable=False)
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
    """一条纯文本信息。"""

    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="approved")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    user: Mapped["User"] = relationship(back_populates="nodes")


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
