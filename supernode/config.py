"""SuperNode 配置。

开发环境默认值即可运行；生产环境通过环境变量覆盖。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    """应用配置。所有时间单位均为秒。"""

    # 数据库
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "SUPERNODE_DATABASE_URL", "sqlite:///./supernode.db"
        )
    )

    # 服务
    host: str = field(default_factory=lambda: os.environ.get("SUPERNODE_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.environ.get("SUPERNODE_PORT", "8000")))

    # Challenge / 验证码有效期
    registration_challenge_ttl: int = 300   # 注册 challenge 有效期 5 分钟
    auth_challenge_ttl: int = 300           # 认证 challenge 有效期 5 分钟
    email_code_ttl: int = 900               # 邮箱验证码有效期 15 分钟

    # 邮箱验证码
    email_code_length: int = 6              # 6 位数字验证码
    email_code_max_attempts: int = 5        # 最大错误尝试次数

    # Token
    token_ttl: int = 86400                  # 24 小时
    token_bytes: int = 32                   # 256 bit 随机 token

    # 节点内容
    node_content_max_length: int = 10000    # 单条信息最大字符数

    # 邮箱服务
    # 开发模式: "console"（打印到日志，不实际发信）
    # 生产模式: "smtp"（需要配置 SMTP 相关项）
    email_backend: str = field(default_factory=lambda: os.environ.get("SUPERNODE_EMAIL_BACKEND", "console"))
    smtp_host: str = field(default_factory=lambda: os.environ.get("SUPERNODE_SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: int(os.environ.get("SUPERNODE_SMTP_PORT", "587")))
    smtp_user: str = field(default_factory=lambda: os.environ.get("SUPERNODE_SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.environ.get("SUPERNODE_SMTP_PASSWORD", ""))
    email_from: str = field(default_factory=lambda: os.environ.get("SUPERNODE_EMAIL_FROM", "supernode@localhost"))


def get_settings() -> Settings:
    """构造配置实例。"""
    return Settings()
