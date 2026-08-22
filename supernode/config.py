"""SuperNode 配置。

开发环境默认值即可运行；生产环境通过环境变量或 .env 文件覆盖。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_env_file():
    """加载项目根目录的 .env 文件（如果存在）。

    不依赖 python-dotenv，简单的 KEY=VALUE 解析。
    已存在的环境变量不会被覆盖。
    """
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key and key not in os.environ:
            os.environ[key] = value


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

    # 速率限制（IP 级，滑动窗口）
    rl_auth_challenge: tuple[int, int] = (10, 60)       # 10 次/分钟
    rl_register_start: tuple[int, int] = (5, 3600)      # 5 次/小时
    rl_publish: tuple[int, int] = (60, 3600)            # 60 次/小时
    rl_recover: tuple[int, int] = (3, 3600)             # 恢复 3 次/小时

    # 过期数据清理
    cleanup_interval_hours: int = 6                   # 每 6 小时清理一次过期记录

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
    """构造配置实例。自动加载 .env 文件（如果存在）。"""
    _load_env_file()
    return Settings()
