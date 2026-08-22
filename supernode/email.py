"""SuperNode 邮件服务。

开发模式（email_backend = "console"）：
    验证码打印到标准输出，不实际发送。开发调试用。

生产模式（email_backend = "smtp"）：
    通过 SMTP 发送。
"""

from __future__ import annotations

import logging
import secrets
import smtplib
from dataclasses import dataclass
from email.mime.text import MIMEText

logger = logging.getLogger("supernode.email")


@dataclass
class EmailResult:
    """发送结果。"""
    ok: bool
    code: str
    error: str = ""


def generate_email_code(length: int) -> str:
    """生成纯数字一次性验证码。"""
    return "".join(secrets.choice("0123456789") for _ in range(length))


def send_verification_code(
    settings,
    to_email: str,
    code: str,
) -> EmailResult:
    """发送邮箱验证码。

    根据 settings.email_backend 选择 console 或 smtp。
    """
    if settings.email_backend == "console":
        return _send_console(to_email, code)
    elif settings.email_backend == "smtp":
        return _send_smtp(settings, to_email, code)
    else:
        return EmailResult(ok=False, code=code, error=f"未知 email_backend: {settings.email_backend}")


def _send_console(to_email: str, code: str) -> EmailResult:
    """开发模式：打印验证码到日志。"""
    logger.info("[console-email] To: %s | 验证码: %s", to_email, code)
    print(f"\n[SuperNode 开发模式] 发往 {to_email} 的验证码: {code}\n", flush=True)
    return EmailResult(ok=True, code=code)


def _send_smtp(settings, to_email: str, code: str) -> EmailResult:
    """生产模式：SMTP 发送。

    端口 465 → SMTP_SSL（直接 TLS 包裹）
    端口 587 → SMTP + STARTTLS
    """
    subject = "SuperNode 注册验证码"
    body = f"您的 SuperNode 注册验证码：\n\n{code}\n\n验证码 {settings.email_code_ttl // 60} 分钟内有效，请勿泄露给他人。"
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = settings.email_from
    msg["To"] = to_email

    try:
        if settings.smtp_port == 465:
            # SMTP over SSL（Gmail 465 用这种）
            with smtplib.SMTP_SSL(settings.smtp_host, 465, timeout=15) as server:
                server.login(settings.smtp_user, settings.smtp_password)
                server.sendmail(settings.email_from, [to_email], msg.as_string())
        else:
            # SMTP + STARTTLS（标准 587）
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
                server.starttls()
                server.login(settings.smtp_user, settings.smtp_password)
                server.sendmail(settings.email_from, [to_email], msg.as_string())
        return EmailResult(ok=True, code=code)
    except Exception as e:
        logger.error("SMTP 发送失败: %s", e)
        return EmailResult(ok=False, code=code, error=str(e))
