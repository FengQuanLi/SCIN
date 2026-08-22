"""SuperNode 密码学工具模块。

使用 cryptography 库实现 Ed25519 密钥生成、签名与验证。
不要在此模块中自行实现任何密码学算法。

密钥格式约定（全部为 hex 字符串）：
    - 原始 Ed25519 私钥材料:  32 bytes -> 64 hex chars
    - 原始 Ed25519 公钥材料:  32 bytes -> 64 hex chars
    - Ed25519 签名:          64 bytes -> 128 hex chars
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RAW_PRIVATE_KEY_LEN = 32  # bytes
RAW_PUBLIC_KEY_LEN = 32  # bytes
RAW_SIGNATURE_LEN = 64  # bytes

HEX_PRIVATE_KEY_LEN = 64  # hex chars
HEX_PUBLIC_KEY_LEN = 64  # hex chars
HEX_SIGNATURE_LEN = 128  # hex chars

# Challenge 长度（bytes）。16 bytes 对一次性、短期有效的 challenge 足够。
CHALLENGE_BYTES = 16


def generate_keypair() -> tuple[str, str]:
    """生成 Ed25519 密钥对，返回 (private_key_hex, public_key_hex)。

    private_key_hex 是 32 字节原始私钥材料（不是 64 字节的
    签名用种子扩展形式），与文档约定一致。
    """
    private_key = Ed25519PrivateKey.generate()
    priv = private_key.private_bytes_raw()
    pub = private_key.public_key().public_bytes_raw()
    return priv.hex(), pub.hex()


def load_private_key(priv_hex: str) -> Ed25519PrivateKey:
    """从 32 字节原始私钥材料的 hex 字符串加载 Ed25519 私钥。"""
    raw = _decode_hex(priv_hex, "private_key", RAW_PRIVATE_KEY_LEN)
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(pub_hex: str) -> Ed25519PublicKey:
    """从 32 字节原始公钥材料的 hex 字符串加载 Ed25519 公钥。"""
    raw = _decode_hex(pub_hex, "public_key", RAW_PUBLIC_KEY_LEN)
    return Ed25519PublicKey.from_public_bytes(raw)


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """用 Ed25519 私钥对消息签名，返回 64 字节签名。"""
    return private_key.sign(message)


def sign_hex(priv_hex: str, message: bytes) -> str:
    """便捷方法：从 hex 私钥签名，返回 hex 签名。"""
    private_key = load_private_key(priv_hex)
    return sign(private_key, message).hex()


def verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """用 Ed25519 公钥验证签名。成功返回 True，失败返回 False。"""
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def verify_hex(pub_hex: str, message: bytes, signature_hex: str) -> bool:
    """便捷方法：hex 公钥 + hex 签名验证。"""
    try:
        public_key = load_public_key(pub_hex)
        signature = _decode_hex(signature_hex, "signature", RAW_SIGNATURE_LEN)
    except ValueError:
        return False
    return verify(public_key, message, signature)


def generate_challenge() -> str:
    """生成密码学安全的随机 challenge（hex 字符串）。"""
    return secrets.token_hex(CHALLENGE_BYTES)


def is_valid_public_key_hex(pub_hex: str) -> bool:
    """校验 public_key 字段是否为合法的 32 字节 hex。"""
    if not isinstance(pub_hex, str) or len(pub_hex) != HEX_PUBLIC_KEY_LEN:
        return False
    try:
        load_public_key(pub_hex)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_signature_hex(sig_hex: str) -> bool:
    """校验 signature 字段是否为合法的 64 字节 hex。"""
    if not isinstance(sig_hex, str) or len(sig_hex) != HEX_SIGNATURE_LEN:
        return False
    try:
        bytes.fromhex(sig_hex)
        return True
    except ValueError:
        return False


def _decode_hex(value: str, name: str, expected_len: int) -> bytes:
    """解码 hex 字符串并校验长度。"""
    if not isinstance(value, str):
        raise ValueError(f"{name} 必须是字符串")
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"{name} 不是合法的 hex 字符串")
    if len(raw) != expected_len:
        raise ValueError(
            f"{name} 长度错误: 期望 {expected_len} 字节, 实际 {len(raw)} 字节"
        )
    return raw
