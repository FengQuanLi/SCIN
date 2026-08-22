"""Phase 1: Ed25519 密码学验证测试。

验证密钥生成、签名、验证的完整流程。
"""

import pytest
from supernode import crypto


class TestKeypair:
    def test_generate_keypair_lengths(self):
        priv, pub = crypto.generate_keypair()
        assert len(priv) == crypto.HEX_PRIVATE_KEY_LEN == 64
        assert len(pub) == crypto.HEX_PUBLIC_KEY_LEN == 64

    def test_generate_keypair_hex(self):
        priv, pub = crypto.generate_keypair()
        int(priv, 16)
        int(pub, 16)

    def test_generate_keypair_unique(self):
        p1, pu1 = crypto.generate_keypair()
        p2, pu2 = crypto.generate_keypair()
        assert p1 != p2
        assert pu1 != pu2

    def test_load_roundtrip(self):
        priv, pub = crypto.generate_keypair()
        pk = crypto.load_private_key(priv)
        puk = crypto.load_public_key(pub)
        assert pk.public_key().public_bytes_raw() == bytes.fromhex(pub)


class TestSignVerify:
    def test_sign_verify_success(self):
        priv, pub = crypto.generate_keypair()
        message = b"hello supernode"
        sig = crypto.sign_hex(priv, message)
        assert len(sig) == crypto.HEX_SIGNATURE_LEN == 128
        assert crypto.verify_hex(pub, message, sig) is True

    def test_verify_wrong_message(self):
        priv, pub = crypto.generate_keypair()
        sig = crypto.sign_hex(priv, b"original")
        assert crypto.verify_hex(pub, b"tampered", sig) is False

    def test_verify_wrong_key(self):
        priv1, pub1 = crypto.generate_keypair()
        _, pub2 = crypto.generate_keypair()
        sig = crypto.sign_hex(priv1, b"msg")
        assert crypto.verify_hex(pub2, b"msg", sig) is False

    def test_verify_bad_signature_format(self):
        _, pub = crypto.generate_keypair()
        assert crypto.verify_hex(pub, b"msg", "not-hex") is False
        assert crypto.verify_hex(pub, b"msg", "aa" * 10) is False  # 短签名

    def test_verify_bad_public_key(self):
        priv, _ = crypto.generate_keypair()
        sig = crypto.sign_hex(priv, b"msg")
        assert crypto.verify_hex("zz" * 32, b"msg", sig) is False


class TestChallenge:
    def test_generate_challenge(self):
        c1 = crypto.generate_challenge()
        c2 = crypto.generate_challenge()
        assert len(c1) == crypto.CHALLENGE_BYTES * 2
        assert c1 != c2

    def test_challenge_sign_verify_flow(self):
        """完整 challenge-response 流程。"""
        priv, pub = crypto.generate_keypair()
        challenge = crypto.generate_challenge()
        sig = crypto.sign_hex(priv, challenge.encode())
        assert crypto.verify_hex(pub, challenge.encode(), sig) is True

    def test_replay_detection(self):
        """重放攻击：用旧签名 + 新 challenge 应验证失败。"""
        priv, pub = crypto.generate_keypair()
        challenge1 = crypto.generate_challenge()
        sig = crypto.sign_hex(priv, challenge1.encode())
        challenge2 = crypto.generate_challenge()
        # 用 challenge2 的字节验证 challenge1 的签名 → 应失败
        assert crypto.verify_hex(pub, challenge2.encode(), sig) is False


class TestValidation:
    def test_valid_public_key(self):
        _, pub = crypto.generate_keypair()
        assert crypto.is_valid_public_key_hex(pub) is True

    def test_invalid_public_key(self):
        assert crypto.is_valid_public_key_hex("") is False
        assert crypto.is_valid_public_key_hex("abc") is False
        assert crypto.is_valid_public_key_hex("zz" * 32) is False
        assert crypto.is_valid_public_key_hex(123) is False
        # "a"*64 是合法的 32 字节 hex，Ed25519 接受任意 32 字节作为公钥
        assert crypto.is_valid_public_key_hex("a" * 64) is True

    def test_valid_signature(self):
        priv, _ = crypto.generate_keypair()
        sig = crypto.sign_hex(priv, b"x")
        assert crypto.is_valid_signature_hex(sig) is True

    def test_invalid_signature(self):
        assert crypto.is_valid_signature_hex("") is False
        assert crypto.is_valid_signature_hex("not-hex") is False
        # "aa"*64 是合法的 64 字节 hex（长度校验通过）
        assert crypto.is_valid_signature_hex("aa" * 64) is True
        # 长度不对
        assert crypto.is_valid_signature_hex("aa" * 63) is False
