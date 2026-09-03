#!/usr/bin/env python3
"""SuperNode 广播客户端（MVP）。

用法: python3 client.py <private_key_hex> [server_ip] [port]
  private_key_hex: 64位hex私钥（Ed25519）
  server_ip: 默认 127.0.0.1
  port: 默认 9999
"""
import asyncio
import json
import os
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import padding, serialization

SERVER_IP = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
SERVER_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 9999


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


class BroadcastClient:
    def __init__(self, private_key_hex: str):
        self.sk = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        self.pk = self.sk.public_key()
        self.pk_hex = self.pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.token = b""
        self.authenticated = False
        self.transport = None
        self.heartbeat_task = None
        self.running = True

    def connection_made(self, transport):
        self.transport = transport
        print(f"[{time.strftime('%H:%M:%S')}] 已连接 {SERVER_IP}:{SERVER_PORT}，发送 HELLO...")
        self.send_raw({"type": "hello", "public_key": self.pk_hex})

    def datagram_received(self, data, addr):
        if not self.authenticated:
            try:
                pkt = json.loads(data.decode("utf-8"))
            except Exception:
                return
            ptype = pkt.get("type")
            if ptype == "challenge":
                challenge = pkt.get("challenge", "")
                sig = self.sk.sign(challenge.encode("utf-8"))
                print(f"[{time.strftime('%H:%M:%S')}] 收到 challenge，发送签名...")
                self.send_raw({"type": "proof", "sig": sig.hex()})
            elif ptype == "token":
                self.token = bytes.fromhex(pkt.get("token", ""))
                self.authenticated = True
                print(f"[{time.strftime('%H:%M:%S')}] ✅ 认证成功! token={self.token.hex()}")
                self.heartbeat_task = asyncio.create_task(self.heartbeat_loop())
            elif ptype == "error":
                print(f"[{time.strftime('%H:%M:%S')}] ❌ 错误: {pkt.get('msg')}")
                self.running = False
        else:
            # 已认证：解密
            try:
                plaintext = aes_decrypt(data, self.token)
                pkt = json.loads(plaintext.decode("utf-8"))
            except Exception:
                return
            ptype = pkt.get("type")
            if ptype == "hb_ack":
                pass  # 心跳确认，静默
            elif ptype == "broadcast":
                print(f"\n{'='*60}")
                print(f"📢 收到广播! node_id={pkt.get('node_id')}")
                print(f"   标题: {pkt.get('title')}")
                print(f"   作者: {pkt.get('author')}")
                print(f"   公钥: {pkt.get('pubkey', '')[:32]}...")
                print(f"   摘要: {pkt.get('summary', '')[:100]}")
                print(f"   内容: {pkt.get('content', '')[:200]}...")
                print(f"{'='*60}\n", flush=True)

    def send_raw(self, obj):
        data = json.dumps(obj).encode("utf-8")
        self.transport.sendto(data)

    def send_encrypted(self, obj):
        plaintext = json.dumps(obj).encode("utf-8")
        ciphertext = aes_encrypt(plaintext, self.token)
        self.transport.sendto(ciphertext)

    async def heartbeat_loop(self):
        """每60秒发一次心跳。"""
        while self.running and self.authenticated:
            await asyncio.sleep(60)
            if self.transport and not self.transport.is_closing():
                self.send_encrypted({"type": "hb"})
                print(f"[{time.strftime('%H:%M:%S')}] 💓 心跳已发送")
            else:
                break

    def connection_lost(self, exc):
        print(f"[{time.strftime('%H:%M:%S')}] 连接断开: {exc}")
        self.running = False


async def main():
    if len(sys.argv) < 2:
        print(f"用法: python3 client.py <private_key_hex> [server_ip] [port]")
        sys.exit(1)
    privkey = sys.argv[1]
    client = BroadcastClient(privkey)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: client, remote_addr=(SERVER_IP, SERVER_PORT)
    )
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n客户端已退出")
