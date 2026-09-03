#!/usr/bin/env python3
"""SuperNode 广播服务器（MVP）。

UDP 长连接 + 公钥挑战认证 + session_token + AES 加密 + 心跳保活 + 轮询数据库广播。

协议（所有包都是 JSON + AES 加密，首次握手除外）：
  客户端 → 服务器:
    1. HELLO:   {"type":"hello", "public_key":"<64hex>"}           (明文)
    2. PROOF:   {"type":"proof", "sig":"<128hex>"}                  (明文，sign(challenge))
    3. HEARTBEAT: {"type":"hb"}                                     (AES加密, key=session_token)
  服务器 → 客户端:
    1. CHALLENGE: {"type":"challenge", "challenge":"<32hex>"}       (明文)
    2. TOKEN:     {"type":"token", "token":"<64hex>"}               (明文，session_token)
    3. HB_ACK:    {"type":"hb_ack"}                                  (AES加密)
    4. BROADCAST: {"type":"broadcast", "node_id":1, "title":"...", "author":"...", "pubkey":"...", "summary":"...", "content":"..."} (AES加密)

加密: AES-128-CBC, key = session_token[:16] (前16字节), IV 随机16字节拼在密文前。
"""
import asyncio
import base64
import hashlib
import json
import os
import secrets
import struct
import time
import logging
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import padding, serialization

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("broadcast")

# ── 配置 ──
UDP_PORT = 9999
HEARTBEAT_TIMEOUT = 180       # 3分钟没心跳踢掉
HEARTBEAT_INTERVAL = 60       # 客户端建议60秒一次
POLL_INTERVAL = 30            # 每30秒扫一次数据库
POLL_WINDOW = 60              # 只扫1分钟内变化的帖子
DB_HOST = "127.0.0.1"
DB_PORT = 3306
DB_USER = os.environ.get("SCIN_DB_USER", "scin")
DB_PASS = os.environ.get("SCIN_DB_PASS", "change_me")
DB_NAME = os.environ.get("SCIN_DB_NAME", "scin_trial")


# ── AES 加解密 ──
def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-128-CBC 加密，返回 IV(16) + ciphertext。"""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-128-CBC 解密，输入 IV(16) + ciphertext。"""
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ── 连接状态 ──
class Client:
    def __init__(self, addr, public_key: str, user_id: int):
        self.addr = addr
        self.public_key = public_key
        self.user_id = user_id
        self.token = b""          # session_token (16字节)
        self.authenticated = False
        self.last_heartbeat = time.time()
        self.last_broadcast_id = 0  # 最后收到的广播 node_id

    def send(self, loop, data: bytes):
        transport = self._transport
        if transport and not transport.is_closing():
            transport.sendto(data)

    # FastAPI 注入
    _transport = None


class BroadcastServer:
    def __init__(self):
        self.clients: dict[str, Client] = {}  # addr -> Client
        self.pending_auth: dict[str, dict] = {}  # addr -> {public_key, challenge, user_id}
        self.transport = None
        self.last_poll_time = 0
        # 服务器自己的密钥对（用于签名广播，后续可选）
        self._sk = ed25519.Ed25519PrivateKey.generate()
        self.broadcaster_pubkey_hex = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def connection_made(self, transport):
        self.transport = transport
        log.info(f"广播服务器监听 :{UDP_PORT}")

    def datagram_received(self, data, addr):
        try:
            self._handle_packet(data, addr)
        except Exception as e:
            log.error(f"处理包异常 {addr}: {e}")

    def _handle_packet(self, data: bytes, addr):
        addr_str = f"{addr[0]}:{addr[1]}"

        # ── 未认证：明文 JSON ──
        if addr_str not in self.clients or not self.clients[addr_str].authenticated:
            try:
                pkt = json.loads(data.decode("utf-8"))
            except Exception:
                log.warning(f"非JSON包 {addr}: {data[:50]}")
                return
            ptype = pkt.get("type")

            if ptype == "hello":
                self._on_hello(pkt, addr, addr_str)
            elif ptype == "proof":
                self._on_proof(pkt, addr, addr_str)
            else:
                log.warning(f"未知类型(未认证) {addr}: {ptype}")

        # ── 已认证：AES 加密 ──
        elif addr_str in self.clients:
            client = self.clients[addr_str]
            if not client.token:
                return
            try:
                plaintext = aes_decrypt(data, client.token)
                pkt = json.loads(plaintext.decode("utf-8"))
            except Exception:
                log.warning(f"解密失败 {addr}")
                return
            ptype = pkt.get("type")
            if ptype == "hb":
                self._on_heartbeat(client, addr_str)
            else:
                log.warning(f"未知类型(已认证) {addr}: {ptype}")

    def _on_hello(self, pkt, addr, addr_str):
        """首次连接：客户端发公钥。"""
        public_key = pkt.get("public_key", "")
        if len(public_key) != 64:
            self._send_raw(addr, {"type": "error", "msg": "public_key must be 64 hex"})
            return
        # 查数据库找 user_id
        user_id = self._lookup_user(public_key)
        if user_id is None:
            self._send_raw(addr, {"type": "error", "msg": "unknown public_key"})
            return
        challenge = secrets.token_hex(16)
        self.pending_auth[addr_str] = {"public_key": public_key, "challenge": challenge, "user_id": user_id}
        log.info(f"HELLO {addr} user_id={user_id}")
        self._send_raw(addr, {"type": "challenge", "challenge": challenge})

    def _on_proof(self, pkt, addr, addr_str):
        """签名验证。"""
        pending = self.pending_auth.get(addr_str)
        if not pending:
            self._send_raw(addr, {"type": "error", "msg": "no pending challenge"})
            return
        sig = pkt.get("sig", "")
        challenge = pending["challenge"]
        public_key = pending["public_key"]
        user_id = pending["user_id"]
        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
            pk.verify(bytes.fromhex(sig), challenge.encode("utf-8"))
        except Exception:
            self._send_raw(addr, {"type": "error", "msg": "signature invalid"})
            self.pending_auth.pop(addr_str, None)
            return
        # 认证成功
        token = os.urandom(16)  # 16字节 AES key
        client = Client(addr, public_key, user_id)
        client.token = token
        client.authenticated = True
        client._transport = self.transport
        self.clients[addr_str] = client
        self.pending_auth.pop(addr_str, None)
        log.info(f"AUTH OK {addr} user_id={user_id} token={token.hex()}")
        # 下发 token（明文）
        self._send_raw(addr, {"type": "token", "token": token.hex()})
        # 心跳确认（加密）
        self._send_encrypted(client, {"type": "hb_ack"})

    def _on_heartbeat(self, client, addr_str):
        """心跳。"""
        client.last_heartbeat = time.time()
        self._send_encrypted(client, {"type": "hb_ack"})

    def _send_raw(self, addr, obj):
        """发送明文 JSON。"""
        data = json.dumps(obj).encode("utf-8")
        self.transport.sendto(data, addr)

    def _send_encrypted(self, client, obj):
        """发送 AES 加密 JSON。"""
        plaintext = json.dumps(obj).encode("utf-8")
        ciphertext = aes_encrypt(plaintext, client.token)
        self.transport.sendto(ciphertext, client.addr)

    def _lookup_user(self, public_key: str):
        """公钥查 user_id。"""
        import pymysql
        try:
            conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, db=DB_NAME)
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE public_key=%s LIMIT 1", (public_key,))
            row = cur.fetchone()
            conn.close()
            return row[0] if row else None
        except Exception as e:
            log.error(f"DB查询失败: {e}")
            return None

    async def poll_broadcasts(self):
        """定期扫描数据库，向已连接用户广播新帖子。"""
        import pymysql
        while True:
            await asyncio.sleep(POLL_INTERVAL)
            try:
                conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, db=DB_NAME)
                cur = conn.cursor()
                # 找1分钟内 broadcast_status 变化为 broadcasting/broadcast_done 的帖子
                cur.execute("""
                    SELECT n.id, n.title, n.content, n.summary, n.broadcast_status,
                           u.display_name, u.public_key as u_pubkey
                    FROM nodes n
                    JOIN users u ON n.user_id = u.id
                    WHERE n.broadcast_status IN ('broadcasting', 'broadcast_done')
                    AND n.updated_at > NOW() - INTERVAL 1 MINUTE
                    ORDER BY n.id ASC
                """)
                rows = cur.fetchall()
                conn.close()

                for row in rows:
                    node_id, title, content, summary, bstatus, display_name, u_pubkey = row
                    # 只广播给还没收到这个 node_id 的客户端
                    for client in list(self.clients.values()):
                        if not client.authenticated or client.last_broadcast_id >= node_id:
                            continue
                        client.last_broadcast_id = node_id
                        pkt = {
                            "type": "broadcast",
                            "node_id": node_id,
                            "title": title or "",
                            "author": display_name or f"user_{client.user_id}",
                            "pubkey": u_pubkey,
                            "summary": (summary or "")[:500],
                            "content": (content or "")[:2000],
                            "status": bstatus,
                        }
                        self._send_encrypted(client, pkt)
                        log.info(f"BROADCAST node={node_id} → {client.addr}")
            except Exception as e:
                log.error(f"轮询广播失败: {e}")

    async def cleanup_loop(self):
        """定期清理超时连接。"""
        while True:
            await asyncio.sleep(60)
            now = time.time()
            for addr_str, client in list(self.clients.items()):
                if client.authenticated and now - client.last_heartbeat > HEARTBEAT_TIMEOUT:
                    log.info(f"清理超时连接 {addr_str} user_id={client.user_id}")
                    del self.clients[addr_str]
            log.info(f"当前连接数: {len(self.clients)}")


async def main():
    server = BroadcastServer()
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _DatagramProto(server), local_addr=("0.0.0.0", UDP_PORT)
    )
    # 启动后台任务
    asyncio.create_task(server.poll_broadcasts())
    asyncio.create_task(server.cleanup_loop())
    # 永久运行
    await asyncio.Event().wait()


class _DatagramProto(asyncio.DatagramProtocol):
    def __init__(self, server: BroadcastServer):
        self.server = server

    def connection_made(self, transport):
        self.server.transport = transport
        self.server.connection_made(transport)

    def datagram_received(self, data, addr):
        self.server.datagram_received(data, addr)


if __name__ == "__main__":
    asyncio.run(main())
