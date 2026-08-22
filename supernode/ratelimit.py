"""SuperNode 内存速率限制器。

基于滑动窗口的 IP 级速率限制。
单进程部署足够（Uvicorn 单 worker）。
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class RateLimit:
    max_requests: int
    window_seconds: int


class RateLimiter:
    """线程安全的滑动窗口速率限制器。"""

    def __init__(self):
        self._lock = threading.Lock()
        # key -> deque of timestamps
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        # 定期清理，避免内存泄漏
        self._last_cleanup: float = 0.0
        self._cleanup_interval: float = 300.0  # 5 分钟清理一次

    def check(self, key: str, limit: RateLimit) -> bool:
        """检查是否允许请求。返回 True=允许, False=拒绝。"""
        now = time.monotonic()
        with self._lock:
            self._maybe_cleanup(now)
            dq = self._hits[key]
            # 移除窗口外的旧记录
            cutoff = now - limit.window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= limit.max_requests:
                return False
            dq.append(now)
            return True

    def _maybe_cleanup(self, now: float):
        """清理长时间无活动的 key，防止内存泄漏。"""
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        stale = []
        for key, dq in self._hits.items():
            if not dq or dq[-1] < now - 3600:  # 1 小时无活动
                stale.append(key)
        for key in stale:
            del self._hits[key]


# 全局实例
_limiter = RateLimiter()


def get_limiter() -> RateLimiter:
    return _limiter
