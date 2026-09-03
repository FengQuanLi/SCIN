#!/bin/bash
# 清除首页缓存（置顶/取消置顶后立即生效）
# 用法: bash ops/scripts/05_clear_home_cache.sh [cache_path]
CACHE="${1:-/opt/supernode/home_cache.json}"
if [ -f "$CACHE" ]; then
    rm -f "$CACHE"
    echo "已清除: $CACHE"
else
    echo "缓存不存在: $CACHE"
fi
