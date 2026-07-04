"""
SysGuard AI — Cache Manager
Prevents redundant psutil calls on every Streamlit rerun.
5-second TTL keeps UI snappy on i3/HDD hardware.
"""

import time
from typing import Callable, Any


class CacheManager:
    """
    Simple TTL cache.
    Each key stores (value, timestamp).
    Expired entries are re-fetched on next access.
    """

    def __init__(self, ttl_seconds: int = 5):
        self.ttl   = ttl_seconds
        self._data = {}

    def get(self, key: str, fetch_fn: Callable) -> Any:
        """
        Return cached value if fresh, else call fetch_fn() and cache result.
        fetch_fn must be zero-argument callable: lambda: get_cpu_info()
        """
        now = time.monotonic()
        if key in self._data:
            value, ts = self._data[key]
            if now - ts < self.ttl:
                return value
        value = fetch_fn()
        self._data[key] = (value, now)
        return value

    def invalidate(self, key: str = None):
        """Invalidate one key or entire cache."""
        if key:
            self._data.pop(key, None)
        else:
            self._data.clear()

    def age(self, key: str) -> float:
        """Seconds since key was last fetched. -1 if not cached."""
        if key in self._data:
            return round(time.monotonic() - self._data[key][1], 1)
        return -1.0
