"""One lock per key, created at most once"""

from __future__ import annotations

import threading
from typing import Hashable

__all__ = ["KeyedLocks"]


class KeyedLocks:
    """A registry vending one `threading.Lock` per key, forever."""

    __slots__ = ("_map_lock", "_locks")

    def __init__(self) -> None:


        self._map_lock = threading.Lock()
        self._locks: dict[Hashable, threading.Lock] = {}

    def __len__(self) -> int:
        """How many keys hold a lock."""
        with self._map_lock:
            return len(self._locks)

    def lock_for(self, key: Hashable) -> threading.Lock:
        """This key's lock, creating it at most once."""
        with self._map_lock:
            return self._locks.setdefault(key, threading.Lock())

    def forget(self) -> None:
        """Drop every lock nobody is holding."""
        with self._map_lock:
            for k in [k for k, lk in self._locks.items() if not lk.locked()]:
                del self._locks[k]

    def retire(self, key: Hashable) -> None:
        """Drop `key`'s lock unconditionally -- ONLY when the key is retired."""
        with self._map_lock:
            self._locks.pop(key, None)

    def known_keys(self) -> "list[Hashable]":
        """The keys currently holding a lock. For diagnostics and tests only."""
        with self._map_lock:
            return list(self._locks)
