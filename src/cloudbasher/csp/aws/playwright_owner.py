"""One long-lived thread that owns a Playwright sync session for its whole life."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional, TypeVar

from cloudbasher.core.utils.output import detail, log

T = TypeVar("T")


_OWNER_ATTR = "_cb_pw_owner"


class PlaywrightOwner:
    """A single thread that all Playwright calls are funnelled through."""

    def __init__(self, *, name: str = "pw-owner") -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=name)
        self._lock = threading.Lock()
        self._closed = False
        self._thread_ident: Optional[int] = None


        self._thread_ident = self._executor.submit(threading.get_ident).result()
        detail(f"[browser] Playwright owner thread started ident={self._thread_ident}")

    def is_owner_thread(self) -> bool:
        """True when the caller is already ON the owner thread."""
        return threading.get_ident() == self._thread_ident

    def call(self, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Run ``fn`` on the owner thread and return its result here."""
        if self.is_owner_thread() or self._closed:
            return fn(*args, **kwargs)
        return self._executor.submit(fn, *args, **kwargs).result()

    def shutdown(self, *, wait: bool = True) -> None:
        """Stop the owner thread. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True


        if wait and self.is_owner_thread():
            detail("[browser] owner shutdown requested from its own thread; not joining")
            wait = False
        self._executor.shutdown(wait=wait)
        detail("[browser] Playwright owner thread stopped")


def attach_owner(obj: Any, owner: PlaywrightOwner) -> None:
    """Carry ``owner`` on a Playwright object so callers can find it later."""
    try:
        setattr(obj, _OWNER_ATTR, owner)
    except Exception:


        log("[browser] could not attach the Playwright owner to the handle")


def owner_for(*objs: Any) -> Optional[PlaywrightOwner]:
    """The owner attached to any of ``objs``, or None."""
    for obj in objs:
        owner = getattr(obj, _OWNER_ATTR, None)
        if isinstance(owner, PlaywrightOwner):
            return owner
    return None


def run_owned(objs: Any, fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run ``fn`` on the thread that owns ``objs``, or inline if unowned."""
    candidates = objs if isinstance(objs, tuple) else (objs,)
    owner = owner_for(*candidates)
    if owner is None:
        return fn(*args, **kwargs)
    return owner.call(fn, *args, **kwargs)
