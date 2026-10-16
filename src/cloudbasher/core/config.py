"""User configuration loader for ``~/.cloudbasher.rc``."""

from __future__ import annotations

import codecs
import configparser
import os
from pathlib import Path
from typing import Callable, Optional

DEFAULT_RC_PATH = "~/.cloudbasher.rc"


CWD_RC_FILENAME = "cloudbasher.rc"


_NOOP_WARN: Callable[[str], None] = lambda _msg: None


def _strip_one_layer_of_quotes(value: str) -> str:
    """Strip a single matching pair of surrounding ``'`` or ``"``."""
    s = value.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _decode_python_escapes(value: str) -> str:
    """Decode Python escape sequences (``\\Uxxxxxxxx``, ``\\uxxxx``, ``\\n`` …)."""
    try:
        return codecs.decode(
            value.encode("latin-1", errors="backslashreplace"),
            "unicode_escape",
        )
    except (UnicodeDecodeError, UnicodeEncodeError):
        return value


def _cook_value(raw: str) -> str:
    """Apply the full quote-strip + escape-decode pipeline to a raw value."""
    return _decode_python_escapes(_strip_one_layer_of_quotes(raw))


RENAMED_KEYS: dict[str, str] = {
    "diag.dns_trace": "diag.net_trace",
    "diag.dns_trace_path": "diag.net_trace_path",
    "diag.dns_bisect": "diag.net_bisect",
}


_RETIRED_SPELLINGS: dict[str, list[str]] = {}
for _old, _new in RENAMED_KEYS.items():
    _RETIRED_SPELLINGS.setdefault(_new, []).append(_old)
del _old, _new


class Config:
    """Read-only view over a parsed rc file."""

    __slots__ = ("_values", "_source_path", "_read")

    def __init__(
        self,
        values: Optional[dict[str, str]] = None,
        source_path: Optional[str] = None,
    ) -> None:
        self._values: dict[str, str] = dict(values or {})
        self._source_path = source_path


        self._read: set[str] = set()

    @property
    def source_path(self) -> Optional[str]:
        """Absolute path of the loaded file, or ``None`` if no file was loaded."""
        return self._source_path

    def _lookup(self, path: str) -> Optional[str]:
        """The raw value for ``path``, honouring a retired spelling, or ``None``."""
        key = path.lower()
        self._read.add(key)
        retired = _RETIRED_SPELLINGS.get(key, ())


        self._read.update(retired)
        if key in self._values:
            return self._values[key]
        for old in retired:
            if old in self._values:
                return self._values[old]
        return None

    def get_string(self, path: str, default: str = "") -> str:
        """Return the cooked string at ``section.key`` or ``default`` if absent."""
        raw = self._lookup(path)
        return default if raw is None else raw

    def get_int(self, path: str, default: int) -> int:
        """Return the integer at ``section.key`` or ``default``."""
        raw = self.get_string(path)
        if not raw:
            return default
        try:
            return int(raw.strip())
        except ValueError:
            return default

    def get_bool(self, path: str, default: bool = False) -> bool:
        """Return the boolean at ``section.key`` or ``default`` if absent/malformed."""
        raw = self._lookup(path)
        if raw is None:
            return default
        normalized = raw.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
        return default

    def with_overrides(self, pairs: dict[str, str]) -> "Config":
        """A NEW Config with ``pairs`` layered over the file's values (`#360`)."""
        merged = dict(self._values)
        merged.update({k.lower(): v for k, v in pairs.items()})
        return Config(values=merged, source_path=self._source_path)

    def keys_read(self) -> set[str]:
        """Dotted paths any getter was asked for. See `_read`."""
        return set(self._read)

    def items_with_prefix(self, prefix: str) -> dict[str, str]:
        """Return ``{suffix: value}`` for every key under ``prefix.`` (e.g. ``"redact.field"`` matches a rc file's ``[redact] field.account = ...``, keyed as ``{"account": "..."}``). For open-ended per-item rc sub-sections whose key names aren't known in advance (unlike ``get_string``/``get_bool``'s fixed dotted paths)."""
        prefix_dot = prefix.lower() + "."


        self._read.update(k for k in self._values if k.startswith(prefix_dot))
        return {
            key[len(prefix_dot) :]: value
            for key, value in self._values.items()
            if key.startswith(prefix_dot)
        }

    def __contains__(self, path: str) -> bool:
        """`key in rc`, through `_lookup` like every other read."""
        return self._lookup(path) is not None

    def __repr__(self) -> str:  # pragma: no cover - debug only
        return f"Config(source={self._source_path!r}, keys={sorted(self._values)!r})"


def _resolve_path(path: Optional[str | os.PathLike[str]]) -> Path:
    if path is not None:
        return Path(path).expanduser()
    env_override = os.environ.get("CLOUDBASHER_RC")
    if env_override:
        return Path(env_override).expanduser()
    cwd_rc = Path(CWD_RC_FILENAME)
    if cwd_rc.exists():
        return cwd_rc
    return Path(DEFAULT_RC_PATH).expanduser()


_active: Optional["Config"] = None


def set_active_config(cfg: "Config") -> None:
    """Publish the Config this process runs under. Called ONCE, from `cli/main.py`, immediately after the `-o` overlay is applied."""
    global _active
    _active = cfg


def active_config() -> "Config":
    """The Config this process runs under, INCLUDING `-o` overrides."""
    return _active if _active is not None else load_user_config()


def switch(path: str, default: bool = True) -> bool:
    """A default-on FALLBACK SWITCH, read at the site that emits or acts."""
    try:
        return active_config().get_bool(path, default=default)
    except Exception:
        return default


def reset_active_config() -> None:
    """Drop the published Config. For tests -- a process-wide singleton that outlives a test is the classic way one test's `-o` leaks into another's."""
    global _active
    _active = None


def load_user_config(
    path: Optional[str | os.PathLike[str]] = None,
    *,
    warn: Callable[[str], None] = _NOOP_WARN,
) -> Config:
    """Load and parse the rc file. Missing or malformed → empty :class:`Config`."""
    rc_path = _resolve_path(path)


    parser = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))

    try:
        with rc_path.open("r", encoding="utf-8") as fh:
            parser.read_file(fh)
    except FileNotFoundError:
        return Config(source_path=None)
    except (configparser.Error, OSError) as exc:
        warn(f"cloudbasher: ignoring malformed {rc_path}: {exc}")
        return Config(source_path=str(rc_path))

    values: dict[str, str] = {}
    for section in parser.sections():
        for key, raw in parser.items(section):
            dotted = f"{section.lower()}.{key.lower()}"
            values[dotted] = _cook_value(raw)

    return Config(values=values, source_path=str(rc_path))
