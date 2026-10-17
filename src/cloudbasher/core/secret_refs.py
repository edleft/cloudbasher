"""1Password secret references in credential files."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from typing import Optional

from cloudbasher.core import mfa_keys
from cloudbasher.core.exceptions import CredentialError


_TEMPLATE_RE = re.compile(r"\{\{\s*(op://[^{}'\"]+?)\s*\}\}")


_BARE_LINE_RE = re.compile(
    r"^(?P<lead>\s*(?:export\s+)?[A-Za-z_]\w*\s*=\s*)"
    r"(?P<q>['\"]?)(?P<ref>op://[^'\"{}]*?)(?P=q)\s*$"
)


DEFERRED_VALUE_KEYS = mfa_keys.deferred_value_keys()


DEFERRED_RESOLVE_KEY = "_CB_MFA_RESOLVE_NOW"


_SENTINEL_OPEN = "@@CBREF{}@@"
_SENTINEL_CLOSE = "@@/CBREF{}@@"

_OP_TIMEOUT_SECONDS = 120
"""Generous because the prompt is human-paced -- Touch ID has to be noticed,
reached for and answered. A short timeout fails exactly when the user is
physically responding to it."""


_CACHE: dict[tuple[str, int, int], str] = {}


_CACHE_LOCK = threading.Lock()


_FAILED: dict[tuple[str, int, int], Exception] = {}


def _reset_cache() -> None:
    """Test seam. Not called in production."""
    _CACHE.clear()
    _FAILED.clear()


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


_KEY_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_]\w*)\s*=")


def _is_deferred(line: str) -> bool:
    """Whether this line's key opts out of eager resolution."""
    m = _KEY_RE.match(line)
    return bool(m and m.group(1).upper() in DEFERRED_VALUE_KEYS)


def refs_by_key(text: str) -> "dict[str, list[str]]":
    """``{KEY: [every op:// reference on that key's line]}``."""
    found: "dict[str, list[str]]" = {}
    for line in text.splitlines():
        if _is_comment(line):
            continue
        key = _KEY_RE.match(line)
        if key is None:
            continue
        refs = [m.group(1) for m in _TEMPLATE_RE.finditer(line)]
        bare = _BARE_LINE_RE.match(line)
        if bare:
            refs.append(bare.group("ref"))
        if refs:
            found.setdefault(key.group(1).upper(), []).extend(refs)
    return found


def find_deferred_refs(text: str) -> dict[str, str]:
    """``{KEY: raw op:// reference}`` for every deferred line that carries one."""
    return {key: refs[0] for key, refs in refs_by_key(text).items() if key in DEFERRED_VALUE_KEYS}


def find_refs(text: str) -> list[str]:
    """Every reference the parser would actually resolve, in order, deduplicated."""
    seen: list[str] = []
    for line in text.splitlines():
        if _is_comment(line) or _is_deferred(line):
            continue
        found = [m.group(1) for m in _TEMPLATE_RE.finditer(line)]
        bare = _BARE_LINE_RE.match(line)
        if bare:
            found.append(bare.group("ref"))
        for ref in found:
            if ref not in seen:
                seen.append(ref)
    return seen


def has_refs(text: str) -> bool:
    """Whether resolving this text requires ``op`` at all."""
    return bool(find_refs(text))


def _substitute(text: str, values: dict[str, str]) -> str:
    """Replace every reference with its resolved value, comments untouched."""
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body) :]
        if _is_comment(body):
            out.append(line)
            continue
        bare = _BARE_LINE_RE.match(body)
        if bare and bare.group("ref") in values:
            q = bare.group("q")


            value = values[bare.group("ref")].rstrip("\r\n")
            out.append(f"{bare.group('lead')}{q}{value}{q}{ending}")
            continue
        out.append(_TEMPLATE_RE.sub(lambda m: values.get(m.group(1), m.group(0)), body) + ending)
    return "".join(out)


def _restore_terminal_after_killed_child() -> None:
    """Turn echo back on if a killed subprocess left it off."""
    try:
        import os
        import sys
        import termios

        fd = sys.stdin.fileno()
        if not os.isatty(fd):
            return
        attrs = termios.tcgetattr(fd)
        attrs[3] |= termios.ECHO | termios.ICANON | termios.ISIG
        termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
    except Exception:
        pass


def _run_op(template: str, *, where: str) -> str:
    """The one subprocess boundary. Injectable so unit tests need no ``op``."""
    binary = shutil.which("op")
    if binary is None:
        raise CredentialError(
            f"{where} uses 1Password references (op://...), but the 1Password CLI "
            "'op' is not on PATH.\n"
            "Install it (brew install 1password-cli), or replace the references "
            "with literal values -- op is required ONLY because this file asks "
            "for it."
        )
    try:
        proc = subprocess.run(
            [binary, "inject"],
            input=template,
            capture_output=True,
            text=True,
            timeout=_OP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:


        _restore_terminal_after_killed_child()
        raise CredentialError(
            f"{where}: 1Password did not respond within {_OP_TIMEOUT_SECONDS}s. "
            "An unanswered biometric/authorisation prompt is the usual cause; "
            "run `op whoami` to check the session."
        ) from None
    except OSError as exc:
        raise CredentialError(f"{where}: could not run 'op inject': {exc}") from exc

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() or "no output"
        raise CredentialError(
            f"{where}: 1Password could not resolve a reference.\n"
            f"  op said: {detail}\n"
            "Check the vault/item/field names, and that you are signed in "
            "(`eval $(op signin)`)."
        )
    return proc.stdout


def _no_unparsed_refs(text: str, *, where: str) -> None:
    """Refuse any ``op://`` left on a value line after substitution."""
    for n, line in enumerate(text.splitlines(), 1):
        if _is_comment(line) or _is_deferred(line) or "op://" not in line:
            continue
        raise CredentialError(
            f"{where} line {n}: a value still contains 'op://' after resolution, "
            "so it was not recognised as a reference.\n"
            "A reference must be the WHOLE value (KEY=op://vault/item/field) or "
            "be wrapped as {{ op://vault/item/field }}. Spaces are fine; "
            "1Password rejects ' & ( ) @ + # , ! : \" and \\ in a path, so an "
            "item whose title contains those must be referenced by its UUID."
        )


def _describe_ref(text: str, ref: str) -> str:
    """``the reference for KEY`` when the key can be found, else the ref itself."""


    for name, refs in refs_by_key(text).items():
        if ref not in refs:
            continue
        if name == DEFERRED_RESOLVE_KEY.upper():
            return "the second-factor reference"
        return f"the reference for {name}"
    return f"the reference {ref!r}"


def resolve_refs(text: str, *, where: str, validate_deferred: bool, runner=None) -> str:
    """Resolve every reference in ``text``. Returns ``text`` unchanged if none."""
    refs = find_refs(text)


    deferred = find_deferred_refs(text) if validate_deferred else {}
    extra_refs = [r for r in deferred.values() if r not in refs]
    if refs or extra_refs:


        from cloudbasher.core.utils.output import out


        out(f"Resolving {len(refs) + len(extra_refs)} secret reference(s) via 1Password...")
    if not refs and not extra_refs:


        _no_unparsed_refs(text, where=where)
        return text

    all_refs = refs + extra_refs
    template = "\n".join(
        _SENTINEL_OPEN.format(i) + "{{ " + ref + " }}" + _SENTINEL_CLOSE.format(i)
        for i, ref in enumerate(all_refs)
    )


    try:
        resolved = (runner or _run_op)(template, where=where)
    except CredentialError as exc:


        if deferred:


            raise CredentialError(
                f"{exc}\n"
                f"  Note: {', '.join(sorted(deferred))} "
                f"{'was' if len(deferred) == 1 else 'were'} in this batch to be "
                "VALIDATED, not used -- their values are discarded, and nothing "
                "has asked for a code yet. So this may still be the reference at "
                "fault."
            ) from exc
        raise

    values: dict[str, str] = {}
    for i, ref in enumerate(all_refs):
        m = re.search(
            re.escape(_SENTINEL_OPEN.format(i)) + r"(.*?)" + re.escape(_SENTINEL_CLOSE.format(i)),
            resolved,
            re.DOTALL,
        )
        if m is None:
            raise CredentialError(
                f"{where}: 1Password returned no value for {ref!r}.\n"
                "(internal: the injected template came back without its marker -- "
                "op's output format may have changed.)"
            )


        if not m.group(1).strip():
            raise CredentialError(
                f"{where}: {_describe_ref(text, ref)} resolved to an EMPTY value.\n"
                "  `op` exits 0 and returns nothing when the ITEM exists but the "
                "FIELD name does not, so this is almost always the last path "
                "segment -- check it against `op item get <item> --format json`. "
                "A label containing a space is the common case, and it needs no "
                "quoting here: the whole value after `=` is the reference.\n"
                "  Reported rather than accepted because an empty credential "
                "field fails much later, as a wrong password or a missing tenant, "
                "with nothing pointing back at the vault path."
            )
        if i < len(refs):


            values[ref] = m.group(1)


    out = _substitute(text, values)


    leftover = find_refs(out)
    if leftover:
        raise CredentialError(
            f"{where}: {len(leftover)} 1Password reference(s) could not be "
            f"substituted, e.g. {leftover[0]!r}."
        )
    _no_unparsed_refs(out, where=where)
    return out


def read_credential_file(path: str, *, runner=None) -> str:
    """Read a credential file, resolving any 1Password references."""
    expanded = os.path.expanduser(path)
    try:
        stat = os.stat(expanded)
        key = (os.path.abspath(expanded), stat.st_mtime_ns, stat.st_size)
    except OSError:


        with open(expanded, encoding="utf-8") as fh:
            return fh.read()

    if key in _CACHE:
        return _CACHE[key]
    if key in _FAILED:
        raise _FAILED[key]


    with _CACHE_LOCK:
        if key in _CACHE:
            return _CACHE[key]
        if key in _FAILED:
            raise _FAILED[key]
        with open(expanded, encoding="utf-8") as fh:
            text = fh.read()
        try:
            resolved = resolve_refs(text, where=path, validate_deferred=True, runner=runner)
        except Exception as exc:
            _FAILED[key] = exc
            raise
        _CACHE[key] = resolved
        return resolved


def warm_credential_file(path: str) -> None:
    """Start resolving `path` in the background, and return immediately."""
    if not path:
        return

    def _warm() -> None:
        try:
            read_credential_file(path)
        except Exception:
            pass

    threading.Thread(target=_warm, name="creds-warm", daemon=True).start()


def describe_refs(text: str) -> Optional[str]:
    """One-line summary for the structure-only inspector, or None."""
    refs = find_refs(text)
    if not refs:
        return None
    return f"{len(refs)} 1Password reference(s) (unresolved): " + ", ".join(refs)
