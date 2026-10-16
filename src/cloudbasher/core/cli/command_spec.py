"""One declarative grammar for every dot-command, and one driver that reads it."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Union

__all__ = [
    "Effects",
    "SlotKind",
    "Slot",
    "Keyword",
    "Verb",
    "Flag",
    "Positional",
    "Rest",
    "CommandSpec",
    "ParseResult",
    "parse",
    "usage",
    "completions",
]


class Effects(enum.Flag):
    """What a command actually does, declared per spec."""

    READ_ONLY = 0
    MUTATES_REGISTRY = enum.auto()
    CREATES_CLOUD = enum.auto()
    DESTROYS_CLOUD = enum.auto()


class SlotKind(enum.Enum):
    """The three selector namespaces, which had four incompatible resolvers."""

    CRED = "cred"
    NODE = "node"
    REGION = "region"


@dataclass(frozen=True)
class Slot:
    """A selector: `<cred#>`, `selected`, `ALL`, `1,3,5`, `us-west-*`."""

    kind: SlotKind
    name: str = "selector"
    required: bool = False


    greedy: bool = False


    accepts: Optional[Callable[[str], bool]] = None


    usage_label: str = ""


@dataclass(frozen=True)
class Keyword:
    """An order-independent `name value...` segment."""

    name: str


    min_arity: int = 0


    aliases: tuple[str, ...] = ()


    abbrev: bool = True


    value_help: str = ""


    usage_hidden: bool = False


    hands_back: bool = False


@dataclass(frozen=True)
class Verb:
    """A trailing sub-command word: `register`, `perms`, `refresh`."""

    name: str
    aliases: tuple[str, ...] = ()
    abbrev: bool = True


@dataclass(frozen=True)
class Flag:
    """A `--name` switch. Distinct from a startup flag, which needs a restart."""

    name: str
    help: str = ""
    usage_hidden: bool = False


@dataclass(frozen=True)
class Positional:
    """A fixed-position value: a path, an int, one of a fixed set of words."""

    name: str
    required: bool = True
    kind: str = "str"
    choices: tuple[str, ...] = ()


    accepts: Optional[Callable[[str], bool]] = None
    reject_hint: Optional[Callable[[str], str]] = None


    usage_label: str = ""


@dataclass(frozen=True)
class Rest:
    """The free-form tail, taken from the RAW line."""

    name: str = "rest"
    required: bool = False


Terminal = Union[Slot, Keyword, Verb, Flag, Positional, Rest]


@dataclass(frozen=True)
class CommandSpec:
    """The whole grammar for one dot-command, and the source of its help."""

    name: str
    summary: str
    terminals: tuple[Terminal, ...] = ()
    effects: Effects = Effects.READ_ONLY

    notes: str = ""


    hidden: bool = False


    subcommands: dict = field(default_factory=dict)

    def keywords(self) -> tuple[Keyword, ...]:
        return tuple(t for t in self.terminals if isinstance(t, Keyword))

    def verbs(self) -> tuple[Verb, ...]:
        return tuple(t for t in self.terminals if isinstance(t, Verb))

    def flags(self) -> tuple[Flag, ...]:
        return tuple(t for t in self.terminals if isinstance(t, Flag))

    def positionals(self) -> tuple[Positional, ...]:
        return tuple(t for t in self.terminals if isinstance(t, Positional))

    def slot(self) -> Optional[Slot]:
        for t in self.terminals:
            if isinstance(t, Slot):
                return t
        return None

    def rest(self) -> Optional[Rest]:
        for t in self.terminals:
            if isinstance(t, Rest):
                return t
        return None


@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int


def tokenize(line: str) -> list[Token]:
    """Split a line into tokens, keeping each token's span in the original."""
    tokens: list[Token] = []
    i, n = 0, len(line)
    while i < n:
        while i < n and line[i].isspace():
            i += 1
        if i >= n:
            break
        start = i
        buf: list[str] = []
        quote: Optional[str] = None
        while i < n:
            ch = line[i]
            if quote:
                if ch == quote:
                    quote = None
                else:
                    buf.append(ch)
            elif ch in ("'", '"'):
                quote = ch
            elif ch.isspace():
                break
            else:
                buf.append(ch)
            i += 1
        tokens.append(Token("".join(buf), start, i))
    return tokens


@dataclass
class ParseResult:
    """What the command got, or why it did not."""

    spec: CommandSpec
    ok: bool = True
    error: str = ""


    raw: str = ""
    selector: Optional[str] = None
    verb: Optional[str] = None
    flags: set[str] = field(default_factory=set)
    positionals: dict[str, str] = field(default_factory=dict)
    segments: dict[str, list[str]] = field(default_factory=dict)
    rest: str = ""


    sub: Optional["ParseResult"] = None

    def value(self, keyword: str, index: int = 0) -> Optional[str]:
        vals = self.segments.get(keyword) or []
        return vals[index] if index < len(vals) else None

    def has(self, keyword: str) -> bool:
        return keyword in self.segments

    def is_bare(self) -> bool:
        """Nothing but the command word -- and `--yes` does not count."""
        return not (self.selector or self.verb or self.positionals or self.segments or self.rest)


def _resolve_word(
    tok: str, candidates: Iterable[tuple[str, str]], abbrev_ok: bool
) -> tuple[Optional[str], bool]:
    """Resolve a token against (spelling, canonical) pairs."""
    low = tok.lower()
    pairs = list(candidates)
    for spelling, canon in pairs:
        if low == spelling:
            return canon, False
    if not abbrev_ok or not low:
        return None, False
    hits = {canon for spelling, canon in pairs if spelling.startswith(low)}
    if len(hits) == 1:
        return hits.pop(), False
    return (None, True) if len(hits) > 1 else (None, False)


def _keyword_pairs(spec: CommandSpec) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for kw in spec.keywords():
        pairs.append((kw.name.lower(), kw.name))
        pairs.extend((a.lower(), kw.name) for a in kw.aliases)
    return pairs


def _may_open_keyword(kw: Optional[Keyword], values: list[str]) -> bool:
    """Whether an ABBREVIATION may open a new keyword, or is the open segment's value."""
    if kw is None:
        return True
    return bool(values)


def parse(spec: CommandSpec, raw_line: str, *, drop_command: bool = True) -> ParseResult:
    """Parse one command line against its spec."""
    res = ParseResult(spec=spec, raw=raw_line or "")
    tokens = tokenize(raw_line or "")
    if drop_command and tokens:
        tokens = tokens[1:]

    kw_pairs = _keyword_pairs(spec)
    verb_pairs = [(v.name.lower(), v.name) for v in spec.verbs()]
    for v in spec.verbs():
        verb_pairs.extend((a.lower(), v.name) for a in v.aliases)
    by_name = {k.name: k for k in spec.keywords()}
    flag_names = {f"--{f.name}" for f in spec.flags()}

    slot = spec.slot()
    rest_t = spec.rest()
    pos_left = list(spec.positionals())


    open_kw: Optional[Keyword] = None
    before_handback: Optional[Keyword] = None

    def vals_of(kw: Optional[Keyword]) -> list[str]:
        return res.segments.get(kw.name, []) if kw is not None else []

    def close() -> None:
        nonlocal open_kw
        open_kw = None

    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        text = tok.text


        if (
            rest_t is not None
            and open_kw is None
            and not pos_left
            and (res.verb is not None or not spec.verbs())
            and (slot is None or res.selector is not None or idx > 0)
        ):
            res.rest = raw_line[tok.start :].strip()
            close()
            return _finish(res, spec)

        if text in flag_names:
            res.flags.add(text[2:])
            idx += 1
            continue

        open_vals = vals_of(open_kw)


        exact_now, _ = _resolve_word(text, kw_pairs, False)
        if exact_now is not None:
            kw = by_name[exact_now]
            if kw.hands_back:
                before_handback = open_kw
            open_kw = kw
            res.segments.setdefault(kw.name, [])
            idx += 1
            continue

        if _may_open_keyword(open_kw, open_vals):


            exact_kw, _ = _resolve_word(text, kw_pairs, False)
            exact_verb, _ = _resolve_word(text, verb_pairs, False)
            canon = exact_kw
            vcanon = exact_verb if res.verb is None else None
            if exact_kw is None and exact_verb is None:
                kw_hit, kw_amb = _resolve_word(text, kw_pairs, True)
                verb_hit, verb_amb = _resolve_word(text, verb_pairs, True)
                if kw_amb or verb_amb or (kw_hit is not None and verb_hit is not None):
                    names = sorted(
                        {k.name for k in spec.keywords()} | {v.name for v in spec.verbs()}
                    )
                    res.ok = False
                    res.error = (
                        f"{spec.name}: '{text}' is ambiguous -- it matches more than "
                        f"one of ({', '.join(names)})"
                    )
                    return res
                canon = kw_hit
                vcanon = verb_hit if res.verb is None else None

            if canon is not None:
                if by_name[canon].hands_back:
                    before_handback = open_kw
                open_kw = by_name[canon]
                res.segments.setdefault(open_kw.name, [])
                idx += 1
                continue

            if vcanon is not None:
                close()
                res.verb = vcanon
                sub_spec = spec.subcommands.get(vcanon)
                if sub_spec is not None:


                    tail = raw_line[tok.end :].strip()
                    res.sub = parse(sub_spec, tail, drop_command=False)
                    if not res.sub.ok:
                        res.ok = False
                        res.error = res.sub.error
                    return _finish(res, spec)
                idx += 1
                continue

            if open_kw is not None and not open_vals:


                res.segments.setdefault(open_kw.name, []).append(text)
                idx += 1
                continue


            if text.startswith("-") and not _is_int(text):
                res.ok = False
                res.error = _unknown_token_error(spec, text)
                return res

            if (
                slot is not None
                and res.selector is None
                and not res.segments
                and not res.positionals
                and (slot.accepts is None or slot.accepts(text))
            ):
                if slot.greedy:


                    rest_tokens = [t.text for t in tokens[idx:] if t.text not in flag_names]
                    res.flags.update(t.text[2:] for t in tokens[idx:] if t.text in flag_names)
                    res.selector = " ".join(rest_tokens)
                    idx = len(tokens)
                    continue
                res.selector = text
                idx += 1
                continue

            if pos_left:
                p = pos_left.pop(0)
                if p.accepts is not None and not p.accepts(text):
                    res.ok = False
                    res.error = (
                        p.reject_hint(text)
                        if p.reject_hint is not None
                        else f"{spec.name}: {text!r} is not a valid {p.name}"
                    )
                    return res
                if p.choices and text.lower() not in {c.lower() for c in p.choices}:
                    res.ok = False
                    res.error = (
                        f"{spec.name}: {p.name} must be one of "
                        f"{', '.join(p.choices)} -- got '{text}'"
                    )
                    return res
                if p.kind == "int" and not _is_int(text):
                    res.ok = False
                    res.error = f"{spec.name}: {p.name} must be a number -- got '{text}'"
                    return res
                res.positionals[p.name] = text
                idx += 1
                continue

            if rest_t is not None:
                res.rest = raw_line[tok.start :].strip()
                close()
                return _finish(res, spec)

            if open_kw is not None:


                taken = " ".join(repr(v) for v in open_vals)
                res.ok = False
                res.error = (
                    f"{spec.name}: unexpected token {text!r} after {open_kw.name} "
                    f"{taken} -- {open_kw.name} takes 1 value."
                    + _offered_tokens(spec)
                    + _startup_flag_hint(text)
                )
                return res

            res.ok = False
            res.error = _unknown_token_error(spec, text)
            return res

        assert open_kw is not None
        res.segments.setdefault(open_kw.name, []).append(text)

        if open_kw.hands_back and res.segments[open_kw.name]:
            open_kw, before_handback = before_handback, None
        idx += 1

    close()
    return _finish(res, spec)


def _is_int(text: str) -> bool:
    return text.isdigit() or (text.startswith("-") and text[1:].isdigit())


def _startup_flag_hint(tok: str) -> str:
    """` -- <flag> is a startup flag...` for a token that looks like one."""
    if not tok.startswith("-"):
        return ""
    return (
        f" {tok} is a startup flag, not a command argument -- it goes on the "
        "run.sh/cloudbasher command line, so it needs a restart."
    )


def _offered_tokens(spec: CommandSpec) -> str:
    """The `(expected: ...)` tail, GENERATED from the spec (#155, criterion G3)."""
    known = sorted([k.name for k in spec.keywords()] + [v.name for v in spec.verbs()])
    return f" (expected: {', '.join(known)})" if known else ""


def _unknown_token_error(spec: CommandSpec, text: str) -> str:
    """Say what was wrong AND which namespace the token came from."""
    if text.startswith("-"):
        return (
            f"{spec.name}: {text} is a startup flag, not a command argument -- it "
            "goes on the run.sh/cloudbasher command line, so it needs a restart."
        )
    tail = _offered_tokens(spec)


    what = "unknown subcommand" if spec.subcommands else "unexpected argument"
    return f"{spec.name}: {what} '{text}'{tail}"


def _one_word_help(value_help: str) -> str:
    """`"<selector>"` -> `"selector"`; anything more complex -> `"value"`."""
    stripped = value_help.strip()
    if stripped.startswith("<") and stripped.endswith(">") and " " not in stripped:
        return stripped[1:-1]
    return "value"


def _finish(res: ParseResult, spec: CommandSpec) -> ParseResult:
    for kw in spec.keywords():
        if kw.name in res.segments and len(res.segments[kw.name]) < kw.min_arity:
            res.ok = False
            got = len(res.segments[kw.name])


            what = _one_word_help(kw.value_help)
            res.error = (
                f"{spec.name}: `{kw.name}` needs a {what} after it"
                if kw.min_arity == 1
                else f"{spec.name}: `{kw.name}` needs {kw.min_arity} values after it"
            ) + (f", got {got}" if got else "")
            return res
    for p in spec.positionals():
        if p.required and p.name not in res.positionals:
            res.ok = False
            res.error = f"{spec.name}: missing required {p.name}"
            return res
    slot = spec.slot()
    if slot is not None and slot.required and not res.selector:
        res.ok = False
        res.error = f"{spec.name}: missing required {slot.name}"
        return res
    rest_t = spec.rest()
    if rest_t is not None and rest_t.required and not res.rest:
        res.ok = False
        res.error = f"{spec.name}: missing required {rest_t.name}"
    return res


_SLOT_LABELS = {
    SlotKind.CRED: "<ID>|selected|ALL",
    SlotKind.NODE: "<node#>|selected|ALL",
    SlotKind.REGION: "<region>|ALL|us-east-*",
}


def _slot_label(slot: Slot) -> str:
    return slot.usage_label or _SLOT_LABELS[slot.kind]


def terse_usage(spec: CommandSpec) -> str:
    """`usage()` collapsed to ONE line, whatever the spec's shape."""
    full = usage(spec).removeprefix("Usage: ")
    if not spec.subcommands:
        return full
    head = f".{spec.name}" if not spec.name.startswith(".") else spec.name
    slot = spec.slot()
    slot_part = ""
    if slot is not None:
        label = _slot_label(slot)
        slot_part = (label if slot.required else f"[{label}]") + " "
    alts = []
    for sub in spec.subcommands.values():


        _, _, tail = usage(sub).removeprefix("Usage: ").partition(" ")
        alts.append(tail.strip())
    return f"{head} {slot_part}[{'|'.join(a for a in alts if a)}]"


def usage(spec: CommandSpec) -> str:
    """Build the usage line from the spec the parser reads."""
    parts: list[str] = [f".{spec.name}" if not spec.name.startswith(".") else spec.name]


    for t in spec.terminals:
        if isinstance(t, Slot):
            label = _slot_label(t)
            parts.append(label if t.required else f"[{label}]")
        elif isinstance(t, Verb):
            parts.append(f"[{t.name}]")
        elif isinstance(t, Positional):
            shown = t.usage_label or t.name
            parts.append(f"<{shown}>" if t.required else f"[{shown}]")
        elif isinstance(t, Keyword):
            if t.usage_hidden:
                continue
            vh = t.value_help or f"<{t.name}>"
            parts.append(f"[{t.name} {vh}]".strip())
        elif isinstance(t, Flag):
            if t.usage_hidden:
                continue
            parts.append(f"[--{t.name}]")
        elif isinstance(t, Rest):
            parts.append(f"<{t.name}>" if t.required else f"[{t.name}]")
    if spec.subcommands:


        slot = spec.slot()
        slot_part = ""
        if slot is not None:
            label = _slot_label(slot)
            slot_part = (label if slot.required else f"[{label}]") + " "
        lines = []
        for i, sub in enumerate(spec.subcommands.values()):
            body = usage(sub).removeprefix("Usage: ")
            head, _, tail = body.partition(" ")
            lines.append(f"{'Usage: ' if i == 0 else '       '}{head} {slot_part}{tail}".rstrip())
        return "\n".join(lines)
    return "Usage: " + " ".join(parts)


def completions(spec: CommandSpec, prefix: str = "") -> list[str]:
    """Every word the parser would accept at a keyword position, for tab-complete."""
    words = [k.name for k in spec.keywords()]
    for k in spec.keywords():
        words.extend(k.aliases)
    words.extend(v.name for v in spec.verbs())
    words.extend(f"--{f.name}" for f in spec.flags() if not f.usage_hidden)
    low = prefix.lower()
    return sorted({w for w in words if w.lower().startswith(low)})
