# TUI reference

CloudBasher has two interactive layouts. **Multi-node is the default** — it
shows a fleet as a table. `--single-node` is the older one-shell-at-a-time
layout, kept because it is the simpler thing to reach for when you genuinely
have one shell.

```bash
./run.sh -F creds.rc -i                  # multi-node (default)
./run.sh -F creds.rc --single-node -i    # single-node
./run.sh -F creds.rc --notui -i          # no TUI at all: plain readline
```

---

## Contents

- [The multi-node screen](#the-multi-node-screen)
    - [Nodes table columns](#nodes-table-columns)
    - [The Status column](#the-status-column)
    - [Keys](#keys)
    - [The command bar](#the-command-bar)
- [The single-node screen](#the-single-node-screen)
- [The startup identity listing](#the-startup-identity-listing)
- [Dot-command reference](#dot-command-reference)
- [Editing keys](#editing-keys)
- [Redaction for demos](#redaction-for-demos)

---

## The multi-node screen

```text
 ┌─ Nodes ────────────────────────────┬─ Info ──────────────────────────┐
 │ ◐  CSP  Cred  Identity  Region ... │ ┌─Log─┐                         │
 │1 ●✓ AWS  [1]   fed/clb-1  us-east-1│ connect us-east-1 ... ok        │
 │2 ●✓ AWS  [1]   fed/clb-2  us-west-2│ bulk 3 node(s): uname -a        │
 │3 ▲– AWS  [2]   role/dep   eu-west-1│   us-east-1  Linux ip-10-...    │
 │                                    │   us-west-2  Linux ip-10-...    │
 │                                    │                                 │
 ├────────────────────────────────────┤                                 │
 │ AWS Node 2 │ us-west-2 │ connected  │                                │
 │        (2/3)                       │                                 │
 └────────────────────────────────────┴─────────────────────────────────┘
 │ b bulk  o output  p provision  c connect  d disconnect  ...  ? help   │
 │ : .provision federation as clb 1-3                                    │
 └───────────────────────────────────────────────────────────────────────┘
```

Four regions, top to bottom:

| Region | What it is |
|---|---|
| **Nodes** | one row per node; the selection and the cursor both live here |
| **Info** | a `Log` tab carrying connection messages and command output |
| **node status line** | two lines describing the *highlighted* row, with an `(M/N)` position gutter |
| **keymap footer** | the always-visible key legend, and the command bar under it |

`Tab` cycles focus between Nodes and Info. The command bar is not a pane and
has no Tab stop — `:` opens it, `Enter` or `Esc` returns focus to wherever it
was.

There is a fifth surface that is hidden until you ask for it: `t` opens a
**side terminal** for the highlighted node, a real shell on that one container,
overlaid beside the table. `t` again closes it.

### Nodes table columns

Reading left to right:

| Column | Meaning |
|---|---|
| *(row gutter)* | the on-screen row number, dim, pinned — this is what a `1-3` range selector indexes |
| `▸` | expand/collapse marker for a group row |
| `⧗` / `·` | Activity — running / queued work; separate from node status |
| `☐` | selection checkbox (`x` toggles, `a` selects all) |
| `◐` | **Status** — three independent glyphs; see below |
| `CSP` | aws / gcp / azure |
| `Act\|Org\|Ten` | AWS account, GCP org, or Azure tenant |
| `Cred` | which loaded credential this node came from, as `[N]` |
| `Identity` | the principal the credential itself is |
| `Target Identity` | the principal it *acts as* — often a different account |
| `Env` | the CSP's own environment id, the one you can paste into a console |
| `IP` / `Host` | as seen from inside the container |
| `Region` | |
| `Last` | when the node was last touched |
| `Created` | |
| `$?` | exit status of the last command |
| `Cmd Out` | first line of the last command's output |

`←`/`→` (or `h`/`l`) page the columns horizontally; the gutter and Status stay
pinned.

### The Status column

Three independent glyph slots — container state, connection state, and the
latest control-plane authentication evidence. They are fully described in
[`lifecycle.md`](lifecycle.md#the-status-axes); the short version:

```text
  ●✓✓  running, connected, accepted  ▲––  suspended, disconnected, unasked
  ●––  running, disconnected         ✗––  failed
  !    permission denied             ?    authentication result inconclusive
```

Activity is a separate column: `⧗` is running work and `·` is queued work.
Neither is a lifecycle or authentication state.

### Keys

All of these act on the **Nodes** pane.

| Key | Action |
|---|---|
| `x` | toggle the highlighted row or group (also sets the range anchor) |
| `X` | select everything between the last `x` and here, inclusive |
| `a` | select — or deselect — every node |
| `j` / `k` | move down / up (vi aliases for `↓` / `↑`) |
| `enter` | expand / collapse the highlighted group |
| `v` | switch between flat and tree view |
| `←` `→` / `h` `l` | page the columns |
| `t` | open / close the side terminal for the highlighted node |
| `z` | zoom the Info pane to full height; again to restore |
| `m` | cycle demo redaction on/off |
| `:` | focus the command bar |
| `?` | help overlay — the same text as `.help` |
| `Q` | quit; arms `quit` in the command bar, `Enter` confirms |

Eight keys **arm** a command rather than running it — they type it into the
command bar with the current selection filled in, and wait for `Enter`:

| Key | Arms |
|---|---|
| `b` | `bulk selected <cmd>` |
| `o` | `output selected` |
| `p` | `provision` |
| `c` | `connect selected` |
| `d` | `disconnect selected` |
| `s` | `start selected` |
| `S` | `stop selected` |
| `U` | `unregister selected` |
| `D` | `delete selected` |

Arming rather than executing is why the destructive ones (`D`, `S`, `U`) are
safe to press: nothing happens until you read the line and press `Enter`.
`Esc` cancels.

### The command bar

`:` opens a one-line bar. Two commands work with or without the leading dot,
because the bar is never mixed with raw shell text:

```text
  bulk <selector> <cmd>      run <cmd> on the matched nodes
  output <selector>          show each matched node's full last output
```

Every other dot-command keeps its `.`. The selector grammar is shared by all of
them — see [`lifecycle.md`](lifecycle.md#what-each-command-does).

`bulk` shows a summary line per node; `output` is how you read the whole thing
afterwards, without re-running anything.

## The single-node screen

```text
 ┌─ CLI 1/1 ──────────────────────────────────────────────────────────┐
 │ cb> .provision                                                     │
 │ provisioned us-east-1 env-abc123                                   │
 │ cb>                                                                │
 ├─ Log 0/0 ──────────────────────────────────────────────────────────┤
 │ [12:04:11] credentials loaded from creds.rc                        │
 ├─ Status ───────────────────────────────────────────────────────────┤
 │ AWS  │ account 1234...  │ us-east-1                                │
 │ CloudShell │ env-abc123 │ running                                  │
 │ 12:04:19 │ cmds 3 │ ready                                          │
 └────────────────────────────────────────────────────────────────────┘
```

The CLI pane is a real terminal surface: what you type stays where you typed
it, output appears below, the next prompt below that. `Tab` cycles CLI ↔ Log;
`PageUp` / `PageDown` scroll the CLI pane's scrollback.

## The startup identity listing

Before any TUI appears, CloudBasher prints what it loaded — one row per
**identity**, not per file block. A block declaring two `ACT_AS` values is two
rows, and it is the `#` column that `.provision <cred#>` addresses.

```text
  #  blk  kind     account       origin  key           acts as        description
  1  1    iam      123456789012  -       AKIA****ABCD  federated/clb  prod deploy
  2  1    iam      123456789012  -       AKIA****ABCD  role/Deploy    prod deploy
  3  2    console  210987654321  alice   -             -> role/Ops    break-glass
```

Worth knowing about three of those columns:

- **`key`** is masked, always. It is a selector you may need to read aloud; it
  is not a secret you need on screen.
- **`account`** with a `->` prefix means the account of the *role being
  assumed*, not the credential's own. Cross-account assume-role is ordinary, so
  an unmarked ARN account would misattribute.
- **`description`** comes from a `# DESCRIPTION:` comment in your `-F` file. It
  exists because `origin` is genuinely unknowable offline for a raw access key —
  there is no token to decode, and only a live `sts:GetCallerIdentity` resolves
  it.

The same renderer backs `.creds` and `.actas show`, so the three can never
disagree.

## Dot-command reference

Also available in-app: `.help`, or `?` in the multi-node UI.

**Shell / session**

| | |
|---|---|
| `.command [cmd]` | run a command, or enter shell mode |
| `.ls [path]` | list a remote directory |
| `.upload <local> <remote>` | upload a file |
| `.download <remote> <local>` | download a file |

**Session info**

| | |
|---|---|
| `.enum` | list CloudShell environments |
| `.creds` | credential summary |
| `.state` | session state |
| `.history` | command history |
| `.perms` | discover permissions with live API probes |

**Node lifecycle** — all take a selector

| | |
|---|---|
| `.connect <sel>` | open a live session (reconnects if needed) |
| `.disconnect <sel>` | close the session; no cloud call |
| `.start <sel>` | resume a suspended environment; does not connect |
| `.stop <sel>` | suspend a running environment (AWS; alias `.suspend`) |
| `.delete <sel> [--yes]` | destroy the environment **and** unregister |
| `.unregister <sel>` | drop locally only (aliases `.deregister`, `.forget`) |

**Housekeeping**

| | |
|---|---|
| `.heartbeat [sec]` | one heartbeat, or start the loop (alias `.ping`) |
| `.echo <msg>` · `.sleep <sec>` · `.clear` | |
| `.verbose [on\|off]` | toggle detail output |
| `.ui [tui\|notui]` | switch UI mode |
| `.run <file>` | execute a batch file line by line |

**Job control**

| | |
|---|---|
| `.loop <sec> <cmd>` | run a shell command in a background loop |
| `.jobs` · `.fg <id>` · `.kill <id>` | list, wait for, stop |

**AWS-specific**

| | |
|---|---|
| `.provision [...]` | create + register + connect; see below |
| `.register <sel>` | probe regions and register what exists |
| `.register <env_id> <region>` | add a known environment; never creates |
| `.region [selector]` | show or set the region |
| `.actas show` | what `ACT_AS` every loaded credential declares |
| `.actas probe [...]` | ask AWS what one credential can actually derive |
| `.createSession` | bootstrap a session via PKCE |
| `.getuploadurls` / `.getdownloadurls` | S3 presigned URLs |

`.provision` grammar, in full:

```text
  .provision                              active identity, detected region
  .provision region <selector>            one node per matched region
  .provision role [<arn>] [as <name>] [i|start-end]
  .provision federation [as <name>] [i|start-end]
  .provision <cred#>|selected [as <name>]
```

`as` is a preposition, not a subcommand — it takes one name and hands the rest
back, so `federation as clb 1-3` and `federation 1-3 as clb` are identical. The
index is a **position, not a count**: `as clb 44-46` makes `clb-44`, `clb-45`,
`clb-46`.

**GCP-specific**

| | |
|---|---|
| `.token` | mint/refresh the file-service JWT |
| `.quota` | weekly usage quota |
| `.fsls` / `.fsupload` / `.fsdownload` | HTTP file service — no SSH session needed |

**Azure-specific**

| | |
|---|---|
| `.creds [show\|configure]` · `.region [REGION]` · `.enum` · `.perms` | |

**Exit** — `.exit`, `.quit`, `Ctrl-D`, or `Q` in the multi-node UI.

## Editing keys

The command line supports readline-style editing (`Ctrl-A`/`Ctrl-E`,
word-jump, `Ctrl-W`, `Ctrl-K`, `Ctrl-R` incremental history search) **and** a
full vi mode — `insert`, `normal`, `replace` and search, with `h l 0 $ b w x D
d{motion} j k / n i a r R s S`. The current mode is shown in the status line.

`!N` re-runs history entry N.

## Redaction for demos

`m` toggles **demo redaction**: account numbers, IPs, hostnames, usernames and
identity ARNs are masked in the Nodes table and in command output. It is
retroactive and reversible — pressing `m` re-renders what is already on screen,
which is the point. You should not have to decide before the demo starts.

```bash
--redact              # start with it on (partial masking)
--redact pseudonym    # substitute stable fake names instead
```

Two things it deliberately does **not** do:

- It never touches the **log file**. That stays a raw local audit trail.
- It is not what protects *credentials*. Access keys and tokens are masked
  unconditionally, everywhere, with no toggle at all.

Per-field styles and custom regex rules are configured ahead of time in
`cloudbasher.rc` — see [`configuration.md`](configuration.md).
