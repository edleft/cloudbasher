# Configuration

Two files, with completely different jobs:

| File | Holds | Template |
|---|---|---|
| your `-F` file | **credentials** — who you are | `creds.rc.example` |
| `cloudbasher.rc` | **preferences** — how the tool behaves | `cloudbasher.rc.example` |

Credential types and the AWS `ACT_AS` modes are listed in
[`creds.rc.example`](../creds.rc.example). This page covers the second file.

- [Where cloudbasher.rc is found](#where-cloudbasherrc-is-found)
- [Syntax](#syntax)
- [`[ui]`](#ui)
- [`[redact]`](#redact)
- [`[performance]`](#performance)
- [`[aws]`](#aws)
- [Files CloudBasher writes](#files-cloudbasher-writes)

---

## Where cloudbasher.rc is found

First match wins:

```text
  1.  $CLOUDBASHER_RC                 explicit, absolute
  2.  ./cloudbasher.rc                cwd -- note: NO leading dot
  3.  ~/.cloudbasher.rc               your account -- note: leading dot
```

The middle one is the project-local override: drop a `cloudbasher.rc` beside
the fleet you are working on and it applies to runs from that directory only.

Missing file is silent and normal. A malformed file warns and falls through to
built-in defaults — it never aborts the run.

Precedence for anything that also has a flag: **CLI > rc > built-in default.**

Start by copying the template, which documents every key inline:

```bash
cp cloudbasher.rc.example ~/.cloudbasher.rc
```

## Syntax

INI-style:

```ini
[section]
key  : 'value'        # ':' or '=' both work; inline comment after # or ;
key2 = "value"
```

Values go through three steps when read:

1. inline comments after `#` or `;` are stripped
2. one outer layer of matching `'...'` or `"..."` is stripped
3. Python string escapes are decoded — `\uXXXX`, `\UXXXXXXXX`, `\n`, `\t`, `\\`

Step 3 is what lets a title carry emoji without pasting raw bytes into a config
file. Settings are referred to elsewhere by dotted path — `ui.title`,
`redact.mode` — matching `section` + `key`.

## `[ui]`

| Key | Default | |
|---|---|---|
| `title` | built-in | title-bar text and welcome banner |
| `prompt` | `cb>` | top-level prompt; a trailing `>` is appended if absent |
| `multi_node` | `true` | set `false` to make `--single-node` the default |

`multi_node = false` is the way to opt out of the fleet UI permanently without
typing `--single-node` every run. `--multi-node` on the command line still
overrides it.

## `[redact]`

Demo obfuscation: masks account numbers, IPs, hostnames, usernames and identity
ARNs in the Nodes table and in command output.

| Key | Default | |
|---|---|---|
| `enabled` | `false` | `--redact` and the TUI's `m` key both flip this |
| `mode` | `partial` | `partial` keeps a recognizable prefix/suffix; `pseudonym` substitutes a stable fake name |

`partial` renders `52.1**.**.18` — distinct real values stay visually distinct,
which matters when you are pointing at a table of them. `pseudonym` gives more
privacy and less realism; the same real value maps to the same fake name for
the life of the process.

Per-field overrides pin one field type independently of `mode`:

```ini
field.identity  : 'pseudonym'   # the built-in default: a half-masked ARN
                                # is unreadable either way
field.ip        : 'partial'
```

Custom regex rules are the escape hatch, for when a field's built-in style is
not precise enough. Only **named** capture groups are substituted; everything
else passes through:

```ini
# keep the sequence number legible, hide the codename: clb-1 -> otter-1
rule.fed_seq.pattern : (?P<base>[A-Za-z]+)-\d+$
rule.fed_seq.mode    : pseudonym
rule.fed_seq.scope   : field:identity
```

Setting a rule's `mode` to `off` exempts a shape from an otherwise-broad field
default. Rules are tried in definition order; first match wins.

Two boundaries worth restating:

- Redaction **never touches the log file**.
- Redaction is **not** what protects credentials. Access keys and tokens are
  masked unconditionally, on every surface, with no toggle.

## `[performance]`

Fan-out and timing knobs. Every key is optional; an unconfigured section
changes nothing. These exist because a large fleet has a different shape from
a single node.

| Key | Default | |
|---|---|---|
| `max_workers` | `16` | thread-pool size shared by every per-node fan-out |
| `env_status_poll_interval_seconds` | `1.1` | fallback status-poll cadence |
| `env_start_expected_seconds` | `6.0` | how long a start is expected to take |
| `env_stop_expected_seconds` | `13.4` | likewise for stop |
| `env_status_poll_dense_seconds` | `0.2` | cadence inside the expected window |
| `env_status_poll_quiet_fraction` | `0.7` | fraction of the expectation to stay quiet for |
| `reset_retry_delay_seconds` | `2.0` | retry delay after a connection reset |
| `warmup_retry_delays_seconds` | `15,45` | backoff for a not-ready shell |
| `heartbeat_interval_seconds` | `270` | environment keepalive cadence |
| `heartbeat_ws_ping_interval_seconds` | `15` | idle WebSocket ping |
| `heartbeat_retry_interval_seconds` | `60` | tightened cadence after a failure |
| `heartbeat_max_retries` | `3` | before reverting to normal cadence |

Waiting for a container to change state is not a race — it takes as long as it
takes — so the poll settings only control *when you ask*, never the answer.
Polls run on two tiers: quiet while the answer cannot plausibly have arrived,
then dense across the window where it is expected.

If you raise `max_workers` and start seeing "connection to remote host was
lost" retries in the log, that is the signal to lower it again: it means you
have found the provider's connection-rate throttle.

## `[aws]`

Optional integration points for a live CloudTrail/EventBridge log feed and
Cost & Usage Report billing data. Each key is independently gated — leave one
unset and the corresponding tab stays a placeholder, with no error.

These point at infrastructure you deploy in **your own** account (an API
Gateway WebSocket over an EventBridge rule; a CUR delivered to S3). The
deployment templates are not part of this distribution, and this file has no
bearing on whether the infrastructure exists.

| Key | |
|---|---|
| `eventbridge_ws_url` | the `wss://` endpoint for the live log feed |
| `cur_bucket_name` / `cur_report_name` / `cur_s3_prefix` | where the CUR lands |
| `cur_region` | the region the CUR **bucket** is in — not your session region |
| `billing_poll_interval_seconds` | default `900` |

`cur_region` is the one that bites: a mismatch surfaces as an S3 301 redirect
rather than an obvious error.

## Files CloudBasher writes

| File | What | Mode |
|---|---|---|
| `state.bin` | the encrypted registry — credentials, nodes, active node | `0600` |
| `state_<csp>.bin` | single-node mode's per-CSP slot | `0600` |
| `cloudbasher.log` | the run log, **raw and unmasked** | umask |

State encryption is AES-256-GCM with an scrypt KDF, and the file is written
mode `0600`.

A fresh run always writes the default state file. `-m FILE` resumes from a
different one, which is how you keep separate demo and production registries
side by side — copy `state.bin` aside once, then resume from the copy:

```bash
cp state.bin demo1.bin
./run.sh -m demo1.bin -i
```

`-m` is one of the three mutually exclusive credential sources, so it is never
combined with `-F` or `--creds-env`.

Change the log path with `-l/--log`; `-l stdout` or `-l stderr` sends it to the
console instead of a file.

The log receiving raw text is deliberate — it is a local audit trail, while the
terminal may be screen-shared. It is written with your default umask, so put it
somewhere you would put a credential.
