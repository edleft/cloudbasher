# Lifecycle

Everything CloudBasher does sits on four nested things. Confusing two of them is
the most common early mistake, so they are worth naming precisely.

```text
  ┌─ credential ─────────────────────────────────────────────────────────┐
  │  one block in your -F file: a key, a service account, a console login │
  │                                                                       │
  │  ┌─ identity ──────────────────────────────────────────────────────┐ │
  │  │  what that credential ACTS AS, plus the NAME it acts under.      │ │
  │  │  One credential can declare several. On AWS the name is a        │ │
  │  │  namespace -- see "The name decides what exists" below.          │ │
  │  │                                                                  │ │
  │  │  ┌─ node ─────────────────────────────────────────────────────┐ │ │
  │  │  │  one row in the Nodes table: an identity + a region,        │ │ │
  │  │  │  tracked locally by CloudBasher.                            │ │ │
  │  │  │                                                             │ │ │
  │  │  │  ┌─ environment ─────────────────────────────────────────┐ │ │ │
  │  │  │  │  the actual CloudShell container, owned by the CSP.    │ │ │ │
  │  │  │  │  Outlives your process. Costs storage. Deleting a node │ │ │ │
  │  │  │  │  is NOT deleting this.                                 │ │ │ │
  │  │  │  └───────────────────────────────────────────────────────┘ │ │ │
  │  │  └────────────────────────────────────────────────────────────┘ │ │
  │  └─────────────────────────────────────────────────────────────────┘ │
  └───────────────────────────────────────────────────────────────────────┘
```

The distinction that matters most: **a node is local bookkeeping, an environment
is cloud state.** `.unregister` forgets the node. `.delete` destroys the
environment. One is free and reversible; the other is neither.

---

## Contents

- [Nothing starts automatically](#nothing-starts-automatically)
- [The status axes](#the-status-axes)
- [The state diagram](#the-state-diagram)
- [What each command does](#what-each-command-does)
- [Getting a first node](#getting-a-first-node)
- [Across restarts](#across-restarts)
- [The name decides what exists](#the-name-decides-what-exists)
- [Storage, quota and cost](#storage-quota-and-cost)

---

## Nothing starts automatically

Startup loads and *declares* your identities. It does not look for
environments, and it does not create any.

```text
  ./run.sh -F creds.rc -i
        │
        ▼
  parse creds.rc ──▶ identities registered ──▶ TUI opens, Nodes table EMPTY
                                                       │
                              you are here ────────────┘
```

This surprises people who expect a shell to be waiting. It is deliberate: an
environment created on your behalf is an environment you did not choose the
name, region or identity for — and on AWS all three are load-bearing.

`.provision` and `.register` are the only ways to get a node. `--auto-connect`
opts into the eager behaviour explicitly.

## The status axes

A node's Status column carries **three independent glyphs**. They report
container state, connection state, and the latest explicit control-plane
authentication evidence; reading them as one value is a reliable way to get
confused.

```text
   Status
   ┌────┬────┬────┐
   │ ●  │ ✓  │ ✓  │
   └────┴────┴────┘
     │    │    └── control plane: latest explicit authentication evidence.
     │    └─────── connection: live, in THIS process. Never stored.
     └──────────── container: what the CSP reports. Survives your process.
```

They move independently. A container can be `Running` while you hold no session
to it (you exited and came back). A session cannot be held to a container that
is `Suspended` — but the container does not care whether you are connected.
Control-plane evidence is independent too: a working terminal does not prove
the credential can authenticate a later API call, and a failed API call does
not necessarily mean authentication was rejected.

| | Glyph | Meaning |
|---|:---:|---|
| **Container** | `●` | `Running` — up and usable |
| | `▲` | `Suspended` — `.start` resumes it |
| | `✗` | `Failed` — ERROR/DELETED, or bootstrap failed |
| | `⊘` | `CredentialInvalid` — the heartbeat found the credential dead |
| | `?` | `Unknown` — the CSP reported a status not mapped |
| | `–` | no status on record |
| **Connection** | `✓` | `Connected` — a live session is held |
| | `↻` | `Retrying` — the heartbeat is mid-retry-cycle |
| | `–` | `Disconnected` — no session in this process |
| **Control plane** | `✓` | latest control-plane request authenticated |
| | `↻` | request/heartbeat retry in progress |
| | `✗` | authentication explicitly rejected |
| | `!` | authenticated principal lacks permission |
| | `?` | request failed without an authentication verdict |
| | `–` | no control-plane result observed |

The Activity column is separate from Status: `⧗` means work is running on the
node, and `·` means it is queued. During lifecycle transitions, tint on the
existing status glyph indicates direction while the glyph continues to report
the current state.

One asymmetry worth knowing: `.stop` drops the connection glyph to `–` the
moment the API accepts the call, before teardown finishes. A suspending
container has no reachable connection, so there is no transition to watch on
that axis.

## The state diagram

The diagram below focuses on container and connection transitions. Control-plane
evidence is orthogonal to these lifecycle changes and is shown in the third
Status glyph.

```text
                          (no node yet)
                                │
              .provision        │        .register
        create + register       │       register an environment
          + connect             │        that already exists
                └───────────────┼───────────────┘
                                ▼
                        ┌───────────────┐
          .connect ────▶│   ● Running   │◀──── .start
                        │   ✓ Connected │
                        └───────┬───────┘
                                │
              .disconnect       │        .stop  (AWS only)
        drop the session,       │        suspend the container
        container untouched     │
                ┌───────────────┴───────────────┐
                ▼                               ▼
        ┌───────────────┐               ┌───────────────┐
        │   ● Running   │               │  ▲ Suspended  │
        │ – Disconnected│               │ – Disconnected│
        └───────┬───────┘               └───────┬───────┘
                │                               │
                │  .connect ──▶ (Running/Connected) ◀── .start then .connect
                │                               │
                └───────────────┬───────────────┘
                                │
                 .unregister    │    .delete
              forget locally,   │   destroy the environment
              environment lives │   AND unregister
                       ┌────────┴────────┐
                       ▼                 ▼
                (no node;          (no node;
                 environment        environment
                 still exists)      gone for good)
```

Two paths lead off the bottom of that diagram and they are not
interchangeable — the left one is reversible with `.register`, the right one is
not reversible at all.

## What each command does

| Command | Cloud call? | Container | Connection |
|---|:---:|---|---|
| `.provision` | yes — creates | → `Running` | → `Connected` |
| `.register` | probe only | unchanged | unchanged |
| `.connect` | yes | wakes it if needed | → `Connected` |
| `.disconnect` | **no** | unchanged | → `Disconnected` |
| `.start` | yes | → `Running` | unchanged (still disconnected) |
| `.stop` / `.suspend` | yes (AWS) | → `Suspended` | → `Disconnected` |
| `.unregister` | **no** | unchanged | dropped with the node |
| `.delete` | yes — destroys | gone | gone |

`.disconnect` and `.unregister` are the two that make no cloud call at all.
If you are unsure whether a command is safe to try, that is the property to
check: no cloud call means nothing to undo.

`.start` deliberately does **not** connect. Waking a fleet and opening sessions
to it are separately expensive, and doing them together is what makes a
160-node resume feel slow.

Every one of these takes the same selector grammar:

```text
  selected        the current Nodes-pane selection
  ALL             every registered node
  us-east-*       a region glob
  us-east-1,eu-west-1
                  a comma list
  1-3             a row range, indexing the Nodes table's row gutter
  <node_id>       one node
  <substring>     case-insensitive, matched against id / region / credential
```

## Getting a first node

The short path, once your `-F` file parses:

```text
  .provision                      one node, the active identity's region
  .provision region us-east-1,us-west-2
                                  one node per region
  .provision federation as clb 1-3
                                  three federated identities: clb-1..clb-3,
                                  one node each
  .provision 2                    act as loaded credential [2] from the
                                  startup listing
```

`.provision` with no arguments is the one to start with: create, register and
connect, in the active identity's detected region, in one step.

If environments already exist — created by an earlier run, or by the AWS
console — `.register` finds them without you knowing any environment id:

```text
  .register us-east-*             probe those regions, register what exists
  .register <env_id> us-east-1    add a specific known environment
```

## Across restarts

Session state is saved encrypted (AES-256-GCM, scrypt KDF, file mode `0600`)
and restored with `-m`:

```text
  ./run.sh -m -i          ──▶  identities and nodes come back
                               with their LAST-KNOWN container status,
                               and DISCONNECTED
```

Restored nodes are registered, not live. Nothing reconnects until you say so:

```text
  .connect ALL            pre-warm the whole fleet; sockets really open
  --auto-connect          do that at startup instead
```

The default is off because reconnecting everything unconditionally does not
scale to a large fleet, and because a restored `Running` status is a
*memory* — the container may have been suspended by the provider since.

Scripted runs (`-c`, `--run`, `.upload`, `.download`, `.enum`, `.perms`) always
connect immediately regardless of the flag; they need a live session right away.

## The name decides what exists

**AWS only, and it catches everybody once.**

CloudShell scopes `describeEnvironments` to the *calling principal*. A derived
principal's name — `FEDERATION_NAME`, `ROLE_SESSION_NAME`, or `as <name>` — is
therefore a **namespace key**, not a label.

```text
  key + ACT_AS=federated + as "clb"    ──▶  sees environments made as clb
  key + ACT_AS=federated + as "test"   ──▶  sees NOTHING made as clb
                                            (they still exist, still cost)
```

Environments created under one name are invisible under another: not listable,
not registerable, not deletable — while still holding persistent storage. This
is why CloudBasher has no invented default name. One it chose for you would
silently decide which environments exist.

`.actas show` prints what every loaded credential declares. `.actas probe` asks
AWS what one credential can actually derive, and prints the `ACT_AS` lines to
paste back into your file.

## Storage, quota and cost

- The quota is on **concurrently running shells** — 10 per region per account on
  AWS — not on how many environments exist. A suspended environment does not
  consume it.
- Each environment holds up to 1 GB of persistent storage per region, which AWS
  reclaims only after 120 days unused.
- So an abandoned fleet is not a quota problem. It is a storage-and-hygiene
  problem, and `.delete` is the only thing that clears it.

CloudTrail is the only account-wide view: it records every `createEnvironment`
call and the identity that made it, regardless of which principal can currently
list the result.

---

Next: [`tui-reference.md`](tui-reference.md) for the screen and the keys, or
[`scenarios.md`](scenarios.md) for end-to-end walkthroughs.
