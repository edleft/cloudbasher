# Scripted and non-interactive use

Everything the TUI does is also reachable without it. The same credential
rules apply — one named source, `ACT_AS` declared on AWS — but nothing waits
for a keystroke.

- [One command](#one-command)
- [Fanning out across regions](#fanning-out-across-regions)
- [Batch files](#batch-files)
- [Inspection without a shell](#inspection-without-a-shell)
- [File transfer](#file-transfer)
- [Credentials from the environment](#credentials-from-the-environment)
- [Logging and timing](#logging-and-timing)
- [Things to know before scripting this](#things-to-know-before-scripting-this)

---

## One command

```bash
./run.sh -F creds.rc -c "whoami"
./run.sh -F creds.rc -c "cat /etc/os-release"
```

`-c` connects, runs, prints, and exits. There is no `--auto-connect` to
remember: scripted runs always connect immediately, because they need a live
session right away.

## Fanning out across regions

`--region` accepts more than one region, and the work runs in parallel:

```bash
./run.sh -F creds.rc --region ALL           -c "date"
./run.sh -F creds.rc --region "us-*"        -c "whoami"
./run.sh -F creds.rc --region us-east-1,eu-west-1 -c "curl -s ifconfig.me"
```

This is the non-interactive shape of a `bulk` command: one CloudShell
environment per region, one command, output labelled per region.

## Batch files

A batch file is a sequence of lines, run top to bottom:

```text
# provision.cmd -- '#' and blank lines are skipped
.provision region us-east-1,us-west-2
.connect ALL
uname -a
df -h /
.stop ALL
```

```bash
./run.sh -F creds.rc --run provision.cmd
```

Lines starting with `.` are dot-commands; everything else is a shell command
sent to the session. An error on one line is reported and the run **continues**
to the next — a batch is not a transaction. A `.quit` in the file ends it early.

The same file works inside an interactive session via `.run provision.cmd`,
which is the easy way to develop one.

## Inspection without a shell

Two actions answer a question and exit, without provisioning anything:

```bash
./run.sh -F creds.rc -e        # .enum -- list environments this principal sees
./run.sh -F creds.rc -s        # .perms -- probe which operations are allowed
```

`-e` is the fastest check that a credential and its `ACT_AS` name are right. An
empty result on AWS usually means the *name* is wrong rather than the key —
environments created under another name are invisible, not absent.

## File transfer

```bash
./run.sh -F creds.rc -u ./payload.sh /home/cloudshell-user/payload.sh
./run.sh -F creds.rc -d /home/cloudshell-user/out.log ./out.log
```

## Credentials from the environment

For CI, or anywhere writing a file is the wrong move:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export ACT_AS=federated
export FEDERATION_NAME=ci

./run.sh --creds-env -c "whoami"
```

`--creds-env` reads **this provider's** conventional variables and nothing
else. It is still an explicit, named source — it is not ambient discovery, and
it will not silently fall back to an instance role or `~/.aws/credentials` if
the variables are unset. It fails and says which one is missing.

`ACT_AS` is as mandatory here as it is in a file.

## Logging and timing

```bash
./run.sh -F creds.rc -c "date" -l run.log
./run.sh -F creds.rc -c "date" -l stdout        # or stderr
./run.sh -F creds.rc -c "date" -v               # -v console, -vv debug detail
./run.sh -F creds.rc -c "date" --timeline t.jsonl
```

`--timeline` writes one JSON object per operation — name, duration, status. It
carries no request or response bodies, so it is safe to attach to a bug report
in a way the log file is not.

**The log file is raw and unmasked.** Redaction and screen-sharing safety apply
to the terminal, not to it.

## Things to know before scripting this

- **`-i`, `-c`, `--run`, `-u`, `-d`, `-e`, `-s` are mutually exclusive.** One
  action per invocation.
- **Provisioning is not idempotent.** `.provision` creates a *new* environment
  every time. To reuse what exists, use `.register` — it probes and adopts
  without creating.
- **`.delete` is irreversible and takes `--yes`** for unattended use. Without
  it, multi-node mode waits for a confirmation no script will give.
- **The AWS derived name is a namespace.** Change `FEDERATION_NAME` /
  `ROLE_SESSION_NAME` / `--as` between runs and the second run will not see the
  first run's environments. This is the single most likely way for a script to
  quietly leak environments.
- **One CloudShell environment per principal per region.** Two parallel jobs
  under the same identity and region contend for the same container. Give
  concurrent jobs distinct names, distinct regions, or both.

## Two worked shapes

**Discovery.** `-e` takes the same multi-region selectors `-c` does, so an
account-wide look at one principal is a single call:

```bash
./run.sh -F creds.rc --region ALL -e
```

Remember what that answers: `describeEnvironments` is scoped to the *calling
principal*, so this lists what **this identity, under this name** can see — not
what the account holds. Environments created under a different derived name are
invisible here.

**Teardown.** Put it in a batch file so it is reviewable before it runs, rather
than typed under time pressure:

```text
# teardown.cmd -- adopt whatever exists in these regions, then destroy it
.register us-east-1,us-west-2
.delete ALL --yes
```

```bash
./run.sh -F creds.rc --run teardown.cmd
```

`.register` only adopts environments that already exist; it never creates one.
`.delete` is irreversible, and `--yes` removes the confirmation that would
otherwise stop a script. Read the file twice.
