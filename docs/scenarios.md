# Scenarios

End-to-end walkthroughs. Each one starts from a credential file and ends with
something useful having happened.

Prerequisites are in [`setup-csp.md`](setup-csp.md); the file format itself is
documented in `creds.rc.example`, which every block below is a filled-in
version of. Everything below assumes:

```bash
chmod 600 creds.rc            # it holds credentials; treat it like one
```

- [1. AWS access key, federated](#1-aws-access-key-federated)
- [2. AWS access key, assume-role](#2-aws-access-key-assume-role)
- [3. AWS console login](#3-aws-console-login)
- [4. AWS SSO](#4-aws-sso)
- [5. GCP service account](#5-gcp-service-account)
- [6. Azure service principal](#6-azure-service-principal)
- [7. Several identities in one file](#7-several-identities-in-one-file)
- [8. A fleet across regions](#8-a-fleet-across-regions)
- [9. Bulk commands and reading the output](#9-bulk-commands-and-reading-the-output)
- [10. File transfer](#10-file-transfer)
- [11. Suspend, resume, tear down](#11-suspend-resume-tear-down)

---

## 1. AWS access key, federated

The most common starting point: one permanent IAM key, acting as a federated
user.

```ini
# creds.rc
# DESCRIPTION: research account, federated
export AWS_ACCESS_KEY_ID=AKIAEXAMPLE00000000
export AWS_SECRET_ACCESS_KEY=FAKEsecretEXAMPLEvalue
export ACT_AS=federated
export FEDERATION_NAME=clb
```

```bash
./run.sh -F creds.rc -i
```

Then, in the command bar (`:`):

```text
.provision                 create + register + connect, one step
uname -a                   ... and you have a shell
```

`FEDERATION_NAME=clb` is not cosmetic. Every environment you create here is
visible only to a principal named `clb`. Choose it once.

Requires `sts:GetFederationToken`, and a permanent `AKIA` key — `federated`
with a temporary `ASIA` credential is rejected before any call.

## 2. AWS access key, assume-role

Same key, but the shell runs as a role — often in a different account.

```ini
export AWS_ACCESS_KEY_ID=AKIAEXAMPLE00000000
export AWS_SECRET_ACCESS_KEY=FAKEsecretEXAMPLEvalue
export ACT_AS=role:arn:aws:iam::123456789012:role/CloudShellRole
export ROLE_SESSION_NAME=clb
```

Needs `sts:AssumeRole` on your side **and** a trust policy on the role naming
you. If you are not sure it will work, ask before provisioning:

```text
.actas probe 1             STS calls only -- creates nothing
```

That prints the `ACT_AS` line(s) the credential can actually support, ready to
paste back into the file.

In the Nodes table this shows up as `Identity` (who you are) and
`Target Identity` (who you act as) differing, with a `->` marking the account
of the role rather than your own.

## 3. AWS console login

No key at all — a username and password, completed in a browser.

```ini
AWS_CONSOLE_USERNAME=someone@example.com
AWS_CONSOLE_PASSWORD=EXAMPLE-not-a-real-password
AWS_CONSOLE_ACCOUNT=123456789012
```

```bash
venv/bin/playwright install chromium     # one-time
./run.sh -F creds.rc -i
```

This one runs **headless**: Playwright types the credentials itself, so there
is nothing for you to do. Add `--show-browser` if you want to watch.

Use the `AWS_CONSOLE_*` names rather than bare `username`/`password` — the bare
form is ambiguous across all three providers, and CloudBasher will ask you to
disambiguate with `csp=aws`.

## 4. AWS SSO

```ini
SSO_START_URL=https://my-co.awsapps.com/start
ACCOUNT_ID=123456789012
ROLE_NAME=AdministratorAccess
```

```bash
./run.sh -F creds.rc --show-browser -i
```

`--show-browser` is **required** here, not optional. You complete the identity
provider's login yourself, so a headless run has nowhere to put it —
CloudBasher refuses up front rather than opening a window you did not ask for.

## 5. GCP service account

```bash
./run.sh --gcp -F sa.json --project my-project -i
```

`sa.json` is the service-account key straight from the console. Nothing to
rename, nothing to convert.

```text
.quota                     weekly Cloud Shell usage
.fsls /home/user           list files -- no SSH session needed
```

GCP gives one Cloud Shell per user, so there is no fleet to build and no name
to choose. The API must be enabled on the project first.

## 6. Azure service principal

```ini
tenant_id=11111111-1111-1111-1111-111111111111
client_id=22222222-2222-2222-2222-222222222222
client_secret=FAKEappSecretEXAMPLE
subscription_id=33333333-3333-3333-3333-333333333333
```

```bash
./run.sh --azure -F creds.rc --shell bash -i
```

Cloud Shell must have been initialized once through the portal for this
account — that step creates a storage account and cannot be done through the
API.

## 7. Several identities in one file

One file can hold every provider and every credential type. **A blank line
separates blocks; a comment line does not.**

```ini
# DESCRIPTION: prod, federated
export AWS_ACCESS_KEY_ID=AKIAEXAMPLE00000000
export AWS_SECRET_ACCESS_KEY=FAKEsecretEXAMPLEvalue
export ACT_AS=federated
export FEDERATION_NAME=clb
# ---- the same key can declare more than one derivation ----
export ACT_AS=role:arn:aws:iam::123456789012:role/ReadOnly
export ROLE_SESSION_NAME=ro

# DESCRIPTION: gcp research project
# (a service-account JSON block, pasted whole, goes here)
```

That is **three** identities from two blocks — the AWS key declares two
derivations, and each is separately addressable:

```text
  #  blk  kind    ...  acts as
  1  1    iam          federated/clb
  2  1    iam          role/ReadOnly
  3  2    gcp-sa       -
```

Then `.provision 2` acts as identity `[2]` specifically.

The blank line is the part that goes wrong. Without one, two credentials merge
into a single block, and the result parses as **one** credential nobody wrote.
CloudBasher refuses that rather than guessing, naming the duplicated material.

A JSON credential can be pretty-printed across many lines without splitting —
brace and bracket depth is tracked, so a blank line inside JSON is just
whitespace.

## 8. A fleet across regions

```text
.provision region us-east-1,us-west-2,eu-west-1
.provision region us-*
.provision region ALL
```

One CloudShell environment per region, per identity. Or many identities in one
region:

```text
.provision federation as clb 1-5        clb-1 .. clb-5, one node each
```

The index is a **position, not a count**: `as clb 44-46` gives you `clb-44`,
`clb-45`, `clb-46` — which is how you add to an existing fleet without
renumbering it.

Combine freely, in any order:

```text
.provision federation as demo 1-10 region ALL
```

Watch the Status column: `⧗` while each is in flight, `●✓` when it is running
and connected.

## 9. Bulk commands and reading the output

Select rows with `x` (or `a` for all), then press `b`:

```text
bulk selected curl -s https://ifconfig.me
```

Or address them directly, without touching the selection:

```text
bulk ALL uname -a
bulk us-east-* df -h
bulk 1-3 whoami
```

`bulk` prints one summary line per node — enough to see the shape of the
result. To read a full answer:

```text
output ALL                 the complete last output, per node
```

That is stored, not re-run. Pressing `o` arms `output selected` for the current
selection.

Exit status lands in the `$?` column and the first output line in `Cmd Out`, so
a failed node is visible in the table without opening anything.

For one node's shell rather than a fan-out, highlight it and press `t` — that
opens a real terminal beside the table, on that container.

## 10. File transfer

```text
.upload  ./payload.sh /home/cloudshell-user/payload.sh
.download /home/cloudshell-user/out.log ./out.log
```

On AWS this goes through presigned S3 URLs, arranged so the URL and its
encryption key never appear in the container's `ps` output.

On GCP there are two routes: `.upload`/`.download` use SFTP and need a live
session, while `.fsupload`/`.fsdownload` use the HTTP file service with their
own token and need no session at all.

## 11. Suspend, resume, tear down

Suspending keeps the environment and its storage; you stop paying for a running
shell and `.start` brings it back.

```text
.stop ALL                  suspend every running environment (AWS)
.start ALL                 resume them -- note: does NOT reconnect
.connect ALL               ... this does
```

Across restarts:

```bash
./run.sh -m -i             identities and nodes return, disconnected
./run.sh -m --auto-connect -i
                           ... and reconnect everything on startup
```

Tearing down for real:

```text
.delete ALL                destroys the environments AND unregisters
.delete ALL --yes          skip the confirmation, for batch use
```

Without `--yes`, multi-node mode confirms by making you re-run the same
selector. `.unregister` is the harmless sibling — it forgets nodes locally and
makes no cloud call, so the environments are still there and `.register` finds
them again.

An abandoned fleet is not a quota problem — the quota is on concurrently
running shells, and a suspended environment does not consume it. It is a
storage problem, and `.delete` is the only thing that clears it.
