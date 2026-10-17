# The credential file

The file you pass with `-F`. One block per identity; nothing in it is searched
for automatically.

`creds.rc.example` at the repo root is the fill-in template — copy it, edit it,
delete what you do not need. This page is the reference behind it: every
accepted shape, every rule the parser enforces, and what the error messages
mean.

```bash
cp creds.rc.example creds.rc        # -F takes any path or name
./run.sh -F creds.rc
```

**Never commit a filled-in copy.** The values are secrets. [Secret
references](#secret-references) show how to keep them in 1Password instead, so
the file itself carries none.

This is not `cloudbasher.rc`, which sets UI and behaviour — see
[configuration.md](configuration.md).

**This release is AWS-only.** A file carrying GCP or Azure material is refused
at startup, so those sections are reference for later releases and must stay
commented.

- [File format](#file-format)
- [Secret references](#secret-references)
- [AWS — IAM access key](#aws--iam-access-key)
- [AWS — console username and password](#aws--console-username-and-password)
- [AWS — SSO / Identity Center](#aws--sso--identity-center)
- [Multi-factor authentication](#multi-factor-authentication)
- [Defaults for bulk provisioning](#defaults-for-bulk-provisioning)
- [The seven AWS credential types](#the-seven-aws-credential-types)
- [GCP (not in this release)](#gcp-not-in-this-release)
- [Azure (not in this release)](#azure-not-in-this-release)
- [No file at all — `--creds-env`](#no-file-at-all----creds-env)
- [If something goes wrong](#if-something-goes-wrong)

## File format

**Every block says which cloud it is for, and declares one credential.** Two
rules, and everything else in this section follows from them:

```
csp=aws                  # REQUIRED, once per block: aws | gcp | azure
ACT_AS=federated         # AWS key blocks: exactly one, never two
```

Neither is guessed. A block of bare `username`/`password` is a valid credential
for all three clouds, so a file that leaves the cloud implicit is a file whose
meaning depends on which parser happens to claim each block first — and a block
claimed wrongly is attributed in silence. `csp=` is the input, not a tie-break.

The second rule is what makes the numbering usable: one block is one credential
is one row in the `.creds` listing, so the `[N]` you select with and the `blk`
that sends you to a place in the file are the same number. To use one key for
two derivations, write two blocks and repeat the key material in each.

**A blank line separates blocks.** One block is one credential, and everything
a credential needs must sit in the same block with no blank line inside it.

This is the rule to get right. A blank line between `FEDERATION_NAME` and its
`ACT_AS` splits one credential into two: the first keeps the key material, the
second carries a derivation with nothing to derive from. That is refused, and
the error names the blank line.

**Comment lines do not split a block**, so notes and banners can go anywhere.
Only a blank line ends a block. A blank line inside pretty-printed JSON does
not split one either.

Three spellings, all equivalent and all accepted:

| Form | Example |
|---|---|
| JSON object | `{"access_key_id": "...", "act_as": "federated"}` |
| `KEY=value` or `KEY: value` | `ACT_AS=federated` |
| `export KEY=value` | `export ACT_AS=federated` |

Key case never matters, in any spelling. Leave a blank line **above** a JSON
block — a comment glued to the opening brace hides it. Glued comments are fine
above `key=value`.

**Several blocks per cloud provider are fine**, and several clouds in one file
are fine. Every block is loaded and numbered; nothing is silently dropped or
overwritten.

**A block is either all comments or a credential.** An all-comment block is
documentation and is skipped, which is what makes commenting a block out work.
Anything else must declare a `csp=` and must parse — a block with a `csp=` line
and nothing under it is an error, not an empty credential.

### Quoting and whitespace

Values may be quoted or bare, and it makes no difference:

```
MFA_CODE=op://Vault/Item/one-time password?attribute=otp
MFA_CODE="op://Vault/Item/one-time password?attribute=otp"
MFA_CODE='op://Vault/Item/one-time password?attribute=otp'
```

All three reach the credential identically. A matching pair of single or double
quotes is stripped, and surrounding whitespace is trimmed.

**A value may contain spaces without being quoted.** In `KEY=value` the value
is the rest of the line — these files have no trailing-comment syntax, so
there is nothing for a space to run into. That matters for 1Password paths,
where the canonical TOTP field is literally named `one-time password`.

What is **not** accepted inside a reference is a quote character or a brace:
`'`, `"`, `{` and `}` end the reference. Quoting cannot rescue a path that
contains them, because the quote characters are excluded from the reference
itself. Rename the vault item or field if a path needs one.

### Declaring the provider

Every block needs one of these, anywhere inside it:

```
csp=aws                        # or provider=aws; either spelling, any case
```

`aws`, `gcp` and `azure` are the accepted values. The line must **not** be
commented out — a commented-out `# csp=aws` is a comment, which is what lets a
whole block be commented out for reference. It is removed before parsing, so it
is safe directly above a JSON block, and it must be the whole line: these files
have no trailing-comment syntax, so `csp=aws  # my key` is not a declaration.

A block that declares nothing is refused with the block quoted back, and a
block whose declared cloud cannot parse it is refused naming that cloud. Both
say what to do. Neither is a silent skip.

A description for the `.creds` table goes on a comment line:

```
# DESCRIPTION: my demo key
```

## Secret references

Any value may be a 1Password reference instead of the secret itself, so the
file can be shared or committed. The `op` CLI is needed only if a file actually
uses one. References on comment lines are never resolved.

| Form | Where it may appear |
|---|---|
| `{{ op://Vault/Item/field }}` | anywhere in a value, including inside JSON |
| `op://Vault/Item/field` | as the whole value only |

References resolve **once per run**, so you approve one prompt rather than one
per read.

The MFA code keys are the exception and resolve at the moment a login form
asks, because a code expires in 30 seconds. See
[Multi-factor authentication](#multi-factor-authentication).

## AWS — IAM access key

**`ACT_AS` is required on every AWS key block.** It states how the key becomes
the principal the container runs as; nothing is inferred from the key itself.

| `ACT_AS` | Principal | Key type |
|---|---|---|
| `federated` | `federated-user/<FEDERATION_NAME>` | AKIA |
| `role:<role-arn>` | `assumed-role/<role>/<ROLE_SESSION_NAME>` | AKIA or ASIA |
| `direct` | the session token, used as-is | ASIA |
| `direct-unbound` | the key, used as-is; no container identity | AKIA |

```
csp=aws                                     # required on every block
AWS_ACCESS_KEY_ID=AKIAEXAMPLE00000000       # aliases: AWS_ACCESS_KEY, ACCESS_KEY_ID, AK
AWS_SECRET_ACCESS_KEY=EXAMPLEFAKEsecretkeymaterialnotreal
                                            # aliases: AWS_SECRET_KEY, SECRET_ACCESS_KEY, SK
AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEXAMPLE   # ASIA keys only; omit for AKIA
                                            # alias: SESSION_TOKEN
ACT_AS=federated                            # required; one of the four above
FEDERATION_NAME=clb-demo                    # names federated-user/<name>
ROLE_SESSION_NAME=my-role-session            # names assumed-role/<role>/<session>
```

**Exactly one `ACT_AS` per block.** A second is an error naming both values.
To use one key for two derivations, write two blocks and repeat the key
material in each — each is then one credential with one number, and the number
the listing shows is the number the file shows. An action may only perform the
derivation its block declares, and for `role:` the ARN must match too. Run
`.creds <n> perms` to see what a loaded credential supports.

`FEDERATION_NAME` and `ROLE_SESSION_NAME` are each used only for their own
derivation and never substitute for one another, so a block declaring a role
needs the session name and a block declaring `federated` needs the federation
name. Both are optional — but if neither the block nor the command supplies a name, the
action fails rather than inventing one.

> **The name is a namespace, not a label.** CloudShell scopes environment
> listing to the calling principal, so renaming orphans every environment
> created under the old name: it still counts against the region's
> 10-environment limit, and nothing can list it again. Choose the name before
> you provision, and do not change it afterwards.

**Two combinations are refused** before any cloud call: `federated` with an
ASIA token, and `direct` with an AKIA key.

`direct-unbound` is the AKIA equivalent of `direct`, and it costs you the
in-container credentials. Control-plane calls and the interactive shell work
normally, but `aws` commands **inside** the shell fail — there is no session
identity to populate the container's credential agent. Use `direct-unbound`
when the shell itself is the point; use `federated` or `role:` when `aws` must
work inside it. Environments created this way belong to the IAM user, a
namespace nothing else can re-derive.

## AWS — console username and password

Signs in through a real browser, headless by default. Bare `username` and
`password` are the shape that parses under all three clouds, which is why the
`csp=` line is what decides; the `AWS_CONSOLE_` spellings are clearer to read
but are not what resolves it.

```
csp=aws                                     # required on every block
USERNAME=someone@example.com                # alias: AWS_CONSOLE_USERNAME
PASSWORD=EXAMPLEFAKEconsolepassword         # alias: AWS_CONSOLE_PASSWORD
ACCOUNT=123456789012                        # alias: AWS_CONSOLE_ACCOUNT; optional
```

For the second factor, see
[Multi-factor authentication](#multi-factor-authentication).

## AWS — SSO / Identity Center

The start URL and the portal login go in **one** block. The `SSO_` prefix is
required: bare username and password are console material, and a block holding
both shapes is refused.

```
csp=aws                                     # required on every block
SSO_START_URL=https://my-co.awsapps.com/start
SSO_USERNAME=someone@example.com            # the portal principal
SSO_PASSWORD=EXAMPLEFAKEportalpassword
ACCOUNT_ID=123456789012                     # the TARGET account to sign into
ROLE_NAME=AdministratorAccess               # the permission-set role
SSO_REGION=us-east-1                        # region of the Identity Center instance
SSO_FLOW=device                             # omit for the portal login; see below
ACT_AS=direct                               # optional; the ASIA already IS the role
```

**`ACCOUNT_ID`, not `ACCOUNT`.** `ACCOUNT_ID` is what an SSO block needs;
`ACCOUNT` belongs to a console block. Writing `ACCOUNT` here is not an error —
it is ignored, and the block then yields no credentials.

**`ACCOUNT_ID` is the account you are signing into**, not the one the
credential comes from. Identity Center is not an account, so cross-account is
the normal case and the identity listing shows this under the target columns
only.

**`SSO_REGION` is not `REGION`.** This one is where the Identity Center
instance lives and cannot be guessed from the start URL. `REGION` is where your
shells run — see
[Defaults for bulk provisioning](#defaults-for-bulk-provisioning).

**A block with only a start URL is refused.** Add the portal login above, or
`SSO_FLOW=device`.

`SSO_FLOW=device` prints a URL and a code for you to approve in a browser you
already have open, so it needs no password in the file — but it **cannot run
unattended**. Prefer the portal login. With `SSO_FLOW=device`, all of
`SSO_START_URL`, `SSO_REGION`, `ACCOUNT_ID` and `ROLE_NAME` are required and
are checked before startup.

## Multi-factor authentication

Declare a second factor and a challenged login answers it for you. **The key
prefix follows the login**, the same way `SSO_USERNAME` does, because the
portal principal is not the console principal:

| Block | Seed key | Code key | Alias |
|---|---|---|---|
| `USERNAME` / `PASSWORD` | `MFA_SECRET` | `MFA_CODE` | `TOTP` |
| `SSO_USERNAME` / `SSO_PASSWORD` | `SSO_MFA_SECRET` | `SSO_MFA_CODE` | `SSO_TOTP` |

**The three spellings in a row are one setting.** Declaring two of them in one
block is an error rather than a silent precedence rule.

### Which key takes which value

The two keys differ in **when** they resolve, and that decides what each
accepts:

| Value | Seed key (`MFA_SECRET`) | Code key (`MFA_CODE` / `TOTP`) |
|---|---|---|
| base32 seed — `JBSWY3DPEHPK3PXP` | yes | yes |
| `otpauth://` URI | yes | yes |
| a finished six-digit code | **no** — refused, naming the code key | yes (expires in under 60 s) |
| `op://` reference returning either of the first two | yes | yes |
| `op://` reference returning a code (`?attribute=otp`) | **no** — see below | yes |

A **seed** is static, so the seed key is resolved once when the file is read. A
**code** is valid for 30 seconds, so the code key is left alone until a login
form actually asks. Put a finished code — or a reference that returns one — in
the seed key and it is already stale by the time it is used, which is why that
cell is refused by name rather than accepted and then failing as a wrong code.

### Recommended form

```
MFA_CODE=op://Vault/Item/one-time password?attribute=otp
```

**Keep `?attribute=otp`.** With the attribute, 1Password returns the current
six-digit code and the seed never leaves the vault. Without it, the same
reference returns the seed as an `otpauth://` URI. Both are accepted in the
code key, so either works — but the attribute is the stronger posture.

**The code keys are never stored.** They resolve at the moment a login form
asks, and reach no saved state and no log. A seed in `MFA_SECRET` is static and
is stored with the rest of the block, which is the second reason to prefer a
reference.

**With no second factor declared**, a challenged login does not wait for you to
type anything. Headless, it fails immediately and names the keys to add. With
`--show-browser` it keeps waiting so you can complete the challenge in the
window yourself.

## Defaults for bulk provisioning

What a bulk `.provision selected` or `.enum` should do with **this**
credential, so a mixed file needs no per-credential arguments that the other
credentials cannot accept. Both take the same grammar as the matching command
tokens.

```
REGION=us-west-2                            # one region
REGION=us-east-1,eu-west-2                  # a comma-list
REGION=us-*                                 # a glob
REGION=ALL                                  # every region
INDEX=2                                     # ONE suffixed name: <name>-2
INDEX=1-3                                   # an inclusive RANGE: -1, -2, -3
```

**`INDEX` is a position, not a count**, and starts at 1. Omit it for a bare
name. With `FEDERATION_NAME=clb`, `INDEX=1-3` derives `clb-1`, `clb-2` and
`clb-3`.

`INDEX` needs a derivation to name, so it applies only with `ACT_AS=federated`
or `ACT_AS=role:`. On `direct`, `direct-unbound`, or a console or SSO login it
is refused rather than ignored: those credentials already **are** the identity.

A declared `INDEX` shows on the `acts as` cell after an arrow, as
`federated/[clb] ->1-3`; a declared `REGION` shows on the `regions` cell.

`INDEX` feeds the derived name, so the namespace warning above applies:
changing it later orphans everything created under the old name.

> **There is no default region anywhere.** Not a built-in, not `AWS_REGION`,
> not a guess. A region decides which environments exist, so it has to be one
> you chose — either here or on the command line.

On a GCP or Azure block, `REGION` and `INDEX` are refused. GCP Cloud Shell has
no selectable region; Google assigns the zone.

## The seven AWS credential types

`ACT_AS` is what makes one key shape into four types, because it decides the
principal the container runs as.

| # | Type | Section |
|---|---|---|
| 1 | console username and password | [console](#aws--console-username-and-password) |
| 2 | SSO portal login | [SSO](#aws--sso--identity-center) |
| 2b | SSO device code | [SSO](#aws--sso--identity-center), `SSO_FLOW=device` |
| 4 | AKIA + `ACT_AS=federated` | [IAM key](#aws--iam-access-key) |
| 5 | key + `ACT_AS=role:<arn>` | [IAM key](#aws--iam-access-key) — the only mode valid for AKIA and ASIA alike |
| 6 | AKIA + `ACT_AS=direct-unbound` | [IAM key](#aws--iam-access-key) |
| 7 | ASIA + `ACT_AS=direct` | [IAM key](#aws--iam-access-key) |

6 and 7 are not two spellings of one idea: each is the only legal way to say
"use this credential as it is" for its own key type.

**JSON field names** are the same keys, case-folded: `access_key_id`,
`secret_access_key`, `session_token`, `act_as`, `federation_name`,
`role_session_name`, `username`, `password`, `account`, `mfa_secret`,
`mfa_code`, `sso_start_url`, `account_id`, `role_name`. Canonical
`AccessKeyId` / `SecretAccessKey` / `SessionToken` casing works too, as does a
raw STS response with everything wrapped in a top-level `Credentials`.

**Shell and INI form:** a `[profile]` header is accepted but ignored. There is
no profile selection — the whole block is read.

## GCP (not in this release)

Leave these commented. A file carrying GCP material is refused at startup.

| Shape | Recognised by |
|---|---|
| Service-account JSON, exactly as downloaded | `"type": "service_account"`, `client_email`, `private_key`, `project_id` |
| Authorized-user JSON, as written by `gcloud auth application-default login` | `"type": "authorized_user"`, `client_id`, `client_secret`, `refresh_token` |
| Browser session cookies — `key=value`, a JSON dict, or a cookie array | any ONE of `SID`, `HSID`, `SSID`, `APISID`, `SAPISID`, `NID`, `__Secure-1PSID`, `__Secure-3PSID`, `__Secure-1PAPISID`, `__Secure-3PAPISID`. Selects the private API path |
| Console username and password, email prefilled | accepted as `key=value` as well as JSON; add `csp=gcp` to disambiguate |
| Bare access token | a `ya29.`-prefixed OAuth2 token on its own. Lasts about an hour and cannot be refreshed |

The authorized-user file is accepted, but it is never searched for — name it
with `-F`.

## Azure (not in this release)

Leave these commented. A file carrying Azure material is refused at startup.
JSON is accepted for all of these, with the same field names.

| Shape | Fields |
|---|---|
| Console username and password, via the Portal | `tenant_id` optional; use a bare `tenant_hint` if the account spans tenants |
| Service principal — an App registration in Entra ID | `tenant_id`, `client_id`, `client_secret`, and `subscription_id` when the account has more than one subscription |
| Service principal by certificate | `tenant_id`, `client_id`, `certificate_path`, `certificate_password` if encrypted. The PEM must hold both the private key and its certificate; the thumbprint is derived for you, so do not supply one |
| Refresh token, after a browser or device-code login | `client_id` optional |
| Access token — a pre-supplied bearer | no refresh path, so it dies in about an hour with no way to renew it from the file |

An MSAL token-cache blob is also detected: a JSON object with top-level
`RefreshToken`, `AccessToken`, `IdToken` and `Account`. Its first cached
refresh token is used.

## No file at all — `--creds-env`

One identity read from the environment instead of a file. Mutually exclusive
with `-F`, and it reads the same key names, so anything above translates
directly.

| Provider | Variables |
|---|---|
| AWS | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `ACT_AS`, `FEDERATION_NAME`, `ROLE_SESSION_NAME`. `ACT_AS` is required here too, with the same rules |
| GCP | `GOOGLE_APPLICATION_CREDENTIALS`, naming a service-account or authorized-user JSON file |
| Azure | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` — all four required |

Console and SSO shapes have no environment form; those need `-F`.

> **There is no automatic credential discovery.** Without `-F`, `--creds-env`
> or `--resume`, startup fails rather than searching for an AWS config file, an
> instance role, or a cloud CLI's cached login. A credential picked up
> automatically is a different principal, and the principal decides which
> environments exist.

## If something goes wrong

**Check the blank lines first.** A file whose blocks are not separated reads as
**one** credential — and it parses, as a principal you did not write, so the
error you get names something unrelated. See [File format](#file-format).

**Registering an identity is not provisioning a shell.** Nothing in this file
creates a CloudShell environment. Startup registers identities and finds
environments that already exist; `.provision` and `.enum ... register` are the
only ways to get a node.

**Key case never matters**, in any spelling.

**Trust the startup output over this page.** Every run prints which source,
which file and which block each identity came from, and its declared `ACT_AS`.
Those values are read from the same place the signing code reads them.
