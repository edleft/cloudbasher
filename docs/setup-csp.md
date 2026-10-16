# Cloud-side setup

What has to exist **in the cloud account** before CloudBasher can do anything.
This is the part no amount of local configuration can fix.

Once the cloud side is in place, the credentials themselves go in the `-F`
file: see [`credential-file.md`](credential-file.md) for every block and key,
and [`creds.rc.example`](../creds.rc.example) for a template to copy.

- [AWS](#aws)
- [GCP](#gcp)
- [Azure](#azure)
- [Checking your work](#checking-your-work)

---

## AWS

AWS needs the most setup of the three, because it is the only one where you
choose *what the credential acts as*.

### 1. CloudShell itself

CloudShell must be available and not disabled for your account in the regions
you intend to use. Organizations can turn it off centrally; if it is off, every
call below fails identically no matter what your IAM policy says.

### 2. Permission to drive the CloudShell control plane

CloudBasher calls these operations directly:

```text
  describeEnvironments   createEnvironment    getEnvironmentStatus
  startEnvironment       stopEnvironment      deleteEnvironment
  createSession          deleteSession        sendHeartBeat
  putCredentials         getFileUploadUrls    getFileDownloadUrls
```

The AWS managed policy **`AWSCloudShellFullAccess`** covers all of them. A
tighter hand-written policy works too — grant `cloudshell:*` or enumerate the
operations above.

`putCredentials` is the one worth noticing: it is what projects a working AWS
identity *into* the container. Without it you still get a shell, but `aws` fails
inside it.

### 3. Permission to derive the identity you declared

Every AWS key-based block must declare `ACT_AS`, and each mode needs a different
permission. This is the step people miss.

| `ACT_AS` | Needs | On what |
|---|---|---|
| `federated` | `sts:GetFederationToken` | the calling **IAM user** |
| `role:<arn>` | `sts:AssumeRole` | the caller, **and** a trust policy on the target role naming the caller |
| `direct` | nothing extra | — |
| `direct-unbound` | nothing extra | — |

Two constraints are structural, not policy:

- **`federated` requires a permanent `AKIA` key.** `sts:GetFederationToken`
  cannot be called with temporary credentials. CloudBasher rejects
  `federated` + `ASIA` before making any call.
- **`direct` requires a temporary `ASIA` credential.** A raw `AKIA` cannot be
  projected into the container, so `direct` + `AKIA` is rejected too — use
  `direct-unbound` if you genuinely want a shell with no AWS identity inside
  it, and know that `aws sts get-caller-identity` will fail in there by design.

For `federated`, note what the resulting credential can do: CloudBasher passes
an `Allow *:*` session policy, so the federated principal's effective
permissions are exactly the calling IAM user's own. The session policy is
required — omit it and AWS returns credentials with **zero** permissions, since
`GetFederationToken` intersects against a session policy that otherwise
defaults to deny-all.

`sts:GetCallerIdentity` is also used, to resolve the `origin` column of the
startup identity listing. Denying it costs you that column and nothing else.

### 4. Decide the principal's name before you provision

For `federated` and `role:`, the derived principal's **name**
(`FEDERATION_NAME` / `ROLE_SESSION_NAME` / `as <name>`) is a namespace key.
CloudShell only ever shows a principal the environments that principal created.

Pick one and write it down. Changing it later does not move your
environments — it hides them, permanently, while they keep consuming storage.
See [`lifecycle.md`](lifecycle.md#the-name-decides-what-exists).

### 5. For console or SSO credentials only

AWS console logins and AWS SSO logins are completed in a real browser:

```bash
venv/bin/playwright install chromium
```

Add `--show-browser` to watch it happen; the default is headless. An SSO login
always requires a visible browser step the first time.

## GCP

Simpler, because there is one Cloud Shell per user and nothing to name.

1. **Enable the API.** `cloudshell.googleapis.com` must be enabled on the
   project. This is the usual first failure.
2. **Scope.** CloudBasher requests `https://www.googleapis.com/auth/cloud-platform`.
   A service-account key or an authorized-user credential both work.
3. **The user must have Cloud Shell available.** It is provisioned per user, not
   per project — an organization policy can disable it.

Two API paths are available:

```bash
--api-path public     # cloudshell.googleapis.com, OAuth2  (default)
--api-path private    # shell.cloud.google.com, browser cookies
```

The public path is the one to use unless you specifically need the private one.

GCP also exposes an HTTP **file service** that needs no SSH session at all —
`.fsls`, `.fsupload`, `.fsdownload` mint their own JWT. `.upload` / `.download`
go over SFTP and do need a live session.

## Azure

1. **Cloud Shell must have been initialized once**, through the portal, for the
   account you are using. First-time initialization creates a storage account,
   and it cannot be done through the CloudShell API.
2. **Tenant and subscription.** Pass `--tenant` and `--subscription` when the
   account has more than one; CloudBasher does not guess.
3. **Shell type.** `--shell bash` (default) or `--shell pwsh`.

Authentication is an OAuth flow against `management.azure.com`. `--no-browser`
falls through to device code; `--login-hint EMAIL` pre-fills the login form.

## Checking your work

Two commands answer "is this credential going to work" without creating
anything.

```text
  .actas probe [<cred#>]     ask AWS what ONE credential can actually derive,
                             and print the ACT_AS line(s) to paste into your
                             -F file. STS calls only -- creates no environment.

  .perms                     probe the CloudShell control plane live and report
                             which operations this credential is allowed.
```

`.actas probe` is the one to reach for when a block is rejected at startup: it
tells you what the credential *can* declare, rather than making you guess.

```text
  .enum                      list the environments this principal can see --
                             which, on AWS, is also a check on whether you
                             have the name right.
```

An empty `.enum` on a credential you know has environments is almost always the
namespace problem, not a permission problem.
