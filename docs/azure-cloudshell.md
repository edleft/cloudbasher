# CloudShell Design — Azure

<a id="id-contents"></a>
## Contents

[1. Control-Plane Flow](#id-section-1)
[2. Container Lifecycle](#id-section-2)
&nbsp;&nbsp;&nbsp;&nbsp;[2.1 Where `$HOME` actually lives](#id-section-2-1)
&nbsp;&nbsp;&nbsp;&nbsp;[2.2 What survives a lifecycle event](#id-section-2-2)
&nbsp;&nbsp;&nbsp;&nbsp;[2.3 Environment status](#id-section-2-3)
[3. REST API](#id-section-3)
&nbsp;&nbsp;&nbsp;&nbsp;[3.1 The `userSettings` document, in full](#id-section-3-1)
[4. WebSocket Protocol](#id-section-4)
&nbsp;&nbsp;&nbsp;&nbsp;[4.1 There is a SECOND WebSocket per terminal](#id-section-4-1)
&nbsp;&nbsp;&nbsp;&nbsp;[4.2 Neither the console id nor the relay host is a stable handle](#id-section-4-2)
&nbsp;&nbsp;&nbsp;&nbsp;[4.3 The terminal expects a real emulator on the wire](#id-section-4-3)
[5. File Transfer](#id-section-5)
&nbsp;&nbsp;&nbsp;&nbsp;[5.1 The bodies, captured](#id-section-5-1)
[6. Credential Types](#id-section-6)
[7. Authentication Flows](#id-section-7)
&nbsp;&nbsp;&nbsp;&nbsp;[7.1 Token properties](#id-section-7-1)
&nbsp;&nbsp;&nbsp;&nbsp;[7.2 Per-endpoint token requirements](#id-section-7-2)
&nbsp;&nbsp;&nbsp;&nbsp;[7.3 Cold Start](#id-section-7-3)
&nbsp;&nbsp;&nbsp;&nbsp;[7.4 Hot Reconnect — existing console, new terminal](#id-section-7-4)
&nbsp;&nbsp;&nbsp;&nbsp;[7.5 Portal Flow — `b677c290-cf4b-4a8e-a60e-91ba650a4abe` (Azure Cloud Shell) tokens only](#id-section-7-5)
&nbsp;&nbsp;&nbsp;&nbsp;[7.6 Credential-type support matrix](#id-section-7-6)
&nbsp;&nbsp;&nbsp;&nbsp;[7.7 App ID reference — auth-flow view](#id-section-7-7)
&nbsp;&nbsp;&nbsp;&nbsp;[7.8 FOCI family behavior, minimum privileges & app-ID matrix](#id-section-7-8)
&nbsp;&nbsp;&nbsp;&nbsp;[7.9 Authorization flows (general, not CloudShell-specific)](#id-section-7-9)
&nbsp;&nbsp;&nbsp;&nbsp;[7.10 Portal Token Exchange](#id-section-7-10)
&nbsp;&nbsp;&nbsp;&nbsp;[7.11 Personal MSA takes a different identity path](#id-section-7-11)
&nbsp;&nbsp;&nbsp;&nbsp;[7.12 Azure CLI resource audiences](#id-section-7-12)
[8. Sessions](#id-section-8)
&nbsp;&nbsp;&nbsp;&nbsp;[8.1 Heartbeat / idle / keepalive — SIX layers, and the one everyone defends was never observed to need it](#id-section-8-1)
&nbsp;&nbsp;&nbsp;&nbsp;[8.2 Published service limits](#id-section-8-2)
&nbsp;&nbsp;&nbsp;&nbsp;[8.3 Revocation](#id-section-8-3)
&nbsp;&nbsp;&nbsp;&nbsp;[8.4 Persistence](#id-section-8-4)
[9. IAM Permission Model](#id-section-9)
&nbsp;&nbsp;&nbsp;&nbsp;[9.1 The minimum role also WRITES](#id-section-9-1)
&nbsp;&nbsp;&nbsp;&nbsp;[9.2 ARM RBAC role requirements](#id-section-9-2)
&nbsp;&nbsp;&nbsp;&nbsp;[9.3 Storage account requirements and supported principals](#id-section-9-3)
&nbsp;&nbsp;&nbsp;&nbsp;[9.4 The two storage actions, and what each one gates](#id-section-9-4)
&nbsp;&nbsp;&nbsp;&nbsp;[9.5 How a personal MSA account gets access to CloudShell](#id-section-9-5)
&nbsp;&nbsp;&nbsp;&nbsp;[9.6 Cloud Shell uses ARM authorization, not a separate API permission](#id-section-9-6)
&nbsp;&nbsp;&nbsp;&nbsp;[9.7 IAM actions](#id-section-9-7)
&nbsp;&nbsp;&nbsp;&nbsp;[9.8 Three timing and scope facts that decide whether an IAM measurement means anything](#id-section-9-8)
&nbsp;&nbsp;&nbsp;&nbsp;[9.9 Minimum Azure RBAC by Cloud Shell operation](#id-section-9-9)
[10. Threat Modeling](#id-section-10)
&nbsp;&nbsp;&nbsp;&nbsp;[10.1 Attack Surface](#id-section-10-1)
&nbsp;&nbsp;&nbsp;&nbsp;[10.2 Access policies and control scope](#id-section-10-2)
&nbsp;&nbsp;&nbsp;&nbsp;[10.3 Abuse Scenarios](#id-section-10-3)
&nbsp;&nbsp;&nbsp;&nbsp;[10.4 Hardening Recommendations](#id-section-10-4)


<a id="id-section-1"></a>
## 1. Control-Plane Flow


Azure Cloud Shell uses three control and session tiers. The flow starts with ARM configuration, continues through the Console API on an Azure Service Bus relay, then carries terminal traffic over a pair of WebSockets

1. **ARM control plane** — `management.azure.com`, API version `2023-02-01-preview`.
2. **Console HTTP API** — hosted on a Service Bus relay such as `ccon-prod-{region}-aci-{N}.servicebus.windows.net`; unlike AWS and GCP, this is an Azure Relay-fronted API rather than a direct regional endpoint.
3. **WebSocket relay pair** — the terminal PTY and a terminal-scoped `/control` companion ([§4.1](#id-section-4-1)). Captures have observed terminal and control-channel messages, including download and token-audience metadata. Because channel placement varies across captures, clients should open and classify both sockets. The download flow uses `POST /download`, a `fileUri` handoff on `/control`, and a console-tier `GET` to retrieve the bytes. The browser token handoff includes `POST {console.uri}/accessToken`; a separate `/console-token` call has also been observed, but its purpose is not established. No bearer, cookie, or control URL is persisted.

```text
┌─────────────────────────────┐
│ Caller / CloudBasher        │
│ Azure user or service       │
└──────────────┬──────────────┘
               │ ARM bearer authorization
               ▼
┌─────────────────────────────┐
│ 1. ARM control plane        │
│ management.azure.com        │
│ Console + user settings     │
└──────────────┬──────────────┘
               │ console.uri in PUT response
               ▼
┌─────────────────────────────┐
│ 2. Console HTTP API         │
│ Azure Service Bus relay     │
│ Terminal lifecycle/REST     │
└──────────────┬──────────────┘
               │ terminal PTY + /control WebSockets
               ▼
┌─────────────────────────────┐
│ 3. WebSocket relay pair     │
│ Terminal PTY + /control     │
└──────────────┬──────────────┘
               │ shell I/O
               ▼
┌─────────────────────────────┐
│ Cloud Shell container       │
│ Linux shell environment     │
└─────────────────────────────┘
```


**End-to-end Console credential → terminal → `az` Graph command.** Read this together with [§9.2](#id-section-9-2), which records the two initial Portal OAuth stages and the alternate device-code path. The key distinction is that authentication to manage/provision Cloud Shell and the later token requested by an in-container `az` command are **separate token exchanges**. The first bearer authorizes ARM/Console API calls; the relay `auth-token` authorizes the WebSocket connection; the later Graph access token is requested for the command's resource. Do not reuse or conflate these tokens.

```text
Owner       CloudBasher client          Entra ID / ARM / Console        Container + Portal bridge
  |                 |                              |                               |
  | .provision cred |                              |                               |
  |---------------->| A1: device-code OR Portal browser auth                       |
  |                 |<-----------------------------| ARM-audience delegated bearer |
  |                 | A2: userSettings / console / terminal REST                   |
  |                 |----------------------------->|                               |
  |                 | A3: POST /authorize          |                               |
  |                 |<-----------------------------| opaque relay auth-token       |
  |                 | A4: open PTY + /control WebSockets                           |
  |                 |------------------------------------------------------------->|
  |                 |                              |        az ad ...              |
  |                 |                              |       B1 → localhost:50342    |
  |                 |                              |       B2/B3 → relay/browser   |
  |                 |                              |       B4-B9 → Portal/Entra    |
  |                 |                              |       B10 reply to az: open   |
```

| Token / credential | Issuer and use | Audience / client | Boundary |
|---|---|---|---|
| Console ARM bearer | Entra token obtained by the selected CloudBasher auth route; used by the Python client for ARM and Console HTTP requests. | Legacy ARM audience `https://management.core.windows.net/`; client ID depends on the route. For example, device code uses Azure CLI `04b07795-…`; native Portal sign-in has distinct initial and broker-refresh clients in §9.2. | Delegated user authority; expiry, tenant, scopes, MFA/Conditional Access affect API access. The Portal route's refresh token is browser-bound; generic replay was refused. |
| Relay `auth-token` | Returned by Console `POST /authorize`; used to open the terminal relay WebSockets. | Opaque relay credential, not the ARM or Graph OAuth bearer. | Kept in memory and sent as the WebSocket `Cookie`; do not log or persist it. |
| In-container requested token | Requested by `az` through the local broker and, in the observed native Portal path, brokered through the Portal parent. | Graph request observed as `https://graph.microsoft.com/`; exact Entra client ID, scope, token claims, and full supported audience set remain open. | Separate delegated token. Never infer its `aud` from the request string or use the ARM bearer as a substitute. |
| Portal refresh token | Used by the Portal parent during the observed browser-origin refresh exchange. | Form field names observed; exact values/client policy remain open. | Browser-bound and rotating; do not extract for generic native MSAL replay or persist. |

**Per-command token exchange.** This begins after A4, when the shell and relay are ready. The diagram summarizes the observed path from an in-container `az` request through the Portal and Entra ID. Some local broker and relay details remain unresolved; the diagram does not imply a complete end-to-end transaction trace.

```text
   Cloud Shell container / Linux                       Azure Portal browser                   Entra ID
 ┌───────────────────────────────┐              ┌────────────────────────────────┐         ┌─────────────┐
 │ (B1) az CLI process           │              │ (B4) terminal iframe JS        │         │  Entra ID   │
 │     POST localhost:50342/...  │              │     ux.console.azure.com       │         │             │
 │     resource=<requested URI>  │              │                                │         │             │
 └──────────────┬────────────────┘              └────────────────┬───────────────┘         │             │
                │ (B2) local broker                              │                         │             │
                │ (B3) broker/relay path                         │                         │             │
                └──────────────────────────────────────────────> │                         │             │
                                                                 │ (B5) postMessage        │             │
                                                                 │ {signature, type,       │             │
                                                                 │  audience, ...          │             │
                                                                 ▼                         │             │
                                                ┌────────────────────────────────┐         │             │
                                                │ (B6) Portal parent host JS     │────────>│ (B7) POST   │
                                                │     token acquisition          │ refresh │ /{tid}/     │
                                                │                                │ grant   │ oauth2/v2.0 │
                                                │                                │<────────│ /token      │
                                                │ (B8) postToken {message,       │         │ 200 seen;   │
                                                │     audience} to iframe        │         │ body unknown│
                                                └────────────────┬───────────────┘         └─────────────┘
                                                                 │
                                                ┌────────────────▼───────────────┐
                                                │ (B9) terminal iframe JS        │
                                                │ POST {console.uri}/accessToken │
                                                │ {"token":"<string>"}           │
                                                └────────────────┬───────────────┘
                                                                 │
                                                  (B10) local broker reply to az
```

Some details remain outside the confirmed flow: the precise local request/response correlation between `az` and the broker, the purpose of `/console-token`, and whether the browser-side exchange supplies the token returned to the CLI. The Portal refresh-token request values and returned token claims are not reproduced here.


| Step | Code location / component | Request or response evidence |
|---|---|---|
| B1 | `az` CLI process in Linux container; Cloud Shell selection in Azure CLI profile; `CloudShellCredential` in Azure CLI/MSAL | Current upstream source defines POST `http://localhost:50342/oauth2/token`, `Metadata: true`, and form `resource=<requested scope-derived resource>`. Owner-run debug observed Graph and ARM POSTs returning HTTP 200, response lengths 3277/3013 bytes; EWS requested `https://outlook.office365.com/EWS.AccessAsUser.All` and got HTTP 200 / 3113 bytes. A fresh marker-bounded Graph/ARM/EWS run again saw all three local POSTs return 200, sizes 3276/3014/3163 bytes, with Graph and ARM resource calls 200. Manual direct `GET $MSI_ENDPOINT?resource=...` probes are separate. |
| B1-alt | `az login --identity` → Azure CLI `ManagedIdentityCredential` → MSAL `ManagedIdentityClient` → Azure IMDS, when `ACC_CLOUD` is unset | Owner-supplied `az --debug` log: `GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.core.windows.net%2F`, HTTP 200. CLI profile result identifies `assignedIdentityInfo: MSI`, `name: systemAssignedIdentity`, `type: servicePrincipal`. |
| B2 | Root-owned in-container broker; listener process unknown | Listener observed at `127.0.0.1:50342`; root-owned `RelayProxyServer.dll` and `node app.js` processes are observed. The accepted side of the sampled connection did not expose process attribution. |
| B3 | Broker ↔ terminal relay ↔ Portal browser | The owner-driven browser observer received `tokenAudience=https://graph.microsoft.com/` on `/control` in /`249`; added marker-bounded Graph and EWS frames, both followed by Entra and Service Bus exchanges. EWS audience was `https://outlook.office365.com/`. Historical Portal evidence attributes token metadata to the terminal stream. |
| B4 | Terminal iframe JavaScript in the Portal browser, from the saved `ux.console.azure.com` v2 bundle | Token request handler runs in the iframe; `trustedAuthority` supplies the parent-message origin. |
| B5 | Iframe JavaScript → Portal parent JavaScript, `window.parent.postMessage` | For the Graph example, first `{signature:"portalConsole", type:"getToken", audience:"https://graph.microsoft.com/", resourceId:…, fileShare:…, getTokenWithDetails:true}`, then a follow-up with `getTokenWithDetails:false` and mapped `audience:"microsoft.graph"`. |
| B6 | Portal parent host JavaScript | Receives the request and obtains a delegated token for the audience. |
| B7 | Portal parent browser → Entra ID | In the Graph exchange, tenant-scoped `POST /{tid}/oauth2/v2.0/token` used refresh-token grant fields and returned HTTP 200. The EWS exchange also returned HTTP 200. Response shape included access/ID/refresh-token, scope, token-type, and expiry fields. |
| B8 | Portal parent JavaScript → terminal iframe JavaScript | `postToken` message has `message` and `audience`; iframe requires `message` and passes both to the token callback. |
| B9 | Browser-side terminal/Portal code → Console HTTP API | Both `POST {console.uri}/accessToken` and `POST {console.uri}/console-token` returned HTTP 200 during Graph exchange and EWS exchange. The `/accessToken` body shape is `{"token":"<string>"}`; `/console-token` has keys `audience` (string) and `token` (object). The saved terminal bundle establishes an `Authorization` header slot for `/accessToken`. |
| B10 | Console endpoint / local broker → waiting `az` process | Expected to satisfy B1's pending request. |


The four-layer stack, end to end

```
┌───────────────────────────────────────────────────────────────────┐
│  Layer 1: ARM Control Plane                                       │
│  management.azure.com                                             │
│  POST/PUT/GET/DELETE /providers/Microsoft.Portal/...              │
│  Bearer token: Azure AD JWT (~1hr); scope: management.core.windows│
│  API version: 2023-02-01-preview                                  │
│  Accepted app IDs (full client ID + app name):                    │
│    b677c290-cf4b-4a8e-a60e-91ba650a4abe  Azure Cloud Shell        │
│    04b07795-8ddb-461a-bbee-02f9e1bf7b46  Azure CLI                │
│    04b07795-8542-4c4c-9cb8-f0f09d69f25f  UNVERIFIED               │
└──────────────────────┬────────────────────────────────────────────┘
                       │ returns console.uri  (Service Bus relay host)
                       ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Layer 2: Console HTTP API                                              │
│  ccon-prod-{region}-aci-{N}.servicebus.windows.net:443                  │
│  /cc-{ID}/terminals           POST — create terminal                    │
│  /cc-{ID}/authorize           POST — get opaque WebSocket auth-token    │
│  /cc-{ID}/keepAlive           GET  — prevent idle timeout               │
│  /cc-{ID}/terminals/{TID}/upload    POST — file upload                  │
│  /cc-{ID}/terminals/{TID}/download  POST — file download                │
│  /cc-{ID}/files/{path}              GET  — list directory               │
│  Auth: same Bearer token as Layer 1 + Referer: https://portal.azure.com/│
└──────────────────────┬──────────────────────────────────────────────────┘
                       │ POST /authorize → opaque auth-token
                       ▼
┌────────────────────────────────────────────────────────────────┐
│  Layer 3: WebSocket PTY  (Service Bus relay — all clients)     │
│  wss://{relay_host}/$hc/{console_path}/terminals/{TERMINAL_ID} │
│  Header: Cookie: auth-token={OPAQUE}  (no Authorization header)│
│  Header: Origin: https://ux.console.azure.com                  │
│  Frames: UTF-8 text only; raw PTY data + ANSI sequences        │
│                                                                │
│  [Portal only — requires an Azure Cloud Shell token:           │
│   client_id b677c290-cf4b-4a8e-a60e-91ba650a4abe]              │
│  wss://ux.console.azure.com//{TERMINAL_ID}                     │
│  Header: Authorization: Bearer {Azure Cloud Shell token}       │
└──────────────────────┬─────────────────────────────────────────┘
                       │ persistent storage
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  Layer 4: Azure File Storage (out-of-band)                   │
│  cs{ACCOUNT}.file.core.windows.net                           │
│  Home directory mount (/home/{user}) persists across sessions│
└──────────────────────────────────────────────────────────────┘
```

**Credential injection — where different starting credentials enter this stack** (CloudBasher-specific synthesis; see [§7](#id-section-7) for full mechanics of each row): every credential type this runner supports injects at exactly one point — **Layer 1**, as the input to an MSAL token-acquisition call that produces an ARM-audience Bearer token. Nothing downstream of that token varies by credential type.

| Starting credential | MSAL call at Layer 1 | Resulting token's `appid` | Refresh path |
|---|---|---|---|
| Service principal (`client_id`+`client_secret`) | `acquire_token_for_client` | your SP's client_id | Re-acquire every ~1hr, no user interaction |
| Refresh token (file) | `acquire_token_by_refresh_token` | client_id in file (default `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI)) | Sliding refresh_token rotation |
| Access token only (file) | none — used directly | token's own appid | No refresh path; expires ~1hr |
| Env vars (`AZURE_CLIENT_*`) | `acquire_token_for_client` (SP via env) | `AZURE_CLIENT_ID` value | Same as SP |
| OAuth browser (3LO) | `acquire_token_interactive` | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI) | Refresh token returned |
| OAuth device code | `acquire_token_by_device_flow` | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI) | Refresh token returned |
| Azure CLI (`--az-cli`) | delegated to `az account get-access-token` | `04b07795-8542-4c4c-9cb8-f0f09d69f25f` (**UNVERIFIED — see the 2026-08-28 correction**) | No in-process refresh |
| WAM broker (Windows only) | `acquire_token_interactive(broker=True)` | `c44b4083-cba6-42be-8e29-b9702cdde539` (Azure Portal / WAM broker) | Refresh token returned |

**The key downstream fact**: Layer 2's `POST /authorize` does **not** validate the Bearer token's `appid` — it mints an opaque WebSocket `auth-token` for *any* valid ARM-audience token. So once any row above produces a valid Layer-1 Bearer token, Layers 2–4 behave **identically** regardless of which credential produced it. This is structurally different from AWS (where credential type determines the entire `putCredentials` path) and GCP (where credential type forks the whole session into the Public or Private path, §1 of the GCP protocol record) — Azure's credential-type differences are fully absorbed at Layer 1, and everything downstream of it is credential-agnostic. The one documented exception is the **Portal-only WebSocket path** (`wss://ux.console.azure.com`), which *does* check `appid` and requires it to be `b677c290-cf4b-4a8e-a60e-91ba650a4abe` (Azure Cloud Shell) specifically — but that path is only reachable by the real Azure Portal, not by this runner's own emulation, which always uses the Service Bus relay path (Layer 3, top branch).

<a id="id-section-2"></a>
## 2. Container Lifecycle


<a id="id-section-2-1"></a>
### 2.1 Where `$HOME` actually lives


`$HOME` is **neither a directory on the file share nor container-local storage.** It is a ~5 GB **ext2 disk image** on the share, loop-mounted into place at container start

| Path | Filesystem | What it actually is |
|---|---|---|
| `$HOME` = `/home/<user>` | **`ext2`** | `/dev/loop0`, backed by `.cloudconsole/acc_<user>.img` — a **disk image ON the file share** |
| `/usr/csuser/clouddrive` | **`cifs`** | the Azure File Share itself — the container's **only** network mount |
| `~/clouddrive` | symlink | → `/usr/csuser/clouddrive` |

```
/dev/loop0: [0113]:13835128424026341376 (/usr/csuser/clouddrive/.cloudconsole/acc_s2.img)
```

**Why the indirection exists**: SMB cannot express POSIX ownership, permission bits or symlinks. A loop-mounted ext2 image gives a real POSIX filesystem whose bytes happen to travel over SMB.

**Four consequences, each stated once and referenced elsewhere:**

| | |
|---|---|
| **`$HOME` is persistent** | the image outlives every container. [§2.2](#id-section-2-2) has the measured survival matrix |
| **`userSettings.diskSizeInGB: 5`** | is the size of that image, not of a quota ([§3](#id-section-3)) |
| **`$HOME` is opaque to Azure Files** | one `.img` blob, so file-level soft delete cannot recover anything inside it (§1.1) |
| **No mount ⇒ silent `overlay`** | without `listKeys/action` the shell still starts and `$HOME` degrades to ephemeral with no error (§1.1, and Claim B) |


<a id="id-section-2-2"></a>
### 2.2 What survives a lifecycle event


| Path | After a RESTART | After a 20-min IDLE RECYCLE |
|---|---|---|
| `/tmp`, `/var/tmp` | **destroyed** | *inferred* destroyed — see below |
| `$HOME`, `$HOME/.ssh`, `$HOME/.azure` | **survive** | **survive** |
| `$HOME/clouddrive` | **survives** | **survives** |

**Restart and idle recycle are indistinguishable on this measure.** Both tear the container down — `POST /terminals` 4,723 ms and 4,746 ms respectively, against 209 ms for a warm re-attach — and both preserve everything backed by the share.


**Two operator-facing commands, and BOTH are misnamed — in opposite directions:**

| Command | Sounds like | Actually does |
|---|---|---|
| **Reset user settings** | a wipe | deletes the **pointer**; every file survives |
| **`clouddrive unmount`** | a scoped, reversible unmount | **deletes the storage binding and kills the session** |

Neither a *Reset user settings* action nor `clouddrive unmount` removes files from `$HOME`. After the storage binding was restored, `$HOME`, `$HOME/.ssh`, `$HOME/.azure` and `$HOME/clouddrive` remained intact; only container-local paths were lost when the container was recycled. Persisted data is removed only by deleting the file share or its `acc_<user>.img` image.


- **"Console"** = an ACI (Azure Container Instance) container (`cc-{4CHAR}-{8HEX}`), provisioned via `PUT /consoles/default` — note the **fixed singular name** `default`; the API doesn't appear to support multiple concurrent consoles per identity.
- **"Terminal"** = a lightweight PTY inside the console; many terminals can run concurrently within one console (10 observed in one capture), all sharing one Azure-File-Share-backed `$HOME`.

**Environment Lifecycle**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Console States                                                         │
│                                                                         │
│  [Not Provisioned] ──PUT──► [Provisioning] ──~30-60s──► [Succeeded]     │
│                                                              │          │
│                                                         [In Use]        │
│                                                              │          │
│                                         20min idle or DELETE─►[Recycled]│
│                                                              │          │
│                                              PUT ◄───────────┘          │
│                                          (reprovision)                  │
└─────────────────────────────────────────────────────────────────────────┘
```

**Console and terminal lifecycle:** an idle timeout or platform-side recycle can end a console session or replace its container. The protocol does not expose a reliable read-only status check for this state. Reopening uses the console `PUT` response to distinguish a newly created console (`201`) from an update/reuse (`200`), then creates a fresh terminal with `POST /terminals`. Terminal IDs are one-time-use and are not reused after a reconnect. A platform recycle and an idle recycle are not distinguishable from the client solely by the terminal handle.

**Console vs. Terminal — relationship tree**

```
Identity (user / service principal)
  └── Console  (1 ACI container, /consoles/default)
        ├── Terminal A  (PTY, 32-hex ID, WebSocket → ux.console.azure.com)
        ├── Terminal B  (PTY, 32-hex ID, WebSocket → ux.console.azure.com)
        └── Terminal C  (...)
              │
              └── All share: /home/{user}  (an ext2 image stored on the share)
```

One console can host multiple independent terminal PTYs; each `POST /terminals` creates a separate terminal session. The API path names a single console resource (`/consoles/default`), so this interface does not provide a collection of consoles for one identity.


<a id="id-section-2-3"></a>
### 2.3 Environment status

Azure Cloud Shell does not expose a read-only console-status endpoint. `GET /providers/Microsoft.Portal/consoles/default` has returned `404` both when a console exists and when it does not, so the response is not a state indicator. The `PUT` response is the available lifecycle signal: `201` indicates creation and `200` an update/reuse. Because `PUT` can create or update the console, it is a mutating operation, not a status probe. `POST {console.uri}/terminals` creates a new PTY; it reports terminal availability, not a non-mutating view of console state.

| Operation | Observed result | What it tells the caller |
|---|---|---|
| `GET /providers/Microsoft.Portal/consoles/default` | `404` in sampled calls, including after successful creation | Does not indicate whether a console exists or is ready |
| `PUT /providers/Microsoft.Portal/consoles/default` | `201` for creation; `200` for update/reuse | Creates or refreshes the console resource |
| `POST {console.uri}/terminals` | Creates a new terminal and returns its connection details | Opens a PTY; the terminal ID is not a reusable console-status handle |
| `DELETE /providers/Microsoft.Portal/consoles/default` | Deletes the console resource | Lifecycle action, not a status query |

No separate read-only console enumeration or status call has been established for this API.

<a id="id-section-3"></a>
## 3. REST API

The Azure Cloud Shell flow uses ARM for user settings and console lifecycle, then a console HTTP API and WebSockets for terminal access. Its main sequence is

| Step | Method / endpoint | Tier | Authorization | Purpose |
|---|---|---|---|---|
| 1 | `GET` or conditional `PUT /providers/Microsoft.Portal/userSettings/cloudconsole` | ARM | Delegated ARM bearer | Read or initialize shell preferences |
| 2 | `PUT /providers/Microsoft.Portal/consoles/default` | ARM | Delegated ARM bearer | Create or reuse the user's console; response includes its URI |
| 3 | `POST {console.uri}/terminals` | Console HTTP | ARM bearer and Portal `Referer` | Create a terminal PTY and return a one-time terminal ID |
| 4 | `POST {console.uri}/authorize` | Console HTTP | ARM bearer and Portal `Referer` | Obtain the opaque token used for relay WebSocket authentication |
| 5 | WebSocket to the console relay; terminal and `/control` channels | Service Bus relay | Opaque authorization token | Carry terminal traffic and control messages |
| 6 | Repeating `POST {console.uri}/keepAlive` | Console HTTP | ARM bearer and Portal `Referer` | Maintain the active console session |

File transfer uses additional console HTTP calls: upload posts a multipart body; download uses a request followed by a separate transfer response. The `/control` channel may carry transfer metadata. See [§5](#id-section-5).
<a id="id-section-3-1"></a>
### 3.1 The `userSettings` document, in full


`put_user_settings` existed in cloudbasher with **zero callers and no recorded body shape**, and no source in the corpus documented one. Captured at `PUT /providers/Microsoft.Portal/userSettings/cloudconsole?api-version=2023-02-01-preview`

```json
{"properties": {
  "networkType": "Default",
  "preferredLocation": "westus",
  "preferredOsType": "linux",
  "preferredShellType": "pwsh",
  "sessionType": "Mounted",
  "storageProfile": {
    "diskSizeInGB": 5,
    "fileShareName": "cs-<masked>",
    "storageAccountResourceId": "/subscriptions/<sub>/resourcegroups/<rg>/providers/Microsoft.Storage/storageAccounts/<acct>"
  },
  "terminalSettings": {"fontSize": "medium", "fontStyle": "monospace"},
  "userSubscription": "<sub>",
  "vnetSettings": null
}}
```

**This document is the entire binding between a user and their storage** — one `GET` plus one `PUT` is a complete backup and restore of it (§1.1, DR).

#### Region contract — configuration, placement, and scope

`preferredLocation` is the Azure Cloud Shell **placement preference**, not an AWS-style per-command region selector. The console ARM resource itself is tenant-scoped — `PUT /providers/Microsoft.Portal/consoles/default` has neither a subscription nor a location in its URL — so one console request does not fan out across regions.

| Question | Observed protocol answer | Client contract |
|---|---|---|
| Where is the value sent? | `userSettings.properties.preferredLocation` (for example, `westus`). | A clean-state credential's `region` populates this field only while creating absent `userSettings`; existing settings are preserved. |
| Does it affect provisioning? | Yes, directly for **Mounted** setup: the native portal creates/adopts `cloud-shell-storage-{region}` and creates that resource group with body `{"location":"{region}"}`. | Treat it as material setup state, not display-only metadata. |
| What about **Ephemeral**? | The observed ephemeral body still carries `preferredLocation` and `userSubscription`, but carries no `storageProfile` and makes no storage calls. `preferredLocation` is therefore required configuration shape here, not observed evidence of a storage-location decision. | Supply one Azure location plus one subscription; do not infer a mounted storage location or a compute-location guarantee from an ephemeral console. |
| Does it prove the container's physical location? | No. The service returns a global console resource; relay-host grammars sometimes encode a region and sometimes do not. | Report a parsed relay region only as a diagnostic. Do not claim a hard placement/isolation guarantee from the configured value alone. |
| Is subscription the same thing? | No. `userSubscription` selects the subscription/storage or service context; `preferredLocation` selects the Azure location preference. | Require and track both independently. |

For CloudBasher's `creds.rc`, `region=westus` therefore means **one initial Azure Cloud Shell location preference**. It is neither `all`, a comma-separated set, nor a request for one environment per region. `vnetSettings.location`, when present for an isolated console, is separately the VNet's location — not the Cloud Shell location.


Three fields no source mentions at all: **`diskSizeInGB`** (5 — the size of the ext2 image, [§2](#id-section-2)), **`networkType`/`vnetSettings`**, and **`userSubscription`**.

<a id="id-section-4"></a>
## 4. WebSocket Protocol


Azure's terminal transport is the simplest of the three CSPs: plain UTF-8 text frames (WebSocket opcode `0x1`) carrying raw PTY output and ANSI sequences, with **no binary framing at all** — unlike AWS's 116-byte SSM binary header or GCP's binary-tunneled SSH. There is nothing to byte-parse; a text frame's payload is exactly what the PTY produced.

Two, mutually exclusive upgrade paths exist, both created by the same `POST /terminals` call ([§3](#id-section-3))

1. **Service Bus relay** (all clients) — `wss://{relay_host}/$hc/{console_path}/terminals/{TERMINAL_ID}`. Auth is `Cookie: auth-token={opaque}` (from `POST /authorize`, [§7](#id-section-7)); no `Authorization` header at all.
2. **Portal-only path** (`b677c290-cf4b-4a8e-a60e-91ba650a4abe` (Azure Cloud Shell) tokens only) — `wss://ux.console.azure.com//{TERMINAL_ID}`. Auth is `Authorization: Bearer {Azure Cloud Shell token}` directly; any other `appid` gets HTTP 503. Emulation code should always use path 1 — `socketUri` from the terminal-creation response points at path 2 and only works for portal-issued tokens.

Terminal IDs are 32-character lowercase hex, one-time-use — every terminal creation call (including `-m/--resume`) mints a fresh ID; there is no "reconnect to the same terminal ID" concept, unlike a resumable session ID.

Once connected, a short in-band bootstrap (`export CLICOLOR_FORCE=1 FORCE_COLOR=1` → drain → printf marker probe) confirms shell readiness — see the Cold Start diagram in [§7](#id-section-7). Resize is a separate out-of-band REST call, not a WebSocket control frame — contrast AWS, which resizes via a binary WebSocket frame.


<a id="id-section-4-1"></a>
### 4.1 There is a SECOND WebSocket per terminal


**Both this document and the reference implementation describe one socket per terminal. There are two.**

```
wss://{relay}/$hc/{console_path}/terminals/{TERMINAL_ID}            <- the PTY (documented)
wss://{relay}/$hc/{console_path}/terminals/{TERMINAL_ID}/control    <- undocumented
```

A session with two terminals opened **two `/control` sockets**, one per terminal — so it is scoped **per-terminal, not per-console**.


cloudbasher opens only the PTY socket. Whether that is *sufficient* is untested; it has reached a live shell many times without the control socket, so it is not required for the happy path.

<a id="id-section-4-2"></a>
### 4.2 Neither the console id nor the relay host is a stable handle

The console URI and relay host are temporary connection details. The only way to obtain a current `console.uri` is to `PUT /consoles/default`; because that request can create or refresh the console, clients should not treat it as a read-only status check or persist the returned URI across restarts.
<a id="id-section-4-3"></a>
### 4.3 The terminal expects a real emulator on the wire


Everything above describes the *transport*. This describes what the container expects of whatever is on the other end of it, and it is the gap between "we can read and write text frames" and "we can drive this shell".


**The prompts, with actual bytes at last.**

| Shell | Prompt, ANSI-stripped | Matches `[\$#]\s*$`? |
|---|---|---|
| bash | `<user> [ ~ ]$` | **yes** |
| pwsh | `PS /home/<user]> ` | **NO** |

The bash prompt is **not** `user@host:~$` — Azure CloudShell ships a custom `PS1` of the form `<user> [ <cwd> ]$`. It still ends in `$`, so a trailing-character regex holds, but anything matching on the *shape* `user@host` fails. This was recorded as a known limitation and is now *observed*.

**Device Status Report — the container asks where the cursor is, 19 times.**

The container sends `ESC[6n` (DSR) and expects `ESC[<row>;<col>R` back. In one captured session that happened **19 times** and the browser's xterm.js answered every one

```
recv containing ESC[6n            : 19
sent matching ESC[<row>;<col>R    : 19
```

`grep -rn '\[6n' src/cloudbasher/` finds **no responder anywhere** — not in the implementation, not in `csp/aws/`, not in `core/`. cloudbasher reads and writes text; it does not emulate a terminal on the wire.


**PSReadLine echoes per CHARACTER, and that — not the prompt regex — is what breaks completion detection.** The sent side of typing `pwd`, then `Get-L…`

```
'\x1b[21;1R', '\x1b[21;18R', 'p', 'w', '\x1b[21;19R', 'd', '\x1b[21;20R', '\r',
'\x1b[26;1R', '\x1b[26;18R', 'G', 'e', '\x1b[26;19R', 't', '\x1b[26;20R', '-', ...
```

The received echo colours each character individually (`\x1b[0m\x1b[93mp`), interleaved with absolute cursor moves like `\x1b[21;18H`. `AzureSession._is_complete` requires the echoed command to be present before accepting a prompt match — and under PSReadLine the echo is not a contiguous line. It is one character per frame, syntax-coloured, repainted by absolute cursor positioning, and interleaved with DSR replies. `strip_ansi` may reassemble the characters; **nothing guarantees they arrive in source order** once the shell starts repainting.

**Consequence, and it is a design conclusion rather than a bug report: PowerShell support is not "widen the prompt regex".** It needs a terminal emulator on the *protocol* side. `pyte` is already a dependency and already instantiated — in the implementation, on the **display** side. Tracked as, and shared with, which needs the same emulator for a different reason.

**The container also talks about itself.** The pwsh banner carries `Your Cloud Shell session will be ephemeral so no files or system changes will persist beyond your current session.` — independent confirmation of `sessionType` ([§2](#id-section-2)) from inside the container rather than from the ARM request body. The two agree, which is what makes `sessionType` trustworthy as *the* persistent-vs-ephemeral switch.

Also in that banner stream, and mentioned nowhere else in the corpus: pwsh auto-runs `Connect-AzAccount` (`VERBOSE: Authenticating to Azure...`) and warns `TenantId '<tid>' contains more than one active subscription. First one will be selected` — **a silent subscription selection happening inside the container**, independent of whatever subscription the caller used to provision it.

<a id="id-section-5"></a>
## 5. File Transfer


- **Upload**: multipart POST with a **browser-randomised** boundary and a required field name `uploading-file` — the field name is undocumented publicly and capture-derived; the boundary is the stock `----WebKitFormBoundary`+16 form, different in all three captured uploads. This document described it as *fixed* until 2026-09-07: that was the reference implementation client's constant, not the service's requirement. **Upload emits no WebSocket control frame** — unlike download, everything the client needs is in the HTTP response.
- **Download**: **three-step, and the middle step is on the terminal's companion `/control` WebSocket**
- No presigned-S3-style URLs, no SSE-C key material — structurally simpler exposure model than AWS's file-transfer threat surface, but the fixed multipart boundary is itself a minor fingerprinting/CSRF-adjacent quirk worth noting if this is ever reused defensively.

**Sequence diagrams**

```
Upload:  Client → POST /terminals/{TID}/upload
                   Content-Type: multipart/form-data; boundary=(FIXED, non-random)
                   field name MUST be "uploading-file" (undocumented, capture-derived)
                 ← {path, size, ...}  (200)

Download: Client → POST /terminals/{TID}/download   body {"filename": "/home/user/f.txt"}
                  ← {"filepath", "fileUri", "audience":"download"} on terminal /control
                  ← 200, Content-Length: 0
          Client → GET {console.uri}{fileUri}
                  ← <file bytes>  (200)
```

The former `NOT OBSERVED` labels are superseded by 's end-to-end Service Bus arm. The relative-path rule is still a client contract: Azure upload/download acceptance is bounded to the returned home directory, and CloudBasher resolves relative destinations there. **Upload and directory listing work**; download now has a live-verified relay path. Directory listing is a plain `GET {console.uri}/files/{url-encoded-path}` (empty directory → ``; non-existent path → `404`).

<a id="id-section-5-1"></a>
### 5.1 The bodies, captured


| Call | Body |
|---|---|
| `POST {relay}/cc-<id>/terminals/<tid>/upload` | multipart — **not recoverable from Playwright's `post_data`**, so the fixed-boundary claim above remains reference implementation-sourced, not re-observed |
| ← response | `{"message": "File uploaded successfully", "path": "/home/<user>"}` |
| `POST {relay}/cc-<id>/terminals/<tid>/download` | `{"filename": "/home/<user>/HELLO.txt"}` |

Both are **terminal**-scoped, not console-scoped — the path carries `/terminals/<tid>/`. The download request body confirms the reference implementation's documented shape exactly; **the upload response is new** and was recorded nowhere.

`GET /files/<path>` returns an array, and this is the shape `list_directory` should be parsing

```json
[{"isFolder": true,  "name": ".azure",        "uri": "/files/home/<user>/.azure"},
 {"isFolder": false, "name": ".bash_history", "uri": "/files/home/<user>/.bash_history"}]
```


<a id="id-section-6"></a>
## 6. Credential Types

**Carved out 2026-09-08** from material that already existed in this document but was scattered across [§7](#id-section-7) and [§9](#id-section-9). Nothing here is new: the per-endpoint detail, the observations behind each row and the app-ID allowlist analysis stay where they are, and this section is the overview the template asks every bible to carry.

**Every credential type answers the same question — what mints the Bearer token, and does it keep minting one?** Azure has no equivalent of AWS's SigV4 signing key: every path ends in an OAuth Bearer token for the ARM audience, and the types differ only in how that token is obtained and whether it renews.

| Starting credential | How the Bearer is obtained | Auto-refresh | Reaches CloudShell |
|---|---|:---:|:---:|
| **Refresh token** | MSAL `acquire_token_by_refresh_token` | yes, sliding | yes |
| **OAuth browser (3LO)** | MSAL `acquire_token_interactive` | yes | yes |
| **OAuth device code** | MSAL `acquire_token_by_device_flow` | yes | yes |
| **Azure CLI** | `az account get-access-token` | no — one-shot | yes |
| **Access token only** | used directly, nothing acquires it | no — ~1 h, then dead | while unexpired |
| **Service principal** (`client_id` + `client_secret`) | MSAL `acquire_token_for_client` | yes | **NO — refused** |
| **Environment variables** (`AZURE_CLIENT_*`) | MSAL `acquire_token_for_client`, service principal by another name | yes | **NO — same refusal** |

**The load-bearing fact, and it is the opposite of what every source recommended.** A service principal — the one credential type a reader would reach for to automate anything — **cannot reach CloudShell**,. The refusal is an **app-ID allowlist**, not a permissions problem: a token minted by the wrong client id is refused on the stream endpoint even when its holder can see the subscription and the token carries the right audience.

**Measured width: 2 of 23.** Of twenty-three first-party app ids that will mint a valid user-context ARM token, two get past the CloudShell gate — the **Azure CLI** (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) and **Visual Studio** (`aebc6443-996d-45c2-90f0-388ff96faa56`). Both names are Microsoft's own. The practical consequence is that a non-interactive Azure automation must borrow one of those two client ids, or hold a refresh token minted under one.

**And the gate is a DISCOVERY control, not an access control.** A token the gate refuses still reaches a live shell if the caller already holds a console `uri` obtained some other way. What the allowlist prevents is *finding* the console, not *using* it — which is the distinction that matters when reasoning about it as a security boundary.

**Two things this section deliberately does not settle.** Whether the allowlist is a Microsoft-side default or a locally configurable tenant policy is undistinguished — one tenant cannot tell those apart. And the per-endpoint breakdown of which token type satisfies which call lives in [§7](#id-section-7), because it is an authentication-flow property rather than a credential-type one.

<a id="id-section-7"></a>
## 7. Authentication Flows


#### CloudBasher implementation status per credential type — **the table lives in [§9](#id-section-9)**

The tables in this section describe the **protocol**. Whether *this codebase* completes each of them end to end is a separate question, and it is tracked in **[§9](#id-section-9), "CloudBasher implementation status per credential type"** — one table, not two. As of 2026-08-29 the refresh-token and access-token flows are both *observed* reaching a live shell.

That distinction is not pedantry. the corresponding document carried "Confirmed" against its console-login row for months while the path could not complete a single run — the protocol claim was true and the implementation claim was false, and nothing in the doc separated them. Four defects and three failed debugging attempts followed. See `the protocol record-aws.md` §2.2, "CloudBasher implementation status per credential type", for the shape this table should take once each Azure credential type has actually been exercised

Rules for filling it, learned the expensive way

- Mark every cell **observed** / **inferred** / **open**. An inference recorded as a finding is what cost the AWS debugging its three wasted attempts.
- "The code has a branch for it" is not *observed*. Reaching a working shell is.
- A credential type refused at the source boundary is a legitimate row, not a gap — say so and say why.
- Update this in the same change as the code, not afterwards.

*(This section covers both the wire-level mechanics of the token exchange and the authorization/credential-acquisition angle — which credential you start with, how it's classified, and which app IDs/flags select which path. These used to be split across two top-level sections; they're merged here because in practice a reader needs both views together to reason about any one credential path.)

- **Entra ID / OAuth2 via MSAL** — not SigV4, not Google-style cookies.
- **Two-step, decoupled WebSocket auth** (Azure-unique)
 1. `POST {console.uri}/authorize` with the ARM Bearer JWT → returns an opaque ~81-character token.
 2. That opaque token is sent as `Cookie: auth-token={opaque}` on the Service Bus relay WebSocket — **no `Authorization` header at all** on that connection.
- A **separate portal-only path** (`wss://ux.console.azure.com//{TID}`) uses `Authorization: Bearer` directly, but only accepts tokens issued to client_id `b677c290-cf4b-4a8e-a60e-91ba650a4abe` (the first-party Azure Cloud Shell confidential app) — tokens from any other app ID get HTTP 503.
- Terminal creation pins `version=2019-01-01` in the querystring — a protocol version **frozen independently of** the ARM API version (`2023-02-01-preview`). Don't conflate the two when porting/upgrading.
- Terminal IDs are 32-character lowercase hex, one-time-use — even `-m/--resume` always issues a fresh `POST /terminals` call; there's no "reconnect to the same terminal ID" concept.

**⚠️ Footgun — mandatory `Referer` header:** every console-tier call (`POST /terminals`, `POST /authorize`, `POST /keepAlive`, file ops) **requires** `Referer: https://portal.azure.com/` in addition to the Bearer token. Omitting it does not produce a clean 401/403 — it produces an **HTTP 500**, which looks like a server-side fault rather than a client-side header omission. This is the single easiest way to break an Azure CloudShell emulation and get a misleading error in return.

<a id="id-section-7-1"></a>
### 7.1 Token properties

| Property | Value |
|---|---|
| Type | Azure AD JWT (Bearer) |
| Scope | `https://management.core.windows.net//.default` |
| Audience (`aud` claim) | `https://management.core.windows.net/` |
| Lifetime | ~3600 seconds (1 hour) |
| Refresh window | Proactive refresh when < 300s remaining |

The scope deliberately uses the **legacy** ARM resource name `management.core.windows.net`, not `management.azure.com` — the console validates the `aud` claim and rejects `management.azure.com`-audience tokens. The double slash in `management.core.windows.net//.default` is intentional: the resource is registered with a trailing slash, so appending `/.default` produces `//default`.

<a id="id-section-7-2"></a>
### 7.2 Per-endpoint token requirements

| Endpoint | Accepts 04b07795-8ddb-461a-bbee-02f9e1bf7b46 | Accepts 04b07795-8542-4c4c-9cb8-f0f09d69f25f | Accepts 1950a258-227b-4e31-a9cf-717495945fc2 | Accepts b677c290-cf4b-4a8e-a60e-91ba650a4abe | Accepts SP |
|---|:---:|:---:|:---:|:---:|:---:|
| ARM `GET /userSettings` | ✓ | ✓ | ✗ ClientNotAllowed | ✓ | ✓ (with perms) |
| Console `POST /terminals` | ✓ | ✓ | untested | ✓ | likely ✓ |
| Console `POST /authorize` | ✓ | likely ✓ | untested | ✓ | likely ✓ |
| Console `GET /keepAlive` | ✓ | likely ✓ | untested | ✓ | likely ✓ |
| Console file ops | ✓ | likely ✓ | untested | ✓ | likely ✓ |
| Service Bus WebSocket | auth-token cookie | auth-token cookie | — | auth-token cookie | auth-token cookie |

The Service Bus WebSocket does **not** use the Bearer token directly — only the opaque `auth-token` obtained from `POST /authorize`; the Bearer token's appid is irrelevant once the auth-token is obtained.

<a id="id-section-7-3"></a>
### 7.3 Cold Start

A cold start provisions a new console (or reuses an existing one) and opens a PTY.

```
Client                      ARM                    Console API (relay)         WebSocket
  │                          │                          │                          │
  │  GET /userSettings       │                          │                          │
  │─────────────────────────►│                          │                          │
  │◄─────────────────────────│  {region, shell}         │                          │
  │                          │                          │                          │
  │  GET /consoles/default   │   (portal does this and  │                          │
  │─────────────────────────►│    IGNORES the answer)   │                          │
  │◄─────────────────────────│  404 ALWAYS  (AZ-OBS-201)│                          │
  │                          │                          │                          │
  │  PUT /consoles/default   │                          │                          │
  │─────────────────────────►│                          │                          │
  │◄─────────────────────────│  201 created / 200 update│                          │
  │                          │  {uri, state: Succeeded} │                          │
  │  NO POLL: the PUT returns Succeeded synchronously   │                          │
  │                          │                          │                          │
  │  POST /cc-{ID}/terminals?cols=220&rows=50&version=2019-01-01&shell=bash        │
  │────────────────────────────────────────────────────►│                          │
  │◄────────────────────────────────────────────────────│                          │
  │  {id, socketUri, idleTimeout, tokenUpdated, rootDir}│                          │
  │                          │                          │                          │
  │  POST /cc-{ID}/authorize (Bearer token)             │                          │
  │────────────────────────────────────────────────────►│                          │
  │◄────────────────────────────────────────────────────│  {"token": "OPAQUE"}     │
  │                          │                          │                          │
  │  WebSocket upgrade wss://{relay}/$hc/cc-{ID}/terminals/{TID}                   │
  │  Cookie: auth-token=OPAQUE                          │   ──────────────────────►│
  │                                                     │             101 Switch ◄─│
  │  banner + ANSI (Welcome to Azure Cloud Shell)       │                    ◄─────│
  │  export CLICOLOR_FORCE=1  ────────────────────────────────────────────────────►│
  │  printf marker ───────────────────────────────────────────────────────────────►│
  │  {marker echo, prompt}  ◄──────────────────────────────────────────────────────│
  │  [shell ready]           │                          │                          │
```

<a id="id-section-7-4"></a>
### 7.4 Hot Reconnect — existing console, new terminal


```
Client                      ARM                    Console API (relay)         WebSocket
  │  PUT /consoles/default   │   (GET returns 404)      │                          │
  │─────────────────────────►│                          │                          │
  │◄─────────────────────────│  200 = it pre-existed    │                          │
  │                          │                          │                          │
  │  POST /cc-{ID}/terminals?...                        │                          │
  │────────────────────────────────────────────────────►│                          │
  │◄────────────────────────────────────────────────────│  {id, socketUri}         │
  │                          │                          │                          │
  │  POST /cc-{ID}/authorize                            │                          │
  │────────────────────────────────────────────────────►│                          │
  │◄────────────────────────────────────────────────────│  {"token": "OPAQUE"}     │
  │                          │                          │                          │
  │  WebSocket upgrade (Service Bus, Cookie: auth-token=OPAQUE)             ──────►│
  │  [banner, prompt, ready]                            │                   ◄──────│
```

Hot start: ~1-2 seconds vs. 30-60s for cold provisioning.

<a id="id-section-7-5"></a>
### 7.5 Portal Flow — `b677c290-cf4b-4a8e-a60e-91ba650a4abe` (Azure Cloud Shell) tokens only

The Azure Portal uses a different WebSocket path that bypasses the Service Bus relay

```
  │  POST /cc-{ID}/terminals?...  → {id, socketUri=wss://ux.console.azure.com//TID}
  │  WebSocket upgrade wss://ux.console.azure.com//{TID}
  │  Header: Authorization: Bearer {Azure Cloud Shell token}
```

This path is **not available** to non-portal tokens — `ux.console.azure.com` returns HTTP 503 for any `appid` other than `b677c290-cf4b-4a8e-a60e-91ba650a4abe` (Azure Cloud Shell). Do not use `socketUri` from the terminal creation response when emulating; always use the Service Bus relay URL constructed from `console.uri`.

**Credential-dependency chain** — everything above ultimately hangs off one Bearer token

```
Starting credential
    │
    ▼
Bearer access_token  (aud=management.core.windows.net/)
    │
    ├──► ARM management.azure.com      (GET/PUT /consoles, GET /userSettings)
    ├──► Console HTTP API              (POST /terminals, GET /keepAlive, file ops)
    └──► POST {console.uri}/authorize
              │
              ▼
         opaque auth-token  (~81 chars, not a JWT)
              │
              ▼
         WebSocket upgrade
         Cookie: auth-token=OPAQUE
```

<a id="id-section-7-6"></a>
### 7.6 Credential-type support matrix

| Starting credential | CLI flag | How Bearer token is obtained | Token appid | Auto-refresh | ARM + Console HTTP | WebSocket (via `/authorize`) |
|---|---|---|---|:---:|:---:|:---:|
| Service principal (client_id + client_secret) — **BLOCKED, | `-F file.json` | MSAL `acquire_token_for_client` (client_credentials grant) | your SP's client_id | ✓ token acquisition works | ✗ **`ClientNotAllowed` at `Microsoft.Portal`** — the app id is refused before RBAC is consulted; Contributor does not help | ✗ |**
| Refresh token | `-F file.json` | MSAL `acquire_token_by_refresh_token` | client_id in file (default 04b07795-8ddb-461a-bbee-02f9e1bf7b46) | ✓ (sliding refresh_token rotation) | ✓ | ✓ |
| Access token only | `-F file.json` | Direct use — no acquisition | token's own appid | ✗ (expires in ~1hr, no refresh) | ✓ while not expired | ✓ while not expired |
| Environment vars (`AZURE_CLIENT_*`) | auto | MSAL `acquire_token_for_client` (SP via env) | `AZURE_CLIENT_ID` value | ✓ | ✓ (same as SP file) | ✓ |
| OAuth browser (3LO) | (default, no `-F`) | MSAL `acquire_token_interactive` | 04b07795-8ddb-461a-bbee-02f9e1bf7b46 | ✓ (refresh_token returned) | ✓ | ✓ |
| OAuth device code | (fallback, no `-F`) | MSAL `acquire_token_by_device_flow` | 04b07795-8ddb-461a-bbee-02f9e1bf7b46 | ✓ (refresh_token returned) | ✓ | ✓ |
| Azure CLI | `--az-cli` | `az account get-access-token` | 04b07795-8542-4c4c-9cb8-f0f09d69f25f | ✗ (one-shot; re-run az manually) | ✓ where 04b07795-8542-4c4c-9cb8-f0f09d69f25f not tenant-blocked | ✓ |


<a id="id-section-7-7"></a>
### 7.7 App ID reference — auth-flow view

This is a concise, auth-flow-centric view of client IDs used by Azure Cloud Shell-related sign-in flows. The complete UUID catalog in Appendix E classifies identifiers found in the Portal bundles; this table focuses on clients with relevant authentication behavior.

| App name | Client ID | Type | Notes |
|---|---|---|---|
| Azure Cloud Shell | `b677c290-cf4b-4a8e-a60e-91ba650a4abe` (Azure Cloud Shell) | **Confidential** | Portal's own app; requires `client_secret`; cannot be used via public client flows |
| WAM Broker / Azure Portal | `c44b4083-cba6-42be-8e29-b9702cdde539` (Azure Portal / WAM broker) | Confidential | Same FOCI family as b677c290-cf4b-4a8e-a60e-91ba650a4abe; used by Windows WAM |
| **Azure CLI** | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI) | **Public**, FOCI | Works for CloudShell ARM API. the Azure CLI is a well-known FOCI family member, and the matrix below says so. What was observed is that swaps *from* it returned `AADSTS70000` — *invalid grant*, not the documented FOCI denial `AADSTS50158` — consistent with the cached RT lacking the `foci=1` claim, not with non-membership |
| **Windows Terminal** | `245e1dee-74ef-4257-a8c8-8208296e1dfd` | Public client | Windows Terminal's Cloud Shell profile uses device-code sign-in and the ARM audience; it passed the Cloud Shell user-settings authorization check in a live test. FOCI membership is unconfirmed. |
| **UNVERIFIED** — identity never established | `04b07795-8542-4c4c-9cb8-f0f09d69f25f` | unknown | Was labelled "Azure CLI"; that name belongs to the row above. Almost certainly meant `b677c290-cf4b-4a8e-a60e-91ba650a4abe` (Azure Cloud Shell). Blocked by some tenants (AADSTS700016) |
| Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` (Azure PowerShell) | Public, FOCI | Gets ARM tokens but **ClientNotAllowed** on CloudShell API endpoints |

<a id="id-section-7-8"></a>
### 7.8 FOCI family behavior, minimum privileges & app-ID matrix

**FOCI swap matrix** — the underlying data behind the "all 9 cross-app FOCI swaps fail" conclusion stated in §10 below

| Source client_id | Target client_id | Outcome |
|---|---|---|
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (cached RT) | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (self) | ✅ access_token issued |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI) | b677c290-cf4b-4a8e-a60e-91ba650a4abe (Cloud Shell, our actual goal) | ❌ AADSTS70000 |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI) | 9 other first-party apps | ❌ AADSTS70000 (all) |


**Minimum privileges per credential type**

| Credential type | What MSAL/AAD requires | What ARM RBAC requires for CloudShell | Cited from |
|---|---|---|---|
| Service Principal (`client_id`+`client_secret`+`tenant_id`) | Application registered in tenant; admin consent for the ARM scope `https://management.core.windows.net//.default`. | At minimum **Reader** on the subscription (for `GET /providers/Microsoft.Portal/userSettings/cloudconsole`). To **provision** a console you need **Contributor** or a custom role with `Microsoft.Portal/consoles/write`. The storage account backing the file share also needs `Microsoft.Storage/storageAccounts/listKeys/action` — **contested; see disagreement A1 in §1.1**, which contradicts this. | That capture's 200s are `GET /tenants` and `GET /subscriptions`; **both CloudShell endpoints returned 400** in the same file. The whole row is moot: see the ClientNotAllowed banner in §7. |
| Refresh token (3-legged user OAuth, post-login) | Client `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (or any FOCI-eligible client) registered multi-tenant; user has consented to the ARM scope. | User must have at least **Reader** on the subscription. Provisioning requires **Contributor** — same as SP. | [§1](#id-section-1)(a) captures `*_refresh_corporate.json`. |
| Access token only (`-F` JSON with `access_token`) | Any path that minted an ARM-audience token. No further AAD interaction. | Same RBAC rules as the principal who minted the token. | N/A — no MSAL involvement. |
| Console username/password | User present in the tenant; MFA satisfied (interactive only); Conditional Access must permit the originating IP/device. | Same as refresh-token — depends on the user's role assignment. Personal MSA accounts cannot create resources in a corporate tenant. | — not yet captured live. |

**First-Party App ID Matrix — cross-reference**. This adds FOCI-membership / device-code-acceptance / FOCI-swappability columns not present in the 21-UUID catalog in Appendix E — the two tables are complementary views of the same client IDs, not duplicates

| client_id | Confidential? | FOCI member? | Accepts device-code on `common`? | FOCI-swappable from cached `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI) RT? | Notes |
|---|:---:|:---:|:---:|:---:|---|
| `b677c290-cf4b-4a8e-a60e-91ba650a4abe` (Azure Cloud Shell) Cloud Shell | ✅ yes | ⚠ undocumented | ✅ yes | ❌ no (AADSTS70000) | Portal-bound; also reachable via Service Bus relay |
| `c44b4083-cba6-42be-8e29-b9702cdde539` (Azure Portal / WAM broker) Portal/WAM | ✅ yes | ⚠ same family as b677c290-cf4b-4a8e-a60e-91ba650a4abe | ❌ no (AADSTS50059) | ❌ no | Try tenant-specific authority to test multi-tenant behavior |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` **Azure CLI** *(was "MS Dev Tools", corrected 2026-08-28)* | ❌ no | ✅ yes | ✅ yes | ✅ yes (self) | Default `_MSAL_CLIENT_ID`; works for ARM + CloudShell ARM API |
| `245e1dee-74ef-4257-a8c8-8208296e1dfd` **Windows Terminal** | ❌ no | ? unconfirmed | ✅ yes | ? untested | Device-code Cloud Shell profile; observed to pass the Cloud Shell user-settings check |
| `04b07795-8542-4c4c-9cb8-f0f09d69f25f` **UNVERIFIED** *(was "Azure CLI", corrected 2026-08-28)* | ? | ? | ❌ no (AADSTS50059 on common) | ❌ no | Identity never established, so Confidential/FOCI are **unknown**, not "no". Tenant-blockable (AADSTS700016) |
| `1950a258-227b-4e31-a9cf-717495945fc2` Azure PowerShell | ❌ no | ✅ yes | ✅ yes | ❌ no | Returns ARM tokens but `ClientNotAllowed` on CloudShell ARM API |
| `04f0c124-f2bc-4f59-8241-bf6df9866bbd` (Visual Studio) Visual Studio | ❌ no | ✅ documented | ✅ yes | ❌ no | Discovered in MSAL Python sample app |
| `14d82eec-204b-4c2f-b7e8-296a70dab67e` (Microsoft Graph PowerShell) MS Graph PowerShell | ❌ no | ⚠ likely | ✅ yes | ❌ no | Microsoft Learn cite |
| `aebc6443-996d-45c2-90f0-388ff96faa56` (Visual Studio Code) VS Code | ❌ no | ⚠ likely | ✅ yes | ❌ no | Used by Azure Account ext |
| `1fec8e78-bce4-4aaf-ab1b-5451cc387264` (Microsoft Teams) MS Teams | ❌ no | ⚠ likely | ✅ yes | ❌ no | confirmation |
| `c7f5b65f-f7e6-485a-b1cf-c5e22f4dd8b0` (Azure Storage Explorer — unverified guess) | ? | ? | ❌ no (AADSTS50059) | ❌ no | Not in Microsoft Learn — classification was a guess |

<a id="id-section-7-9"></a>
### 7.9 Authorization flows (general, not CloudShell-specific)


| Flow | MSAL method | User? | SP? | FOCI-eligible? |
|---|---|:---:|:---:|:---:|
| Client Credentials | `acquire_token_for_client` | No | Yes | No |
| Refresh Token | `acquire_token_by_refresh_token` | Yes | No | Yes, if `foci=1` |
| Authorization Code + PKCE | `acquire_token_interactive` | Yes | No | Yes |
| Device Code | `acquire_token_by_device_flow` | Yes | No | Yes |
| On-Behalf-Of | `acquire_token_on_behalf_of` | Yes | No | No |
| Windows Broker (WAM) | `acquire_token_interactive(broker=True)` | Yes | No | Yes |

<a id="id-section-7-10"></a>
### 7.10 Portal Token Exchange


Sources: and. Four corrections and additions, none of which prior prose recorded.

| # | Finding |
|---|---|
| **Two token POSTs, not one** | The portal posts to `/organizations/` **and then** to a **tenant-specific authority**. A tenant-routing hop no source describes |
| **The scope carries three extra OIDC values** | `openid profile offline_access` alongside `https://management.core.windows.net//.default`. §7's scope is confirmed *exactly*; the three extras are new |
| **`GET /authorize` follows `POST /authorize`** | Only the POST is documented anywhere. The GET is a second, undocumented leg of the same exchange |
| **Call order is `consoles/default` THEN `userSettings`** | ⚠ **see the disagreement below** |
| **Portal entry and CloudShell refresh use different client IDs** | The initial observed PKCE exchange is `c44b4083-3bb0-49c1-b47d-974e53cbdf3c`; a later observed broker-qualified refresh is `b677c290-cf4b-4a8e-a60e-91ba650a4abe`. Both response shapes include redacted access/refresh-token fields. Generic native MSAL replay of the Portal SPA token is refused; separate browser-origin redemption has now succeeded for ARM, but not with the complete broker-qualified request. |
| **Fresh generic replay recheck** | A new Portal token response again yielded `AADSTS9002327` when the captured refresh token was submitted through native MSAL for the ARM scope. The authorization-code request's client ID matched the ARM access token's `appid`. |
| **Portal-origin SPA redemption** | A single JavaScript `fetch` from `https://portal.azure.com`, using that Portal client ID and the ARM scope, redeemed the captured refresh token successfully (HTTP 200). The returned delegated OAuth access token had the ARM audience and matching app ID; the response included a refresh-token field, but old/new values were not compared. This establishes browser-origin viability for this client/scope, not the full native broker-qualified Graph/EWS grant. |


Native Cloud Shell token exchange lets in-container Azure CLI requests obtain delegated access tokens for requested resource audiences through the Portal browser. Captures show a token-audience request on the terminal's `/control` channel, an Entra token exchange, and Console API requests to `/accessToken` and `/console-token`. The exact response path back to the local CLI broker—and the purpose of `/console-token`—remain unresolved, so this is not a complete wire-level account of the exchange.

CloudBasher handles a limited set of resource audiences and checks the token's tenant, client/app ID, audience, delegated scopes, and expiry before forwarding it to the Console API. Token values are not retained in control-frame history or logs. Product checks have passed for Microsoft Graph and Key Vault, but that does not establish full native-protocol emulation or support for arbitrary audiences. These are Entra-issued, delegated user tokens; their authority is constrained by audience and scopes and remains subject to tenant consent, Conditional Access, expiry, and revocation.

<a id="id-section-7-11"></a>
### 7.11 Personal MSA takes a different identity path


**A personal Microsoft account authenticates through `login.live.com`**, not through the work/school path, and it still reaches CloudShell. That matters because `_make_public_client_app` pins authority `.../organizations`, which by Microsoft's own definition **excludes personal MSA** — so the coverage claim that personal MSA works and the authority the code pins were in direct contradiction, unflagged, until this run.


**MSA tokens carry no `upn` claim.** They carry `idtyp`, `scp`, `tid` and `aud` and nothing that names the human. Any code deriving a display identity, a namespace key, or a log line from `upn` gets `None` on a personal account and must have a fallback — this is a different shape from the work/school token, not merely a missing optional field.

<a id="id-section-7-12"></a>
### 7.12 Azure CLI resource audiences

These results inform which service APIs are valid acceptance oracles; they do **not** by themselves establish CloudBasher product behavior or the complete Portal/local-broker wire contract.

| Service/data plane | Native CLI trigger | Requested resource / scope | Observed token `aud` | Native API result | v0.9 acceptance |
|---|---|---|---|---|---|
| ARM | `az resource list` / read-only `az rest` | ARM management resource | ARM resource | Confirmed | Yes |
| Microsoft Graph | `az ad signed-in-user show` | Graph | `https://graph.microsoft.com` | Confirmed | Yes |
| Key Vault data plane | `az keyvault secret list` | `https://vault.azure.net` | `cfa8b339-82a2-471a-a3c9-0fc0be7a4093` (resource application ID) | Confirmed | Yes; current probe lists metadata and emits only a count |
| Storage data plane | `az storage container list --auth-mode login` | Storage | `https://storage.azure.com/` | Confirmed | Additional regression candidate, not required by the selected three-leg matrix |
| Exchange / EWS | explicit EWS scope request | `https://outlook.office365.com/EWS.AccessAsUser.All` | Exchange audience observed, required EWS scope absent | EWS API returned `401 invalid_token` | No; do not use Exchange/EWS APIs as an acceptance oracle |

**Audience policy implementation.** The code keeps the requested resource separate from the issued JWT audience: the implementation maps an exact Key Vault HTTPS root request to `https://vault.azure.net/.default`, then validates the returned `aud` against the Key Vault resource ID above. This is a narrow evidence-backed allowlist, not support for arbitrary scopes. Key Vault data-plane success remains subject to delegated `user_impersonation`, tenant data-plane RBAC/policy, Conditional Access/MFA, expiry and revocation. No secret values are needed for the acceptance.

<a id="id-section-8"></a>
## 8. Sessions


Three session layers exist — the Entra ID sign-in session, the ARM/Console Bearer token, and the CloudShell console/terminal pair itself — each with its own lifetime, refresh mechanism, and revocation story.

**Session types, with trackability**

| Session type | Identifier | Auth mechanism | Lifetime | Trackable? |
|---|---|---|---|---|
| Entra ID sign-in session | Session ID in Entra ID | Bearer JWT + Conditional Access | Configurable (8h default) | Yes — Entra sign-in logs |
| ARM access token | JWT `exp` field | Bearer JWT | ~1 hour | Via ARM Activity Logs |
| Refresh token | Opaque, MSAL-cached | OAuth refresh grant | ~90 days sliding | Via Entra ID token logs |
| CloudShell console | Console ID (`cc-XXXX-...`) | ARM RBAC | Persistent until deleted | Via ARM Activity Logs |
| CloudShell terminal | Terminal ID (32-char hex) | Opaque auth-token cookie | 20-min idle timeout | Via ARM Activity Logs (terminal create) |
| WebSocket PTY session | Auth-token cookie | Service Bus relay | Tied to terminal lifetime | Not individually tracked in standard logs |

<a id="id-section-8-1"></a>
### 8.1 Heartbeat / idle / keepalive — SIX layers, and the one everyone defends was never observed to need it


Each row is a **different object with its own lifetime**. Conflating them is the failure this table exists to prevent.

| # | Layer | Lifetime | Held alive by | Observed / open |
|---|---|---|---|---|
| 1 | **Entra sign-in session** | ~8 h default, tenant-configurable | nothing in this protocol | *sourced*, §8 above |
| 2 | **ARM Bearer token** | ~1 h (`exp`) | **MSAL refresh only** — not a heartbeat. Refresh proactively at <300 s remaining or ARM starts 401ing | *observed* |
| 3a | **ARM console RECORD, never given a container** | **~102.5 min**, bounded `(102.1, 103.5]`. Eleven valid arms survived 15 → 102.1 min untouched; one record was dead by 102.5 min on the same principal | **nothing** — no keepalive of any kind exists at this layer, and none is needed | *observed*, tightening /. Timer-vs-sweeper **answered**: eleven survivals rule out any sweeper coarser than ~1 min, so the record has its own clock |
| 3b | **ARM console RECORD, after a container has existed** | **cliff in `(18, 22]`** when the container is left to die — alive at 18 min on two principals, gone at 22; the window straddles the container's own 20.00-min death. **Survives as long as its container does**: 22 min with a 1 Hz text frame flowing | nothing holds it directly, and nothing can be shown to — the socket dies ~46 s BEHIND its container, so a live-socket/dead-container state is not constructible | *observed*,. Cascade is *inferred*, not measured: a record clock landing inside `(18, 22]` is observationally identical, and with 's keepAlive lever measured at zero there is no arm that separates them |
| 4 | **The CONTAINER** (the ACI behind the record) | **20.00 min from terminal create when abandoned; ≥22 min when a 1 Hz empty TEXT frame is flowing.** Silence does NOT shorten it — 10 min of zero traffic re-attached warm in **247 ms** vs an 11.8 s cold create | Native evidence: an empty TEXT frame at 1 Hz held both for 22 min; `POST /keepAlive` moves the cliff by zero; an RFC6455 ping every 15 s also moves it by zero. **CloudBasher implements** the native-shaped text frame in a session-scoped worker. The owner later verified a long-running TUI session kept terminals usable across AWS, Azure, and GCP; this does not isolate the frame's causal role, extend the controlled 22-minute measurement, or establish a lifetime. **Frame type vs cadence is not yet separated** — `L4-22-ping1s` | *observed*,,,,. Max lifetime still *open* |
| 5 | **WebSocket / relay path** (`…-relay.servicebus.windows.net/$hc/…`) | intermediate proxy + NAT idle windows — **and in practice it does not outlive row 4**: a pinged socket died 20.8 min after terminal create, ~46 s behind the container's own cliff, while a text-framed one lived the full 22 min alongside its container | Native: portal sends an EMPTY TEXT frame (opcode 1, 0 bytes) at 1.0/s, not `ws.ping`. CloudBasher now sends the same frame shape on a 1 Hz session worker. Evidence is a 22-minute floor, not proof of indefinite retention or of the isolated causal factor. | *observed*, |
| 6 | **The portal's terminal UI** (CLIENT-side, not a service object) | **20.03 min from the last KEYSTROKE** | nothing — the frame at row 5 does **not** feed this timer | *observed* |


<a id="id-section-8-2"></a>
### 8.2 Published service limits

**Source:** [Azure Cloud Shell FAQ & troubleshooting](https://learn.microsoft.com/en-us/azure/cloud-shell/faq-troubleshooting) — concurrency limit, idle timeout, the Terms-of-Service clause and `TenantDisabled` all come from that page.

**Azure meters a different axis from AWS and GCP: simultaneity, not cumulative usage.**

| | AWS | GCP | **Azure** |
|---|---|---|---|
| Runtime hours | 200 h / month | 50 h / week (`180000 s`, readable via `GET /devshell/quota`) | **none published** |
| Concurrency | 10 active containers per region per account | — | **20 concurrent users per TENANT** — exceeding it returns `Tenant User Over Quota`; increases via Support, in advance |
| Idle timeout | — | — | **20 min** without interactive activity |
| Quota introspection API | — | **yes** | **no** — and 's operation catalog confirms it: 13 operations, none about quota or usage |

In place of an hours quota, a Terms-of-Service clause — *"Cloud Shell is a free service for managing your Azure environment. It's not a general purpose computing platform. **Excessive usage might be considered a breach of the Azure Terms of Service**, which result in having your access to Cloud Shell blocked."

**Enforcement is tenant-wide, abrupt, and needs a human to undo.** Out-of-the- ordinary CPU consumption can trip fraud prevention and disable Cloud Shell for the whole directory — `{"code":"TenantDisabled"}` — recoverable only by a support request naming the tenant id and a business justification.


**Not published anywhere located:** maximum console lifetime (the row below stays unconfirmed), terminals-per-console (10 observed concurrently), or CPU/memory allocation.

**Timeout Taxonomy**

| Timeout | Trigger | Reset mechanism | Recovery |
|---|---|---|---|
| Console idle (20 min) | No `POST /keepAlive` for 20 min | `POST /keepAlive` (~60s interval) | Auto-reprovision or `PUT /consoles/default`; hot path ~1-2s |
| WS/TCP proxy drop | No WebSocket traffic within intermediate-proxy/NAT idle window (typ. 60-300s) | Empty WebSocket text frame (1 Hz, native-shaped) | Reconnect; new terminal required (old ID invalid) |
| Bearer token expiry (~1hr) | Azure AD JWT 3600s lifetime elapses | MSAL refresh (runner proactively refreshes at <300s remaining) | Re-authenticate via MSAL; 401 on ARM calls if missed |
| Maximum console lifetime | Unconfirmed — some hosted-shell services impose ~20hr hard limits | None (unconfirmed if it exists at all) | Indistinguishable from idle recycle; `provision_or_reuse_console` re-provisions automatically |

<a id="id-section-8-3"></a>
### 8.3 Revocation

No API to enumerate or kill individual terminal sessions. Available levers, in order of strength
- RBAC role removal — does **not** invalidate already-issued live tokens.
- Continuous Access Evaluation (CAE)-based sign-in revocation — near-real-time, but only if CAE is enabled/supported for the tenant.
- Console deletion (`DELETE /consoles/default`, [§3](#id-section-3)) — kills the underlying ACI container outright (the bluntest option).

There is no AWS-style `TokenIssueTime`-based deny-policy equivalent for Azure Cloud Shell specifically.


<a id="id-section-8-4"></a>
### 8.4 Persistence

Azure Cloud Shell persists the user's home directory in an ext2 disk image stored on an Azure Files share. The container mounts that share, and `$HOME` is backed by the image rather than being a directory directly on the share. Container replacement therefore does not by itself remove the persisted home data; deleting the backing share or image does.

<a id="id-section-9"></a>
## 9. IAM Permission Model


<a id="id-section-9-1"></a>
### 9.1 The minimum role also WRITES


The two-action minimum established below gates **reaching a shell**. It also grants **write access to every filesystem tier in the container**, and that was open until now.

*Observed* — role `storageAccounts/read` + `listKeys/action` at subscription scope, on a **cold** container

| Path | What it is | Write |
|---|---|---|
| `/tmp`, `/var/tmp` | container-local | ✓ |
| `$HOME` | the loop-mounted ext2 image | ✓ |
| `$HOME/.ssh`, `$HOME/.azure` | inside that image | ✓ |
| `$HOME/clouddrive` | the CIFS mount of the share | ✓ |


**Two qualifications, both from the same run:**

1. **`DELETE /consoles/default` was accepted by a role with zero `Microsoft.Portal` actions**. Non-enforcement of `Microsoft.Portal/consoles/*` now covers delete as well as write — the operation recorded as never exercised.
2. **The role under test reports four actions, not two**. `Microsoft.Authorization/permissions/read` and `Microsoft.Resources/subscriptions/read` were added so the harness can verify itself; **neither is a CloudShell gate.** Whether a role with *only* the two gate actions still reaches a shell is *inferred*, not observed.


<a id="id-section-9-2"></a>
### 9.2 ARM RBAC role requirements

Action strings for the `Microsoft.Portal` resource provider

| Action | Used by |
|---|---|
| `Microsoft.Portal/userSettings/read` | `GET /userSettings` |
| `Microsoft.Portal/userSettings/write` | `PUT /userSettings` (initial setup, region/shell preference) |
| `Microsoft.Portal/consoles/read` | `GET /consoles/default` |
| `Microsoft.Portal/consoles/write` | `PUT /consoles/default` (provision/reprovision) |
| `Microsoft.Portal/consoles/delete` | `DELETE /consoles/default` |

Action-level built-in-role grant matrix

| Role | userSettings read | userSettings write | console read | console write |
|---|:---:|:---:|:---:|:---:|
| Owner | ✓ | ✓ | ✓ | ✓ |
| Contributor | ✓ | ✓ | ✓ | ✓ |
| Reader | ✓ | ✗ | ✓ | ✗ |
| Custom (minimum) | ✓ | ✓ | ✓ | ✓ |

Coarser-grained summary of the same roles — kept alongside the action-level matrix above since it conveys a different level of detail (pass/fail per role rather than per action)

| Role | CloudShell access | Notes |
|---|:---:|---|
| Owner | ✅ | Full subscription control |
| Contributor | ✅ | Minimum sufficient built-in role |
| Reader | ⚠️ | Can GET consoles but cannot provision |
| Any custom role with `Microsoft.Portal/consoles/*` | ✅ | Explicit permission |


<a id="id-section-9-3"></a>
### 9.3 Storage account requirements and supported principals

For a **mounted** Cloud Shell home, the caller needs effective `Microsoft.Storage/storageAccounts/read` and `Microsoft.Storage/storageAccounts/listKeys/action` permissions on the configured storage account. The first permits terminal creation; the second permits the service to retrieve the account key used to mount the Azure Files share. Without the read action, terminal creation is refused. Without `listKeys/action`, a shell may start without the persistent share mounted.

| Requirement | Purpose |
|---|---|
| Existing Azure Storage account and configured file-share profile | Provides the persistent home image and `~/clouddrive` share |
| `Microsoft.Storage/storageAccounts/read` | Required for `POST /terminals` to accept the configured storage account |
| `Microsoft.Storage/storageAccounts/listKeys/action` | Required for mounting the share; the resulting key is a sensitive credential |
| Shared Key access enabled on the account | Required by the observed account-key/CIFS mount path |

Cloud Shell access is user-delegated and constrained by the service's accepted client applications. The service-principal-only flow is refused by the Cloud Shell endpoint in the tested path; adding storage permissions alone does not make that credential type usable. Refresh-token, device-code, and supported user access-token flows remain subject to token audience, tenant policy, expiry, Conditional Access, and the user's effective RBAC.

<a id="id-section-9-4"></a>
### 9.4 The two storage actions, and what each one gates

The storage permissions gate different stages. The role labels below are replaced with the effective permissions they represent, so the table describes the requirement rather than a private test-role name.

| Effective storage permissions | Terminal creation | Persistent share mounted | Result |
|---|---|---|---|
| Neither `storageAccounts/read` nor `listKeys/action` | Refused (`400 UserSettingsInvalid`) | No | No terminal |
| `listKeys/action` only | Refused (`400 UserSettingsInvalid`) | No | Key permission alone is insufficient |
| `storageAccounts/read` only | Accepted | No | Shell may start with ephemeral home storage |
| Both `storageAccounts/read` and `listKeys/action` | Accepted | Yes | Mounted persistent home and file share |

The minimum observed storage permissions for a mounted session are `storageAccounts/read` and `storageAccounts/listKeys/action`. The first is checked when the terminal is created; the second permits the file-share mount. The `listKeys/action` permission can expose a reusable account key, so it should be scoped and treated as sensitive.
<a id="id-section-9-5"></a>
### 9.5 How a personal MSA account gets access to CloudShell

Assembled here because it is a natural reader question whose answer was spread across [§2](#id-section-2), §1.1 and the research ledger. **The short version: there are no CloudShell permissions to get, and everything a personal account needs arrives from one act — signing up for Azure.**

**Stage 0 — a bare MSA has nothing, and fails before permissions are consulted.**

```
AADSTS16000: User account from identity provider 'live.com' does not exist in tenant
'Microsoft Services' and cannot access the application
b677c290-cf4b-4a8e-a60e-91ba650a4abe (AzurePortal Console App) in that tenant.
The account needs to be added as an external user in the tenant first.
      scope requested: https://management.core.windows.net//.default
```

No RBAC question arises — there is nowhere for the CloudShell app to hold a principal for this identity. `outlook.com` and `live.com` are not a variable: the error names the identity provider as `live.com` **for an `outlook.com` account**.

**Stage 1 — the Azure sign-up grants everything.**

```
quotaId               PayAsYouGo_2014-09-01        (PAYG -- not "free")
authorizationSource   RoleBased
effective actions     ["*"] with an EMPTY notActions
                      + Microsoft.Authorization/elevateAccess/action
                      + roleAssignments/read, roleDefinitions/read
```

*observed* for that end state — Owner-shaped, expressed as a role assignment rather than legacy ownership.

**Stage 2 — CloudShell needs no CloudShell permission.** There is no CloudShell RBAC action to grant or withhold (§ below); `Microsoft.Portal/consoles/write` is **not an enforced gate**; the proven minimum is **two storage actions**, `Microsoft.Storage/storageAccounts/read` + `.../listKeys/action` (S2 rows R6/R7); and the portal **never pre-checks RBAC at all** — it attempts the call and handles the failure. Owner satisfies all of this with enormous room to spare.

**Stage 3 — provisioning does not vary by account type.**

**Stage 4 — the shell's authority is the BROWSER's.**

**The Portal UI is the broker host, not merely a place to store a refresh token — live exchange plus bundle inspection, 2026-10-02.** The saved native terminal client bundle constructs a parent `postMessage` containing `signature: "portalConsole"`, `type`, `audience`, `resourceId`, `fileShare`, and `getTokenWithDetails`; for token requests it also sends a second message with the audience mapped through the bundle's resource map. The terminal iframe accepts messages only from its trusted Portal origin. The parent returns `type: "postToken"` with `message` and `audience`; the terminal UI passes that token to its callback and POSTs `{"token":"<token>"}` to `{console.uri}/accessToken` with an `Authorization` header. The header's source variable and value are not established. These are source-level client facts; the parent implementation, exact Entra request body, and local broker correlation remain open in. Therefore an API client that only retains a Portal refresh token, or only opens the Service Bus sockets, does not yet implement native token brokering. The owner confirmed `az ad signed-in-user show` succeeds in native Portal Cloud Shell while CloudBasher's TUI still times out. Generalizing this behavior to arbitrary requested audiences remains a separate security question.


**Three things this section does NOT establish**, kept here so the next reader does not over-read it. The **sign-up itself was never captured**, so Stage 1 is inference from end states. Whether a personal account can run CloudShell on a **narrower** grant is untested — Owner is known to work and two storage actions are known to suffice for a corporate identity, but nobody has assigned a narrow role on a personal subscription. And whether that `["*"]` is literally the **Owner role** is unknown: the permissions API returns actions, not role names.

<a id="id-section-9-6"></a>
### 9.6 Cloud Shell uses ARM authorization, not a separate API permission

There is no separate Cloud Shell API permission to add to an Entra app registration. Cloud Shell access uses Azure resource authorization and service-side client/token checks. Portal browser features may use Microsoft Graph for unrelated account and directory UI functions; those scopes are not Cloud Shell API permissions.
#### Consent and authorization considerations

Cloud Shell authorization is not enabled by adding a dedicated Cloud Shell API permission to an app registration. The caller needs a supported user-authentication path and the access required by the selected operation; tenant sign-in policies and service-side client restrictions can also apply.

| Authentication path or policy | Consent / access implication |
|---|---|
| Delegated user authentication | No separate Cloud Shell API permission is required in the tested flows. ARM access and storage-backed features remain subject to the user's effective permissions. |
| Service-principal-only authentication | A client-credentials token or RBAC assignment alone does not establish a supported Cloud Shell sign-in path; the tested service-principal-only flow was refused. |
| Conditional Access or client policy | Tenant sign-in controls and service-side client restrictions can block a flow even when the user otherwise has resource permissions. |

<a id="id-section-9-7"></a>
### 9.7 IAM actions

IAM actions, as a code block


```
Microsoft.Portal/consoles/read             — GET /consoles/default
Microsoft.Portal/consoles/write            — PUT /consoles/default (provision)
Microsoft.Portal/consoles/delete           — DELETE /consoles/default
Microsoft.Portal/userSettings/read         — GET /userSettings
Microsoft.Portal/userSettings/write        — PUT /userSettings
```

No documented equivalent of AWS's granular `cloudshell:CreateSession`/`cloudshell:PutCredentials` — Azure CloudShell access is controlled at the ARM resource-provider level, not with fine-grained session actions.

<a id="id-section-9-8"></a>
### 9.8 Three timing and scope facts that decide whether an IAM measurement means anything

Measured live during `51.4`(b). Each one invalidated a result that looked clean, so they are recorded here rather than only in the ledger.

**1. Scope: `userSettings` and `consoles` are tenant-scope**. Covered in §9.7 above. The consequence for the permission model is that the **storage substrate is the only thing subscription RBAC controls**, and the proven minima reflect that: with `userSettings` already present, **four** actions suffice when the resource group is pre-created — `resourceGroups/read`, `storageAccounts/read`, `storageAccounts/write`, `storageAccounts/listKeys/action` — and **five** when it is not, adding `resourceGroups/write`. No `Microsoft.Portal` action and no `*/read` appears in either.

**And the from-scratch case needs no more than that.** A principal that had never used CloudShell, holding those same five and no `Microsoft.Portal` action, wrote its own `userSettings` and provisioned a console. **From-scratch and re-provision have the SAME minimum**; they differ by a *step* — writing `userSettings`, which the first-run wizard normally does — not by a *permission*.

**2. Timing: a grant is not always fast**. A **new** role assignment flipped its canary in **0.5 s**. **Widening an existing role definition** — same assignment, one action added — was still refused at **1468 s (24.5 min)**. Any plan that treats "additive" as "quick" is wrong; the additive ordering avoids the revocation penalty, not a propagation penalty.

**3. Timing: revocation has no documented upper bound**. 's ~32 minutes is a **floor**. One revocation was still unenforced at **45 minutes**. Poll for the flip; never sleep a constant.

**In all three the `permissions` endpoint agreed with the intended state while enforcement did not.** `az role definition list` showed the widened action present for the whole 24.5 minutes. A readiness gate built on either would have declared the arm ready ~24 minutes early — which is how two runs produced a `403` on an action the role demonstrably held, and why both are `INADMISSIBLE` rather than refusals.

**And MFA is a second gate, evaluated after RBAC**. A non-MFA token gets `403 AuthorizationFailed` where RBAC refuses and `401 RequestDisallowedByAzure` where RBAC passes — so **without an MFA-blessed token one can observe RBAC refusals but never RBAC successes**, and no minimum-permission question is answerable. The same non-MFA token provisioned a console successfully, which is fact 1 seen from the other side: the MFA policy protects Azure *resource management*, and a tenant-scope Portal resource is not that. **Confirmed 2026-09-19 on the same resource type**: a principal holding `resourceGroups/write` and nothing else gets `401`, not `403`, on the identical write that answers `403` for a principal without the action — so the 403/401 split is the RBAC verdict deciding which gate speaks, not two verbs gated differently. *Operational consequence:* a throwaway test identity cannot measure RBAC until it has completed MFA enrolment, because every positive result is an ARM write.

<a id="id-section-9-9"></a>
### 9.9 Minimum Azure RBAC by Cloud Shell operation

The permissions needed depend on which operation is performed and whether persistent storage is configured. A successful console request alone does not prove that terminal creation or the storage mount succeeded.

| Scenario | Enforcing operation | Minimum Azure RBAC |
|---|---|---|
| Register the Cloud Shell resource provider | Provider registration request | `Microsoft.CloudShell/register/action` |
| Create a resource group and storage account for a mounted shell | Resource-group and storage-account `PUT` requests, then terminal creation and mount | `resourceGroups/write`, `storageAccounts/write`, `storageAccounts/read`, and `storageAccounts/listKeys/action` |
| Use an existing storage account for a mounted shell | `POST /terminals` and storage-account key retrieval | `storageAccounts/read` and `storageAccounts/listKeys/action` |
| Open a shell without a storage profile (tested ephemeral path) | Tenant-scoped settings/console requests and terminal creation | No subscription-scoped Azure RBAC was required in the tested path |

These are operation-specific findings, not a universal role recommendation. The service's accepted user/client authentication path and tenant policy are separate gates. New or changed role assignments can take time to become effective; verify access through the operation being granted instead of relying only on a permission-list response. MFA or Conditional Access may also gate subscription-scoped writes separately from the Cloud Shell console flow.
<a id="id-section-10"></a>
## 10. Threat Modeling

This section summarizes Azure Cloud Shell access controls and practical hardening considerations.

<a id="id-section-10-1"></a>
### 10.1 Attack Surface

**Device-code phishing.** Device-code sign-in can be abused to trick a user into approving an attacker-initiated sign-in. The resulting delegated authority is the user's, so its reach depends on the app, requested resource, tenant policy, and the user's permissions.

**MFA and device-code sign-in.** Device-code flow does not inherently bypass MFA. Enforced MFA and Conditional Access still apply, though an attacker may try to persuade the user to satisfy a prompt. Use phishing-resistant MFA and restrict device-code sign-in where it is not needed.

**FOCI lateral movement.** Some Microsoft public clients participate in a shared refresh-token family. A qualifying refresh token may support sign-in to multiple family apps, subject to Microsoft’s client and tenant controls; do not assume every refresh token has this property.

**Bearer-token theft.** A stolen delegated access token can let its holder act as the user against the token's intended resource until it expires or is otherwise rejected. Protect browser and CLI token caches, process memory, and logs; apply Conditional Access and revocation controls.

**Cloud Shell as persistent access.** A Cloud Shell console and its persisted home data can outlive the browser tab that opened them. Closing a tab or restarting a container should not be treated as data removal; manage identity access and backing storage separately.

**Contributor blast radius.** Contributor grants broad resource-management rights, not just shell access. Limit its scope and use narrower roles for the storage resources Cloud Shell needs.
<a id="id-section-10-2"></a>
### 10.2 Access policies and control scope

Azure Cloud Shell access spans tenant sign-in controls and subscription-scoped storage permissions. The Cloud Shell user-settings and console requests are tenant-scoped, so subscription RBAC or Azure Policy should not be assumed to block those requests.

| Control boundary | What it affects |
|---|---|
| Entra ID sign-in and Conditional Access | Whether the user's authentication flow can obtain and use an accepted token |
| Cloud Shell service/client policy | Whether the service accepts the requesting client and token for Cloud Shell operations |
| Subscription RBAC and Azure Policy | Subscription resources such as the configured storage account; these controls do not by themselves govern tenant-scoped Cloud Shell settings and console calls |
| Storage-account permissions | Whether a terminal can use the configured persistent file share |

Use tenant sign-in and service-side controls to govern access to the shell, and apply least-privilege RBAC to its storage resources. A subscription-level deny policy is not a verified Cloud Shell access control.
<a id="id-section-10-3"></a>
### 10.3 Abuse Scenarios

**A-1 · Cloud Shell access may be available without subscription-level RBAC.** Tenant-scoped Cloud Shell setup can be separate from subscription roles. Subscription role assignments therefore do not, by themselves, describe every user's ability to start a shell.

**A-2 · Cloud Shell can expose delegated tokens to in-container tools.** The shell can obtain tokens representing the signed-in user for supported resources. Treat those tokens as credentials: limit who can access the shell, protect processes and files, and apply least privilege to the user's identity.

**A-3 · Storage permissions can enable a persistent shell.** Access to the Cloud Shell storage account and its keys can allow the user's home data to be mounted. Review `storageAccounts/read` and `storageAccounts/listKeys/action` as sensitive permissions, even when described as read-oriented.

**A-4 · Storage access can expose Cloud Shell data.** Persistent home data is held in an Azure Files share and disk image. Restrict storage-account and share access, and audit grants that can retrieve account keys.

**A-5 · Restart and reset do not erase persisted home data.** Those actions affect the running console or its storage binding; they do not delete the backing share or home image. Remove the backing storage when data must be destroyed.

**A-6 · Subscription Activity Logs may not show Cloud Shell console activity.** Do not rely on subscription control-plane logs alone to detect shell use; correlate sign-in information with available storage diagnostics and other tenant telemetry.

**A-7 · A browser tab is not the lifetime boundary for a console.** A console may remain available after the tab closes, while its connection details can change. Revoke identity access and review persistent storage as separate response steps.

**A-8 · Device-code phishing can target Cloud Shell-capable clients.** Cloud Shell accepts device-code sign-ins under Azure CLI (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`), Windows Terminal (`245e1dee-74ef-4257-a8c8-8208296e1dfd`), and Visual Studio Code (`aebc6443-996d-45c2-90f0-388ff96faa56`). An attacker may ask a user to complete a sign-in initiated for one of these clients; the resulting token authority remains delegated and policy-controlled. WAM broker device-code support remains undetermined.
<a id="id-section-10-4"></a>
### 10.4 Hardening Recommendations

| Control | Practical guidance |
|---|---|
| Strengthen sign-in | Require MFA and, for privileged users, prefer phishing-resistant methods. Use Conditional Access to apply appropriate device, location, and risk requirements. |
| Restrict legacy and device-code authentication | Disable legacy authentication where possible. Apply tenant policy to restrict device-code flows when they are not required by the organization. |
| Scope Cloud Shell storage permissions | Treat `storageAccounts/read` and `storageAccounts/listKeys/action` as sensitive; together they can enable a persistent, storage-backed shell, and the account key is a reusable credential. |
| Protect persistent data | Restarting or resetting Cloud Shell does not remove data in the configured file share. Remove the share or its stored home image when data must be destroyed. |
| Review resource access | Use least-privilege role assignments for Cloud Shell storage and review grants that allow account-key retrieval. Tenant-scoped Cloud Shell settings and console calls are not controlled by subscription-scoped Azure Policy or RBAC alone. |

These controls address different boundaries: identity sign-in, subscription resources, and persistent storage. Apply the relevant tenant and resource controls together.
