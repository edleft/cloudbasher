# CloudShell Design — AWS

<a id="id-contents"></a>
## Contents

[1. Control-Plane Flow](#id-section-1)
[2. Container Lifecycle](#id-section-2)
&nbsp;&nbsp;&nbsp;&nbsp;[2.1 Heartbeat and keepalive](#id-section-2-1)
&nbsp;&nbsp;&nbsp;&nbsp;[2.2 Environment status](#id-section-2-2)
[3. REST API](#id-section-3)
&nbsp;&nbsp;&nbsp;&nbsp;[3.1 Table A — CloudShell control plane](#id-section-3-1)
&nbsp;&nbsp;&nbsp;&nbsp;[3.2 Table B — console-only helper endpoints](#id-section-3-2)
&nbsp;&nbsp;&nbsp;&nbsp;[3.3 Field lineage](#id-section-3-3)
[4. WebSocket Protocol](#id-section-4)
&nbsp;&nbsp;&nbsp;&nbsp;[4.1 WebSocket session-plane elements](#id-section-4-1)
&nbsp;&nbsp;&nbsp;&nbsp;[4.2 Message types](#id-section-4-2)
&nbsp;&nbsp;&nbsp;&nbsp;[4.3 ACK payload fields](#id-section-4-3)
&nbsp;&nbsp;&nbsp;&nbsp;[4.4 Command encoding](#id-section-4-4)
&nbsp;&nbsp;&nbsp;&nbsp;[4.5 Terminal control sequences](#id-section-4-5)
&nbsp;&nbsp;&nbsp;&nbsp;[4.6 WebSocket text controls](#id-section-4-6)
[5. File Transfer](#id-section-5)
&nbsp;&nbsp;&nbsp;&nbsp;[5.1 Upload — browser to CloudShell](#id-section-5-1)
&nbsp;&nbsp;&nbsp;&nbsp;[5.2 Download — CloudShell to browser](#id-section-5-2)
[6. Credential Types](#id-section-6)
[7. Authentication Flows](#id-section-7)
&nbsp;&nbsp;&nbsp;&nbsp;[7.1 Track A, step by step](#id-section-7-1)
&nbsp;&nbsp;&nbsp;&nbsp;[7.2 Track B, step by step](#id-section-7-2)
[8. Sessions](#id-section-8)
&nbsp;&nbsp;&nbsp;&nbsp;[8.1 IAM credentials and sessions](#id-section-8-1)
&nbsp;&nbsp;&nbsp;&nbsp;[8.2 Flows between the three session kinds](#id-section-8-2)
&nbsp;&nbsp;&nbsp;&nbsp;[8.3 Revocation does not reach the WebSocket](#id-section-8-3)
[9. IAM Permission Model](#id-section-9)
&nbsp;&nbsp;&nbsp;&nbsp;[9.1 Minimal privileges](#id-section-9-1)
&nbsp;&nbsp;&nbsp;&nbsp;[9.2 Container credential binding](#id-section-9-2)
[10. Threat Modeling](#id-section-10)
&nbsp;&nbsp;&nbsp;&nbsp;[10.1 Attack Surface](#id-section-10-1)
&nbsp;&nbsp;&nbsp;&nbsp;[10.2 Access Policies](#id-section-10-2)
&nbsp;&nbsp;&nbsp;&nbsp;[10.3 Abuse Scenarios](#id-section-10-3)


<a id="id-section-1"></a>
## 1. Control-Plane Flow


High-level view of the normal flow, before the detailed per-topic sections below. All API-mode paths converge on the same REST→WebSocket pivot; what differs by credential type is *how the caller gets authorized to reach that pivot*, not the pivot itself.

```
                    ┌───────────────────────────────┐
                    │        Caller Identity        │
                    │     IAM user · SSO user       │
                    │ Assumed Role · Federated User │
                    │      Permanent AKIA keys      │
                    │      Temporary ASIA tokens    │
                    └───────────────┬───────────────┘
                                    │ SigV4 (API) or Console Cookies (Browser)
                                    ▼
        ┌──────────────────────────────────────────────────────────┐
        │                   REST Control Plane                     │
        │            cloudshell.<region>.amazonaws.com             │
        │    describeEnvironments → createEnvironment →            │
        │  getEnvironmentStatus → startEnvironment → createSession │
        └────────────────────────────┬─────────────────────────────┘
                                     │ StreamUrl + TokenValue
                                     ▼
           ┌─────────────────────────────────────────────────────┐
           │                WebSocket Terminal                   │
           │           wss://ssmmessages.<region>...             │
           │             SSM-style binary framing                │
           └─────────────────────────┬───────────────────────────┘
                                     │
                                     ▼
      ┌──────────────────────────────────────────────────────────────┐
      │                     CloudShell Container                     │
      │ in-shell `aws` CLI reads AWS_CONTAINER_CREDENTIALS_FULL_URI  │
      │        (~10 min TTL, auto-refreshed via RefreshToken)        │
      └──────────────────────────────────────────────────────────────┘
```

<a id="id-section-2"></a>
## 2. Container Lifecycle


Effective state machine

```mermaid
stateDiagram-v2
    [*] --> NO_ENV
    NO_ENV --> CREATING: createEnvironment
    CREATING --> RUNNING: getEnvironmentStatus polling
    RUNNING --> SESSION_READY: createSession
    SESSION_READY --> INTERACTIVE: WebSocket bootstrap
    INTERACTIVE --> SUSPENDED: service inactivity or stop
    INTERACTIVE --> STOPPED: service stop
    SUSPENDED --> RUNNING: startEnvironment + polling
    STOPPED --> RUNNING: startEnvironment + polling
    RUNNING --> DELETED: delete or terminal lifecycle
    RUNNING --> ERROR: terminal lifecycle
    DELETED --> [*]
    ERROR --> [*]
```

**NOTES**
- `SUSPENDED`/`STOPPED` environments are resumed via `startEnvironment` + poll on `getEnvironmentStatus` — both re-enter at `RUNNING`, not at `NO_ENV`.
- `DELETED` and `ERROR` are terminal.
- There is no explicit "reset" API beyond re-running `startEnvironment`

<a id="id-section-2-1"></a>
### 2.1 Heartbeat and keepalive

**A CloudShell container and the terminal session on it are killed by FOUR different idle timers, on four different clocks, and each is defeated by something different.** Sending more of the wrong keepalive does not help: it was tried, and measured not to.

**What dies, and what defeats it.**

| Timer | What dies | Defeated by |
|---|---|---|
| **~350 s** | the TCP flow (an idle intermediary reaps it; 350 s is the standard NLB idle-flow timeout) | any outbound write — `__ping__` at 15 s is far inside it |
| **~20–28 min** | the SSM session, with pings still flowing | *real channel traffic*, not a text-frame ping |
| **10–20 min** | the environment (idle suspend) | **`sendHeartBeat` — layer 1, on its own.** Not the bridge; see the note below |
| **~9.8–12 h** | hard reset | nothing — mechanism unknown |

**The four keepalive mechanisms, one per timer.** They are independent: each addresses a different clock, and none substitutes for another.

| Layer | Mechanism | What it keeps alive |
|---|---|---|
| **1** | REST `sendHeartBeat` | the **environment** — defers idle suspension |
| **2** | WebSocket `__ping__` text frame | the **socket** — a socket with no writes dies in 300–360 s |
| **3** | `EXTENSIONS_BRIDGE` `{"type":"webapp/connected"}` every 5.0 s | the console's **session** |
| **4** | an interaction keepalive on the user's own session | the **~20 min per-session timer**, which none of the first three reaches |

**"Layer" means this and only this in this document.** It is not an OSI layer and not a protocol plane.


<a id="id-section-2-2"></a>
### 2.2 Environment status

| Observed environment state | Control-plane behavior | Result |
|---|---|---|
| `NO_ENV` | `describeEnvironments` returns none, then `createEnvironment` | new environment path |
| `RUNNING` | no `startEnvironment`; proceed directly to `createSession` | session can be created immediately |
| `SUSPENDED` | `startEnvironment`, then poll `getEnvironmentStatus` | resume flow |
| `STOPPED` | `startEnvironment`, then poll `getEnvironmentStatus` | resume flow |
| `DELETED` | terminal error; no session creation | unusable environment |
| `ERROR` | terminal error; no session creation | unusable environment |

`SUSPENDED` and `STOPPED` are treated identically by the CloudBasher code paths; AWS may distinguish them internally, but the local implementation doesn't need to.

<a id="id-section-3"></a>
## 3. REST API


The control plane. Three rules hold for every endpoint in Table A, so none of them is tabulated

- **Every call is a `POST`**, to `https://cloudshell.<region>.amazonaws.com/<action>`.
- **Every call is SigV4-signed** — by us on Path A, by `/api/prod/presign` on Path B ([§7](#id-section-7)).
- **`EnvironmentId` is required by every call after the first.**

Table B is the exception to all three: a different host, and a different auth model entirely.

<a id="id-section-3-1"></a>
### 3.1 Table A — CloudShell control plane

| Endpoint | Purpose | Inputs | Outputs |
|---|---|---|---|
| `/describeEnvironments` | enumerate environments for the caller in-region | SigV4 auth, region; optional filters not recovered | `Environments`; each entry carries `EnvironmentId`, and a **VPC environment** additionally carries `VpcConfig` + `EnvironmentName` (see below) |
| `/createEnvironment` | create a new environment | SigV4 auth, region. **Body must be the two bytes `{}`, not a zero-length body** — see the note below | new `EnvironmentId` |
| `/getEnvironmentStatus` | retrieve lifecycle state | `EnvironmentId` | `Status` — `RUNNING`, `SUSPENDING`, `SUSPENDED`, `STOPPED`, `DELETED`, `ERROR` |
| `/startEnvironment` | resume a non-running environment | `EnvironmentId` | start accepted; status changes follow |
| `/stopEnvironment` | **DESTRUCTIVE (suspends).** Stop a running environment | `EnvironmentId` | `{"EnvironmentId": …}`; HTTP 200 |
| `/deleteEnvironment` | **DESTRUCTIVE (irreversible).** Delete an environment and its 1 GB of persistent storage | `EnvironmentId` | `{}`; HTTP 200 |
| `/createSession` | create a terminal session | `EnvironmentId`, `SessionType` (`TMUX`\|`BASH`\|`EXTENSIONS_BRIDGE`, [§8](#id-section-8)), and **`TabId` only when `SessionType=TMUX`** | `SessionId`, `StreamUrl`, `TokenValue` |
| `/deleteSession` | tear down a terminal session | `EnvironmentId` **and** `SessionId` — both | `{}` |
| `/redeemCode` | exchange browser auth material for refresh material | `EnvironmentId`, `AuthCode`, `CodeVerifier`, `RedirectUri`, `KeyBase` | `RefreshToken` — and **only** that; the response carries no expiry |
| `/putCredentials` | install in-shell credentials in the container | `EnvironmentId`, `RefreshToken`, `KeyBase` | success / request ID |
| `/sendHeartBeat` | service-side liveness / idle suppression | `EnvironmentId` and session context | success / request ID |
| `/getFileUploadUrls` | stage browser → CloudShell | `EnvironmentId`, `FileUploadPath` | presigned S3 material for **both** legs — see [§5](#id-section-5) |
| `/getFileDownloadUrls` | stage CloudShell → browser | `EnvironmentId`, `FileDownloadPath` | same field family as upload |

<a id="id-section-3-2"></a>
### 3.2 Table B — console-only helper endpoints

Different host (`<region>.console.aws.amazon.com`), different auth (console session cookie + `x-console-api-token`, **not** SigV4), and not part of the CloudShell API. Reachable only on Path B.

| Endpoint | Purpose | Inputs | Outputs |
|---|---|---|---|
| `.../api/prod/browserCreds` | obtain browser-visible temporary AWS credentials | console session state; **the console's own request headers** — a bare POST with only `content-type` gets 401 | `accessKeyId`, `secretAccessKey`, `sessionToken`, `expiration` |
| `.../api/prod/presign` | sign a described request on the caller's behalf | console session; a request descriptor — `service, region, method, protocol, hostname, path, headers, query`, and **`body`** | **signed header material, never credentials** |

<a id="id-section-3-3"></a>
### 3.3 Field lineage

Four chains carry the protocol; everything else is a one-shot success/failure.

- **`EnvironmentId`** — from `/describeEnvironments` or `/createEnvironment`; required by *every* subsequent call in Table A.
- **`RefreshToken`** — `/redeemCode` → `/putCredentials`. Also what the container's credential provider uses to auto-refresh the in-shell credentials (~10 min TTL, [§7](#id-section-7)). **Its own lifetime is NOT disclosed**
- **`SessionId` + `StreamUrl` + `TokenValue`** — all three from one `/createSession`: `StreamUrl` is the WebSocket to connect, `TokenValue` goes in the token envelope ([§4](#id-section-4)), `SessionId` is what `/deleteSession` needs.
- **The presigned/SSE-C family** — `FileUploadPresignedUrl`, `FileUploadPresignedFields`, `FileDownloadPresignedUrl`, `FileDownloadPresignedKey`, `FileDownloadPresignedKeyHash`. One call returns material for **both** legs of a transfer; [§5](#id-section-5) has the full field table.

`createSession` is the pivot between the REST and WebSocket halves of the protocol. The transfer APIs are capability-orchestration APIs, not byte-transfer APIs — the bytes move over S3 and the PTY, never through them.


<a id="id-section-4"></a>
## 4. WebSocket Protocol


SSM-style **binary framing**, distinct from GCP's real-SSH-over-WS and Azure's plain-text framing (see the design record for the 3-way comparison). Frame layout

```
[0:4]    total length (=116 for control frames)
[4:36]   message_type  (input_stream_data | output_stream_data | acknowledge | channel_closed)
[36:40]  schema version (=1)
[40:48]  created (ms epoch)
[48:56]  sequence number
[56:64]  flags (0 normal, 1 = init)
[64:80]  message_id (UUID)
[80:112] SHA-256 digest
[112:116] payload_type (1=text, 3=resize, 0=ack)
[116:...] payload length + payload
```

- **The first frame after connect is a JSON token envelope** — `{MessageSchemaVersion, RequestId, TokenValue}`.
- **Three things write to keep a session alive, and they are not interchangeable.** A text `__ping__` frame on the WebSocket, a REST `sendHeartBeat` call, and — the console's own steady beat — `{"type":"webapp/connected"}` every five seconds on a *separate* `EXTENSIONS_BRIDGE` session. Each defeats a different timer, and a socket with no writes at all dies in 300–360 s against 20.9 min with pings. [§2.1](#id-section-2-1) has the four timers and what defeats each.
- **Not every session is a PTY.** An `EXTENSIONS_BRIDGE` session carries only that JSON line and never produces a prompt, so a client treating "no prompt" as a failed bootstrap will misread one. The `SessionType` triad is in [§8](#id-section-8).
- **There is no canonical close code.** Observed: `11177`, `34945`, `3000`, `1000`. Treat all four as terminal.


<a id="id-section-4-1"></a>
### 4.1 WebSocket session-plane elements

| Element | Transport form | Purpose | Key inputs | Key outputs |
|---|---|---|---|---|
| Token envelope | WebSocket text JSON | bootstrap authorization for the channel | `MessageSchemaVersion`, `RequestId`, `TokenValue` from `/createSession` | accepted session bootstrap |
| Terminal init / resize | WebSocket binary `input_stream_data`, payload type `3` | set PTY geometry | JSON like `{"cols":169,"rows":26}` | screen layout / initial PTY output |
| Shell input | WebSocket binary `input_stream_data`, payload type `1` | send keystrokes or whole command strings | raw bytes such as `ls\r`, `find /tmp\r`, helper `curl...` lines | command execution |
| Shell output | WebSocket binary `output_stream_data` | return prompt, ANSI controls, command output | none from client | PTY bytes that drive client rendering and transfer success detection |
| ACKs | WebSocket binary `acknowledge` | reliability / sequencing | `AcknowledgedMessageType`, `AcknowledgedMessageId`, `AcknowledgedMessageSequenceNumber` | delivery accounting and sender bookkeeping |
| WebSocket keepalive | WebSocket text `__ping__` | data-channel keepalive | literal `__ping__` | no shell-visible output observed |
| Close status text | WebSocket text like `Closed (code=11177)` | lifecycle/status indication | generated by client or session tooling | closure reason |


`__ping__` byte representation

| Representation | Value |
|---|---|
| Text | `__ping__` |
| Hex | `5f 5f 70 69 6e 67 5f 5f` |
| Length | `8` |

this is likely handled by the session gateway and not forwarded to the shell, since it appeared only in WebSocket text artifacts and never echoed in PTY output.

<a id="id-section-4-2"></a>
### 4.2 Message types

| Message type | Direction | Payload type(s) seen | Inputs | Output artifacts |
|---|---|---|---|---|
| `input_stream_data` | client -> server | `3`, `1` | PTY geometry JSON or command bytes plus sequence/message IDs | server ACKs and later shell output |
| `output_stream_data` | server -> client | `1` | none from client | prompt text, command output, ANSI controls, transfer helper status |
| `acknowledge` | bidirectional | `0`, `1` | original message metadata | delivery confirmation and sequence accounting |
| `channel_closed` | server -> client | observed in download trace | generated by server/session lifecycle | WebSocket close/lifecycle indication |

<a id="id-section-4-3"></a>
### 4.3 ACK payload fields

| Field | Meaning |
|---|---|
| `AcknowledgedMessageType` | original message type |
| `AcknowledgedMessageId` | original message UUID-like ID |
| `AcknowledgedMessageSequenceNumber` | original sequence |
| `IsSequentialMessage` | sequencing hint |

<a id="id-section-4-4"></a>
### 4.4 Command encoding

| Pattern | Observation |
|---|---|
| keystroke framing | some interactive sessions send one byte per key |
| line framing | upload/download helpers send longer command strings |
| Enter | carriage return `0x0d` |

<a id="id-section-4-5"></a>
### 4.5 Terminal control sequences

| Control family | Examples | Meaning |
|---|---|---|
| cursor show/hide | `\x1b[?25l`, `\x1b[?25h` | hide/show cursor |
| bracketed paste | `\x1b[?2004h`, `\x1b[?2004l` | readline paste mode |
| cursor/screen controls | `\x1b[H`, `\x1b[J`, `\x1b[K` | cursor/screen operations |
| device attributes | `\x1b[?1c`, `\x1b[?0c` | terminal negotiation behavior |

<a id="id-section-4-6"></a>
### 4.6 WebSocket text controls

| Artifact | Inputs | Output artifacts | Meaning |
|---|---|---|---|
| `__ping__` | literal `__ping__` | none observed in PTY output | app-layer keepalive |
| `Closed (code=11177)` | generated by client or session tooling | closure reason text | close status text |
| `Closed (code=34945)` | generated by client or session tooling | closure reason text | close status text |
| `Closed (code=3000)` | generated by client or session tooling | closure reason text | close status text |
| `Closed (code=1000)` | generated by client or session tooling | closure reason text | close status text |


<a id="id-section-5"></a>
## 5. File Transfer


Presigned S3 both directions, with **SSE-C** (customer-supplied encryption key) material issued alongside the presigned URL. The PTY runs a `curl` command using that key material directly. Both directions share one field family — `getFileUploadUrls`/`getFileDownloadUrls` return the **same field shape** regardless of direction, a symmetry easy to lose when summarized as prose.

<a id="id-section-5-1"></a>
### 5.1 Upload — browser to CloudShell

| Upload step | Method & Endpoint | Request params | Response fields | Purpose |
|---|---|---|---|---|
| **1** | `getFileUploadUrls` | `EnvironmentId`, `FileUploadPath` | both legs' presigned material in one response — see field table below | obtain the presigned upload target plus the SSE-C key needed to pull it back down |
| **2** | WS existence-precheck | `[ -f path ]` | `EXIT_CODE0`/`EXIT_CODE1` | avoid clobbering/duplicating an existing file before staging |
| **3** | Browser `POST` multipart → `FileUploadPresignedUrl` | `FileUploadPresignedFields` (SSE-C key/MD5, SigV4 POST-policy fields) + file bytes | HTTP 204 | stage the file bytes into the S3 staging bucket |
| **4** | WS `curl` with SSE-C headers | pulls from `FileDownloadPresignedUrl`, SSE-C headers | file written into the shell filesystem | pull the staged object down into the container |
| **5** | WS exit-code check | shell exit-code query | `EXIT_CODE0`/`EXIT_CODE1` | confirm the `curl` succeeded |
| **6** | WS teardown | — | — | end of upload sequence |


**What the shell actually receives.** The table's WS steps arrive as these commands, in this order

```
# Shell commands sent over websocket for upload 
HISTFILE=/dev/null
[ -f "<dest path>" ]                      # step 2
echo EXIT_CODE$?                          
curl --fail -H "x-amz-...-key: ..." ...   # step 4
echo EXIT_CODE$?                          # step 5
exit                                      # step 6
```

<a id="id-section-5-2"></a>
### 5.2 Download — CloudShell to browser

| Download step | Method & Endpoint | Request params | Response fields | Purpose |
|---|---|---|---|---|
| **1** | `getFileDownloadUrls` | `EnvironmentId`, `FileDownloadPath` | both legs' presigned material again — same shape as upload | obtain presigned targets for the shell-side and browser-side legs |
| **2** | WS `curl -F...` staging | multipart POST to `FileUploadPresignedUrl` (shell is the writer this time) | HTTP 204 | shell stages the requested file up into S3 |
| **3** | WS exit-code check | shell exit-code query | `EXIT_CODE0`/`EXIT_CODE1` | confirm staging succeeded |
| **4** | WS `exit`+`logout` teardown | — | — | end the WS session before the browser fetch |
| **5** | Browser `GET FileDownloadPresignedUrl` | SSE-C headers | decrypted file bytes | retrieve the file into the browser |


**What the shell actually receives.** The table's WS steps arrive as these commands, in this order

```
# Shell commands sent over websocket for download 
HISTFILE=/dev/null
curl -F 'key=<uuid4>/<uuid4>' ... <presigned POST>    # step 2
echo EXIT_CODE$?                                      # step 3
exit                                                  # step 4
```

<a id="id-section-6"></a>
## 6. Credential Types


Every credential type answers one question — **who signs, and with what?** — and there are two answers. Each ends in material that can call the CloudShell APIs and open a WebSocket terminal session; they differ in who holds it and who signs with it.

- **Track A** — you hold a key. CloudBasher makes each call itself and signs it itself with SigV4. Steps `A1`–`A18`.
- **Track B** — you hold a logged-in browser session and no secret at all. The console makes the calls and its backend signs them. Steps `B1`–`B11`.

The diagram reads top to bottom in two parts. **The top is the only place credential-specific `N.M` steps appear** — six inputs, converging on one of two things you can hold.

**The most important path on this diagram is `auth → API token with CloudShell permissions`.** Everything below the join is shared; everything above it is a different way of arriving at an `ASIA` triple. An SSO login does not have to end in a browser session, and an endpoint that ends it in a signing key was observed. **Below that the two tracks run as parallel chains**, `A1`–`A18` on the left and `B1`–`B11` on the right, and boxes level with each other are the same call: `A10` and `B6` are one `redeemCode`, differing only in who issues it and who signs it.


| New | Type | `-F` file |
|---|---|---|
| **1** | Console username + password | its credential file |
| **2** | SSO Identity Center username + password | its credential file |
| **3** | Supplied ASIA + session token (`ACT_AS=direct`) | its credential file |
| **4** | AKIA + `ACT_AS=role:<arn>` | its credential file |
| **5** | AKIA + `ACT_AS=federated` | its credential file |
| **6** | AKIA + `ACT_AS=direct-unbound` | its credential file |
| — | SSO device code | *not a type — retired* |
| — | AKIA + `ACT_AS=direct` | *not a type — refused at intake* |

Two things stopped being types, and both keep their box in the diagram because the question "why isn't that a type?" is asked often enough to be worth answering in place: **SSO device code** produces an ASIA triple, which is Type 3 — a longer road to a value already supported, and the only SSO route needing a human. **`ACT_AS=direct` with an AKIA key** is refused by `validate_act_as` as product policy; say `direct-unbound` and the same key works (Type 6).

Step numbers inside each type's own table are keyed to its NEW number. The device-code steps are `D.1`–`D.6`, since it has no number to key to.

**The same six types, condensed to the two answers.** This is the overview; the detailed version below carries the per-type step numbers.

```mermaid
flowchart LR
  C["<b>Console</b><br/>username + password"]
  S["<b>SSO Identity Center</b><br/>login"]
  T["<b>Temp access token</b><br/>ASIA + session token"]
  P["<b>Permanent access key</b><br/>AKIA"]

  C --> BROWSER
  S -.->|"GET /federation/console<br/><i>248 requests — not needed</i>"| BROWSER
  S -->|"GET /federation/credentials<br/>2 requests"| KEY
  T --> KEY
  P -->|"sts:AssumeRole"| KEY
  P -->|"sts:GetFederationToken"| KEY
  P -->|"direct<br/>container gets no IAM binding"| KEY

  BROWSER["<b>Browser console session</b><br/>the console signs on your behalf"]
  KEY["<b>SigV4 signing key</b><br/>you sign every call yourself"]

  BROWSER --> ID
  KEY --> ID
  ID["<b>Caller Identity</b>"] --> REST["<b>REST control plane</b> →<br/>"]
```

- **SSO normally ends in a key, not a console session.** `GET /federation/credentials` returns an `ASIA` triple in 2 requests. The console-session exit (`GET /federation/console`) still works and reaches the same place by way of `presign` and `browserCreds`, but costs 248 requests — 124x more, measured; the derivation is in [§7](#id-section-7) below. It is drawn dashed because it is available, not because it is taken.

<a id="id-section-7"></a>
## 7. Authentication Flows

```mermaid
flowchart TD
    subgraph SUPPLIED["1 · CREDENTIAL TYPE — the part that differs per credential type. Step numbers here are N.M = type N, step M."]
        T1["<b>Type 1</b> · Console username + password&nbsp;&nbsp;<i>creds1</i><br/><b>1.1</b> signin form login, then <b>1.2</b> open the CloudShell widget"]
        T2["<b>Type 2</b> · SSO Identity Center username + password&nbsp;&nbsp;<i>creds2</i><br/><b>2.1</b> portal login — the ONLY step that needs a browser<br/><b>2.2</b> POST /auth/sso-token → bearer (1519 chars)<br/><b>2.6a</b> GET /federation/credentials → ASIA triple<br/><i>no device code, no console session</i>"]
        T3["<b>Type 3</b> · Supplied ASIA + session token, ACT_AS=direct&nbsp;&nbsp;<i>creds3</i><br/>nothing to derive: the caller already holds the signing key"]
        T4["<b>Type 4</b> · AKIA key, ACT_AS=role:ARN&nbsp;&nbsp;<i>creds4</i><br/><b>4.1</b> sts:AssumeRole"]
        T5["<b>Type 5</b> · AKIA key, ACT_AS=federated&nbsp;&nbsp;<i>creds5</i><br/><b>5.1</b> sts:GetFederationToken"]
        T6["<b>Type 6</b> · AKIA key, ACT_AS=direct-unbound&nbsp;&nbsp;<i>creds6</i><br/><b>6.1</b> REST control plane signs fine with the raw permanent key<br/><b>6.2</b> putCredentials is SKIPPED — no in-shell aws, by declaration<br/><b>6.3</b> createSession → a real working terminal"]
        DEV["<i>SSO device code — NOT a credential type</i><br/>retired 2026-08-19: its whole output is an ASIA triple, which is<br/>Type 3. Steps <b>D.1–D.6</b> are kept documented, not built on"]
        REFUSED["<i>AKIA key + ACT_AS=direct — NOT a credential type</i><br/>refused at intake by validate_act_as(). Product policy, not a<br/>protocol limit: say direct-unbound (Type 6) and it works"]
    end

    T1 --> BROWSER
    T2 --> PORTAL
    T3 --> KEY
    T4 --> KEY
    T5 --> KEY
    T6 --> KEY
    DEV -.->|"same endpoint, different bearer source"| PORTAL
    REFUSED --> STOP

    PORTAL["<b>THE SSO JOIN POINT</b> — portal.sso.REGION.amazonaws.com, an ordinary JSON API<br/>POST /auth/sso-token → the bearer. Authenticates on the session cookie x-amz-sso_authn plus an x-amz-sso-csrf-token header<br/>GET /federation/credentials → ASIA + secret + session token &nbsp;←&nbsp; <b>TAKE THIS.</b> 2 requests<br/>GET /federation/console → a console session instead, then presign/browserCreds. NOT needed. 248 requests<br/>Bearer header MEASURED interchangeable: authorization: Bearer TOKEN and x-amz-sso_bearer_token: TOKEN both 200; bare authorization is 401"]
    PORTAL --> KEY

    KEY["<b>You hold a SIGNING KEY</b> — we sign every call ourselves, SigV4<br/>ASIA + secret + session token, except Type 6, which signs with the raw AKIA"]
    BROWSER["<b>You hold a BROWSER SESSION</b> — no secret, ever<br/>the console's backend signs for us via POST /api/prod/presign"]
    STOP["<b>Stops here.</b>"]

    KEY --> A1
    BROWSER --> B1
    STOP -.->|"gate bypassed — probe only"| A1

    subgraph SHARED["2 · THE SHARED PROTOCOL — two tracks, the same five calls. Rows level with each other are the same call."]
        A1["<b>A1</b> sts:AssumeRole / sts:GetFederationToken<br/><i>upgrade AKIA → ASIA</i>"]
        A26["<b>A2–A6</b> describeEnvironments · createEnvironment ·<br/>getEnvironmentStatus · startEnvironment · poll RUNNING"]
        A78["<b>A7 · A8</b> federation getSigninToken, then login<br/><i>→ aws-creds cookie</i>"]
        A9["<b>A9</b> OAuth PKCE broker → AuthCode"]
        A10["<b>A10</b> redeemCode → RefreshToken"]
        A11["<b>A11</b> putCredentials → in-shell aws credentials<br/><i>the only call type 6 fails: its shell still works, but the</i><br/><i>container credential agent on :1338 stays empty</i>"]
        A12["<b>A12</b> createSession → SessionId + StreamUrl + TokenValue<br/>SessionType TMUX / BASH / EXTENSIONS_BRIDGE"]
        A13["<b>A13</b> WS token envelope"]
        A16["<b>A14–A16</b> resize · output · input frames"]

        B1["<b>B1</b> browser console login"]
        B2["<b>B2</b> browserCreds → temporary keys<br/><i>which never sign CloudShell</i>"]
        BENV["<i>no B step</i> — the console's own JS resolves<br/>the environment. We only watch, and capture<br/>the environment id off the wire"]
        B3["<b>B3</b> presign → signed headers for B4"]
        B4["<b>B4</b> OAuth PKCE broker → AuthCode<br/><i>browser-navigated, not API-called</i>"]
        B5["<b>B5</b> presign → signed headers for B6"]
        B6["<b>B6</b> redeemCode → RefreshToken"]
        B7["<b>B7</b> presign → signed headers for B8"]
        B8["<b>B8</b> putCredentials"]
        B9["<b>B9</b> presign → signed headers for B10"]
        B10["<b>B10</b> createSession"]
        B11["<b>B11</b> WS session start<br/><i>its TokenValue is not reusable by us —<br/>a FRESH createSession is required</i>"]

        A1 --> A26 --> A78 --> A9 --> A10 --> A11 --> A12 --> A13 --> A16
        B1 --> B2 --> BENV --> B3 --> B4 --> B5 --> B6 --> B7 --> B8 --> B9 --> B10 --> B11
    end

    A16 --> SHELL
    B11 --> SHELL
    SHELL["<b>The CloudShell container — a real shell on BOTH tracks</b>"]

    SHELL --> KEEP
    KEEP["<b>Keep it alive — all three layers, both tracks</b><br/>sendHeartBeat · ws __ping__ · webapp/connected @ 5.00 s<br/>plus container credential refresh, ~10 min TTL<br/>idle without them → SUSPENDING in 10–20 min"]


    classDef trackA fill:#dbeafe,stroke:#1d4ed8,color:#0c1e3e
    classDef trackB fill:#fef3c7,stroke:#b45309,color:#3b2300
    classDef both fill:#dcfce7,stroke:#15803d,color:#052e16
    classDef bad fill:#fee2e2,stroke:#b91c1c,color:#450a0a

    class KEY,A1,A26,A78,A9,A10,A11,A12,A13,A16 trackA
    class BROWSER,B1,B2,BENV,B3,B4,B5,B6,B7 trackB
    class SHELL,KEEP both
    class STOP bad
```

**Three numbering schemes, and how they relate.** This is the part that confuses every first reader, so it is stated flatly rather than implied

| Label | Means | Where the detail is |
|---|---|---|
| `N.M` — e.g. `3.4` | step *M* of **credential type** *N* | the per-type tables in §7 |
| `A1`–`A18` | a step of the **shared API track** | §7 "Path A" table |
| `B1`–`B11` | a step of the **shared browser track** | §7 "Path B" table |

They are two views of the same traffic: `N.M` numbers what a *credential type* does, `A#`/`B#` number what the *protocol* does. Each type runs one track, and its own steps land on that track like this


| Type | Track | How its `N.M` steps map onto the track |
|---|---|---|
| **1** | A | `1.1` is the `GetFederationToken` half of `A1`; everything after is `A2`–`A18` unchanged |
| **2** | A | `2.1` is the `AssumeRole` half of `A1`; then `A2`–`A18` unchanged |
| **3** | B | `3.1`=`B1` · `3.2` opens the widget that drives `B4`–`B10` · `3.3` is the environment resolution **track B has no number for** · `3.4` = `B4`+`B6`+`B8` together · `3.5`=`B10` · `3.6` is the capture, ours alone · `3.7` is the shell |
| **4** | B | `4.1`–`4.3` replace `3.1`; from `3.2` onward it *is* type 1 |
| **5** | A | not built. Would produce `A1`'s output by a different route, then `A2`–`A18` |
| **6** | A (blocked) | refused at intake. If the gate is bypassed it runs `A1`–`A18` with `A11` the only failing step |

<a id="id-section-7-1"></a>
### 7.1 Track A, step by step

*Four rules hold across the table, so the cells do not repeat them. **Method** and **Endpoint** are given for every REST call; a WebSocket step names the frame and the `StreamUrl` it travels on instead. **Signed by** names what makes the call acceptable to the endpoint — the thing that fails if it is absent — because on this protocol the caller and the signer are not always the same party. **Request** and **Response** list the literal wire fields; anything that is commentary rather than a field is prefixed `NOTE:`.

| Track A step | Method | Endpoint | Signed by | Request fields | Response fields | Purpose |
|---|---|---|---|---|---|---|
| **A1** | `POST` (form-encoded) | `https://sts.amazonaws.com/` | **us** — SigV4, `service=sts`, `region=us-east-1` (the global endpoint signs there regardless of the CloudShell region, `sts.py:35`), using the **long-term AKIA** key | `Action` = `AssumeRole` or `GetFederationToken`, `Version=2011-06-15`; then `RoleArn`, `RoleSessionName`, `DurationSeconds` (AssumeRole) or `Name`, `Policy`, `DurationSeconds` (GetFederationToken) | `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration` | upgrades static/long-term keys to ASIA. **NOTE: permanent keys only.** Happens lazily on the first CloudShell request (step A2) via `_api_creds`, and is cached for the client's lifetime — both sub-paths confirmed to succeed, see the `putCredentials` matrix below |
| **A2** | `POST` | `https://cloudshell.<region>.amazonaws.com/describeEnvironments` | **us** — SigV4, `service=cloudshell`, with A1's ASIA | (body empty; a zero-length body is accepted here, [§4.4](#id-section-4-4)) | `Environments`, each with `EnvironmentId`, `Status` | discover existing environment. **NOTE: scoped to the *calling principal*** — an environment created by a different identity is invisible here, even in the same account |
| **A3** | `POST` | `https://cloudshell.<region>.amazonaws.com/createEnvironment` | **us** — SigV4, `service=cloudshell`, with A1's ASIA | body must be the two bytes `{}` — a zero-length body returns 400 ([§4.4](#id-section-4-4)) | `EnvironmentId` | allocate environment if none found. **NOTE: conditional.** Only reached when the invocation actually needs a container — `--enum`/`--perms` are control-plane-only and never get here |
| **A4** | `POST` | `https://cloudshell.<region>.amazonaws.com/getEnvironmentStatus` | **us** — SigV4, `service=cloudshell`, with A1's ASIA | `EnvironmentId` | `Status` | check current state |
| **A5** | `POST` | `https://cloudshell.<region>.amazonaws.com/startEnvironment` | **us** — SigV4, `service=cloudshell`, with A1's ASIA | `EnvironmentId` | (no documented body) | resume a `SUSPENDED`/`STOPPED` environment. **NOTE: conditional** |
| **A6** | `POST` | `https://cloudshell.<region>.amazonaws.com/getEnvironmentStatus` | **us** — SigV4, `service=cloudshell`, with A1's ASIA | `EnvironmentId` | `Status` | poll until `RUNNING` |
| **A7** | `GET` | `https://signin.aws.amazon.com/federation?Action=getSigninToken` | **nothing signs it — the credential material IS the request.** *Observed in the implementation 2026-09-13, a probe: the URL is built with a plain `urlencode` and opened with no `Authorization` header* | `Action=getSigninToken`, `SessionType=json`, `Session` = JSON `{sessionId, sessionKey, sessionToken}` carrying A1's ASIA verbatim | `SigninToken` | prime a console-equivalent sign-in token. **NOTE: `sessionToken` must be present even for permanent keys** — send `""`, because omitting the field returns HTTP 400 |
| **A8** | `GET` | `https://signin.aws.amazon.com/federation?Action=login` | **the `SigninToken` from A7** — a bearer value in the query string, not a signature | `Action=login`, `SigninToken`, `Issuer`, `Destination` | `Set-Cookie` — the `aws-creds` console session cookie jar | establish the console session the broker's redirect chain needs |
| **A9** | `GET` | `https://auth.cloudshell.<region>.aws.amazon.com/oauth` | **us** — SigV4, `service=cloudshell`, with A1's ASIA. **NOTE: the `aws-creds` cookie from A8 rides the redirect chain but does NOT authorise the call.** A four-rung ladder settled it: cookie alone → `403 Missing Authentication Token`; cookie + the full widget header set → byte-identical 403; signed headers with no widget headers → 200 and the auth code | `client_id=arn:aws:signin:::console/scallop-shell`, `codeVerifier` (**misnamed — it carries the PKCE *challenge***, see the PKCE table), `redirect_uri`, `state`, `EnvironmentId` | `AuthCode`, extracted from the `callback.js` redirect | drive the PKCE broker exchange. **NOTE:** the broker re-signs the downstream request to `{region}.signin.aws.amazon.com/oauth` using CloudShell's own service credentials |
| **A10** | `POST` | `https://cloudshell.<region>.amazonaws.com/createSession` | **us** — SigV4, `service=cloudshell`, with A1's ASIA | `EnvironmentId`, `SessionType`, and `TabId` **only when `SessionType=TMUX`** ([§3.1](#id-section-3-1)) | `SessionId`, `StreamUrl`, `TokenValue` | mint WS session + initial auth envelope. `AWSCloudShellAPI.open_stream` — named to avoid colliding with `CSPProvider.create_session`, which builds the session *object*. **NOTE: ORDER CORRECTED 2026-08-16** — this row was A12, *after* `redeemCode` and `putCredentials`. Both sources disagree with that and agree with each other: the reference implementation posts `createSession` first, and the native restart capture shows `createSession` +25.07 → `redeemCode` +25.55 → `putCredentials` +25.80. CloudBasher implemented this table faithfully and inherited the bug: inverted, the shell handshakes, warmup reports a prompt, and the first command is swallowed — 36 s for `export i=1`, a builtin that needs no credentials at all. What is projected is credentials for the AWS CLI *inside* the container, so nothing about opening the session depends on it |
| **A11** | `POST` | `https://cloudshell.<region>.amazonaws.com/redeemCode` | **us** — SigV4, `service=cloudshell`, with A1's ASIA | `EnvironmentId`, `AuthCode`, `CodeVerifier`, `RedirectUri`, `KeyBase` | `RefreshToken` — and **only** that | exchange the OAuth auth code for a refresh token. **NOTE:** the response carries no expiry of any kind) |
| **A12** | `POST` | `https://cloudshell.<region>.amazonaws.com/putCredentials` | **us** — SigV4, `service=cloudshell`, with A1's ASIA — **but it AUTHORIZES on the OAuth session identity carried by `RefreshToken`, not on the SigV4 signer.** That split is why a raw permanent key reaches a shell and still cannot populate it (H-7) | `EnvironmentId`, `RefreshToken`, `KeyBase` | success / request ID | install exchanged credentials into the container credential provider. **NOTE:** 200 for both assumed-role and federated-user OAuth identities (corrected 2026-07-19 — see the live-verification note above) |
| **A13** | WS frame | `wss://` — the `StreamUrl` from A10 | **the `TokenValue` from A10**, in the envelope itself; no SigV4 anywhere on the WebSocket | `MessageSchemaVersion`, `RequestId`, `TokenValue` | ack | first frame sent after WS connect |
| **A14** | WS frame | `wss://` — the `StreamUrl` from A10 | (already authenticated by A13) | payload type 1, cols, rows | ack | set PTY dimensions |
| **A15** | WS frame | `wss://` — the `StreamUrl` from A10 | (already authenticated by A13) | — | PTY stdout/stderr bytes | shell output stream |
| **A16** | WS frame | `wss://` — the `StreamUrl` from A10 | (already authenticated by A13) | keystrokes / command bytes | — | shell input stream |
| **A17** | `GET` | `$AWS_CONTAINER_CREDENTIALS_FULL_URI` (in-container, `169.254.170.2:1338`) | **the container's own credential agent**, populated by A12; the caller inside the shell presents `$AWS_CONTAINER_AUTHORIZATION_TOKEN` | — | short-lived credentials, TTL ~10 min | ongoing — the container's own credential provider refresh, independent of the WS session |
| **A18** | WS frame **+** `POST` | `wss://` `__ping__` text frame **and** `https://cloudshell.<region>.amazonaws.com/sendHeartBeat` | ping: none. `sendHeartBeat`: **us** — SigV4, `service=cloudshell`, with A1's ASIA | `EnvironmentId` and session context | success / request ID | ongoing — prevents idle/session teardown (detail in [§8](#id-section-8)). **NOTE: defers suspension but never reverses one** |

<a id="id-section-7-2"></a>
### 7.2 Track B, step by step

*Same four rules as Track A. The column that matters most here is **Signed by**: on track B we are never the signer. Every `cloudshell.<region>.amazonaws.com` call below is signed by `/api/prod/presign`, one presign per call ([§7.2](#id-section-7-2) note below), and presign itself is authorised by the console session — not by any key we hold.

| Track B step | Method | Endpoint | Signed by | Request fields | Response fields | Purpose |
|---|---|---|---|---|---|---|
| **B1** | `GET`/`POST` (interactive) | `https://signin.aws.amazon.com/` or an IdP-issued federated URL | **the human, or the IdP** — password/MFA, or a federation assertion | username, password, MFA code — or the federated sign-in URL | console session cookies, and the per-session `x-console-api-token` | establish browser-side console identity |
| **B2** | `POST` | `https://<region>.console.aws.amazon.com/api/prod/browserCreds` | **the console session** — cookies **plus the console's own request headers**; a bare POST carrying only `content-type` gets 401 | (no body fields; the headers are the request) | `accessKeyId`, `secretAccessKey`, `sessionToken`, `expiration` | pull temporary credentials out of the browser session. **NOTE: these DO NOT sign CloudShell — tested 2026-09-13**, a vended ASIA signing `describeEnvironments` gets HTTP 403 Access Denied (H-3). B2 is on the path because the console makes the call, not because track B needs its output |
| **B3** | `POST` | `https://<region>.console.aws.amazon.com/api/prod/presign` | **the console session** — the cookie jar plus `x-console-api-token`, `x-console-info`, `x-widget-id`, `x-widget-stage`, `x-web-client-version`. A bare POST carrying only `content-type` gets 401 | **Headers:** the five above, plus cookies, plus `origin`/`referer` = `https://cloudshell.widget.console.aws.amazon.com`. **Body:** the DESCRIPTOR of the call to be signed — `service=cloudshell`, `region`, `method=GET`, `protocol=https:`, `hostname=auth.cloudshell.<region>.aws.amazon.com`, `path=/oauth`, `headers`, `query`. The client fills `authorization` and `x-amz-security-token` inside `headers` with the literals `PLACEHOLDER_ACCESS_KEY_ID` / `PLACEHOLDER_SESSION_TOKEN` | **Body:** `{headers: {authorization, x-amz-security-token, x-amz-date, x-amz-content-sha256, host, …}}` — the same header set, SIGNED. **NOTE: headers, never credentials** — the signing key's secret never enters the browser | sign **B4**. One presign per signed call: a capture counted 116 against 116, another 63 against 63, nothing unmatched |
| **B4** | `GET` | `https://auth.cloudshell.<region>.aws.amazon.com/oauth` | **`/api/prod/presign`**, signing `service=cloudshell` — and presign will sign a **GET** on `auth.cloudshell.<region>`, which the earlier 13-POST census had never established | `client_id=arn:aws:signin:::console/scallop-shell`, `codeVerifier` (carries the challenge), `redirect_uri`, `state`, `EnvironmentId` | `AuthCode` | the CloudShell widget drives the same PKCE broker exchange as **A9**, browser-navigated rather than API-called |
| **B5** | `POST` | `https://<region>.console.aws.amazon.com/api/prod/presign` | **the console session** — the cookie jar plus `x-console-api-token`, `x-console-info`, `x-widget-id`, `x-widget-stage`, `x-web-client-version`. A bare POST carrying only `content-type` gets 401 | **Headers:** the five above, plus cookies, plus `origin`/`referer` = `https://cloudshell.widget.console.aws.amazon.com`. **Body:** the DESCRIPTOR of the call to be signed — `service=cloudshell`, `region`, `method=POST`, `protocol=https:`, `hostname=cloudshell.<region>.amazonaws.com`, `path=/redeemCode`, `headers`, `query`. The client fills `authorization` and `x-amz-security-token` inside `headers` with the literals `PLACEHOLDER_ACCESS_KEY_ID` / `PLACEHOLDER_SESSION_TOKEN` | **Body:** `{headers: {authorization, x-amz-security-token, x-amz-date, x-amz-content-sha256, host, …}}` — the same header set, SIGNED. **NOTE: headers, never credentials** — the signing key's secret never enters the browser | sign **B6**. One presign per signed call: a capture counted 116 against 116, another 63 against 63, nothing unmatched |
| **B6** | `POST` | `https://cloudshell.<region>.amazonaws.com/redeemCode` | **`/api/prod/presign`** — signed headers, one presign call for this one signed call | `EnvironmentId`, `AuthCode`, `CodeVerifier`, `RedirectUri`, `KeyBase` | `RefreshToken` | same call as Path A **A11** |
| **B7** | `POST` | `https://<region>.console.aws.amazon.com/api/prod/presign` | **the console session** — the cookie jar plus `x-console-api-token`, `x-console-info`, `x-widget-id`, `x-widget-stage`, `x-web-client-version`. A bare POST carrying only `content-type` gets 401 | **Headers:** the five above, plus cookies, plus `origin`/`referer` = `https://cloudshell.widget.console.aws.amazon.com`. **Body:** the DESCRIPTOR of the call to be signed — `service=cloudshell`, `region`, `method=POST`, `protocol=https:`, `hostname=cloudshell.<region>.amazonaws.com`, `path=/putCredentials`, `headers`, `query`. The client fills `authorization` and `x-amz-security-token` inside `headers` with the literals `PLACEHOLDER_ACCESS_KEY_ID` / `PLACEHOLDER_SESSION_TOKEN` | **Body:** `{headers: {authorization, x-amz-security-token, x-amz-date, x-amz-content-sha256, host, …}}` — the same header set, SIGNED. **NOTE: headers, never credentials** — the signing key's secret never enters the browser | sign **B8**. One presign per signed call: a capture counted 116 against 116, another 63 against 63, nothing unmatched |
| **B8** | `POST` | `https://cloudshell.<region>.amazonaws.com/putCredentials` | **`/api/prod/presign`** for the SigV4 half; **authorization is still on the OAuth session identity** in `RefreshToken` | `EnvironmentId`, `RefreshToken`, `KeyBase` | success / request ID | same call as Path A **A12**. **NOTE:** 200 per the matrix above |
| **B9** | `POST` | `https://<region>.console.aws.amazon.com/api/prod/presign` | **the console session** — the cookie jar plus `x-console-api-token`, `x-console-info`, `x-widget-id`, `x-widget-stage`, `x-web-client-version`. A bare POST carrying only `content-type` gets 401 | **Headers:** the five above, plus cookies, plus `origin`/`referer` = `https://cloudshell.widget.console.aws.amazon.com`. **Body:** the DESCRIPTOR of the call to be signed — `service=cloudshell`, `region`, `method=POST`, `protocol=https:`, `hostname=cloudshell.<region>.amazonaws.com`, `path=/createSession`, `headers`, `query`. The client fills `authorization` and `x-amz-security-token` inside `headers` with the literals `PLACEHOLDER_ACCESS_KEY_ID` / `PLACEHOLDER_SESSION_TOKEN` | **Body:** `{headers: {authorization, x-amz-security-token, x-amz-date, x-amz-content-sha256, host, …}}` — the same header set, SIGNED. **NOTE: headers, never credentials** — the signing key's secret never enters the browser | sign **B10**. One presign per signed call: a capture counted 116 against 116, another 63 against 63, nothing unmatched |
| **B10** | `POST` | `https://cloudshell.<region>.amazonaws.com/createSession` | **`/api/prod/presign`** | `EnvironmentId`, `SessionType`, `TabId` (TMUX only) | `SessionId`, `StreamUrl`, `TokenValue` | same call as Path A **A10**. **NOTE:** a *captured* `TokenValue` is dead to us once the browser disconnects; a **fresh** `createSession` signed via presign is not — see fact 4 below |
| **B11** | WS frame | `wss://` — the `StreamUrl` from B10 | **the `TokenValue` from B6**, in the envelope | `MessageSchemaVersion`, `RequestId`, `TokenValue` | ack | shell session begins |

**And what signs presign itself.** `/api/prod/presign` is a `POST` to `https://<region>.console.aws.amazon.com/api/prod/presign`, authorised by the console session cookie plus two headers, and the distinction between them is load-bearing

| Header | Scope | Forgeable? |
|---|---|---|
| `x-console-api-token` | **SESSION** — one fingerprint across eight widgets and two regions in one session) | replayed from any presign the console itself made |

<a id="id-section-8"></a>
## 8. Sessions


**Session types** — every distinct session/token concept in the AWS flow, browser-side, API-side, and container/WS-side

| Session type | Identifier | Auth mechanism | Lifetime | Trackable? |
|---|---|---|---|---|
| Browser console session | `aws-creds` cookie (federation login) | Cookie-based, from `getSigninToken`/`login` | Standard AWS console session duration | Via AWS console sign-in activity |
| CloudShell environment | `EnvironmentId` | IAM-controlled (`cloudshell:*` actions) | Persistent per region/account — survives across sessions (see Persistence below) | Via CloudTrail (`DescribeEnvironments`, etc.) |
| Terminal session | `SessionId` (from `createSession`) | `TokenValue` bootstrap | Per `createSession` call | `createSession` appears in CloudTrail |
| WebSocket bootstrap token | `TokenValue` | Bearer-equivalent, sent in the token-envelope frame | Session-scoped, tied to one WS connection | Not logged in customer CloudTrail |
| OAuth refresh material | `RefreshToken` (from `redeemCode`) | OAuth/PKCE exchange | Persistent until credential projection changes | Capture-only; not in CloudTrail |
| In-container credentials | via `AWS_CONTAINER_CREDENTIALS_FULL_URI` | Container credential provider | ~10 min TTL, auto-refreshed via `RefreshToken` | Distinct STS token visible via `aws sts get-caller-identity` in-shell |

<a id="id-section-8-1"></a>
### 8.1 IAM credentials and sessions


Three kinds of session and the credential shapes that convert between them. A console login yields an API session; an API session yields STS-derived credentials; and a federated URL turns those back into a console session.

```
  Console Session  <──────────────────────────────────────────────────────────────────────┐
          │                                                                               │
  IAM     │ Identity                                                                      │
  Console │ Center                                                                        │
  ═══════ │ ════════                                                                      │
          │ SSO        Perm Keys                                                          │
          v            ═════════                 ─┬──> sts::getSessionToken               │
  API Session ───┬──>  AWS_ACCESS_KEY_ID="AKIA…"  │                                       │
                 │     AWS_SECRET_ACCESS_KEY      ├──> sts::getFederationToken ─┐         │
                 │                                │                             ├─> Federated URL
                 │                                │                             │   ═════════════ 
                 │     Temp Tokens                │                             │   └─> Console
                 │     ═══════════             ───┴──> sts::assumeRole* ────────┘         ^
                 └───> AWS_ACCESS_KEY_ID="ASIA…"       ════════════════                   │
                       AWS_SECRET_ACCESS_KEY           └─> assumeRole                     │
                       AWS_SESSION_TOKEN                   └─> assumeRole ───────────────>│
                            │                                                             │
                            └─────────────────────────────────────────────────────────────┘

  Terminal Session

```

Solid arrows are the paths taken; dashed arrows are alternatives from the same credential.

<a id="id-section-8-2"></a>
### 8.2 Flows between the three session kinds

- **Console → API.** Either an IAM console login or an Identity Center (SSO) login gets you to an API session. That session holds one of two credential shapes.
- **API → STS.** Permanent keys can call `sts::getSessionToken`, `sts::getFederationToken` or `sts::assumeRole*`. Temp tokens, already being a session credential, can only chain further `assumeRole` calls — the asterisk and the two `--> assumeRole` lines mark that role chaining is repeatable.
- **STS → Console.** `getFederationToken` and `assumeRole` both produce material for a **federated URL**, which opens a console session. A temp token reaches the same place directly, without any further STS call — the long path along the bottom.
- **And back again.** The federated URL returns to `Console Session` at the top, so the cycle closes: console → API → STS → console. Nothing in the loop requires a password after the first step.

<a id="id-section-8-3"></a>
### 8.3 Revocation does not reach the WebSocket


There are three different sessions: Console, API, and WebSocket. Typical revocation procedures target Console and API but do not revoke the WebSocket, so there is a window or unauthenticated persistence that is allowed to the container post-revocation.

<a id="id-section-9"></a>
## 9. IAM Permission Model


CloudShell-specific IAM actions — a slice of the general AWS IAM model. Session revocation and policy evaluation are covered in the broader IAM material

| Action | Required to launch | Description |
|---|---|---|
| `cloudshell:CreateEnvironment` | **Yes** | Create environment; retrieve and save layout |
| `cloudshell:CreateSession` | **Yes** | Connect to environment from the console |
| `cloudshell:GetEnvironmentStatus` | **Yes** | Read environment status |
| `cloudshell:StartEnvironment` | **Yes** | Start a stopped environment |
| `cloudshell:PutCredentials` | No | Forward console credentials into the shell (enables in-shell `aws` CLI) |
| `cloudshell:GetFileUploadUrls` | No | Generate presigned S3 URLs for GUI file upload (not available in VPC environments) |
| `cloudshell:GetFileDownloadUrls` | No | Generate presigned S3 URLs for GUI file download (not available in VPC environments) |
| `cloudshell:DescribeEnvironments` | No | Describe environments |
| `cloudshell:StopEnvironment` | No | Stop a running environment |
| `cloudshell:DeleteEnvironment` | No | Delete an environment |
| `cloudshell:ApproveCommand` | No | Approve command sent from other AWS service consoles |
| `cloudshell:SendHeartBeat` | No | Keep the environment alive / suppress idle suspension. **Added 2026-08-14** — observed in the flow ([§2](#id-section-2)) and in CloudTrail ([§3](#id-section-3)), but absent from this table until now, which is why [§2](#id-section-2) could not simply defer to it |

`AWSCloudShellFullAccess` (AWS-managed) grants all CloudShell actions via `cloudshell:*`; `ReadOnlyAccess` does **not** include CloudShell — it's granted only by `AWSCloudShellFullAccess` and `AdministratorAccess`. VPC-mode CloudShell additionally needs `ec2:DescribeVpcs`/`DescribeSubnets`/`DescribeSecurityGroups`/`DescribeDhcpOptions`/`DescribeNetworkInterfaces`/`CreateTags`/`CreateNetworkInterface`/`CreateNetworkInterfacePermission` (+ optionally `DeleteNetworkInterface` for self-cleanup of ENIs), scopable via condition keys `cloudshell:VpcIds`/`cloudshell:SubnetIds`/`cloudshell:SecurityGroupIds`.

<a id="id-section-9-1"></a>
### 9.1 Minimal privileges


The **minimum permissions** to launch CloudShell with credential forwarding, no GUI file transfer

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudShellMinimal",
      "Effect": "Allow",
      "Action": [
        "cloudshell:CreateEnvironment",
        "cloudshell:StartEnvironment",
        "cloudshell:GetEnvironmentStatus",
        "cloudshell:CreateSession",
        "cloudshell:PutCredentials"
      ],
      "Resource": "*"
    }
  ]
}
```

<a id="id-section-9-2"></a>
### 9.2 Container credential binding


`putCredentials` binds the IAM user within the CloudShell container. This appears to be done via the [Container Credential Provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html) service similar to an EC2/Cluster IMDS.
- Cached token returned, refreshed ~20-30mins
- Token revocation invalidates the binding

**Environment Variables**

| Item | Where | Used by |
|---|---|---|
| `AWS_CONTAINER_CREDENTIALS_FULL_URI` | inside CloudShell | AWS CLI / SDK credential provider |
| `AWS_CONTAINER_AUTHORIZATION_TOKEN` | inside CloudShell | container credential provider auth |

<a id="id-section-10"></a>
## 10. Threat Modeling

The order is **what exists** — boundaries, surface, policies, what would be detected — then **what defeats it**, then **what to add**, so the abuse scenarios sit immediately before the recommendations that answer them.

<a id="id-section-10-1"></a>
### 10.1 Attack Surface


##### Sensitive artifacts in the auth chain

| Artifact | Risk |
|---|---|
| `AuthCode` | OAuth/PKCE credential material |
| `CodeVerifier` | OAuth/PKCE verifier secret |
| `RedirectUri` | binds the redirect flow; useful in a replay context |
| `KeyBase` | browser-side credential/context material |
| `RefreshToken` | persistent credential material with replay risk |
| `TokenValue` | session transport secret for the WebSocket bootstrap; short-lived session replay if exposed |
| Federated sign-in URL / token material | console-session bearer material |
| presigned POST/GET material and the SSE-C key | staged-object retrieval — see the risk register and the normative-controls table in [§5](#id-section-5) |
| browser-visible credentials (`browserCreds`) | credential exposure risk |
| raw PTY command lines | can contain presigned URLs, SSE-C keys and shell commands |

None of these should be logged raw; cached auth artifacts should be stored outside git with restrictive permissions.

##### Risk register (file transfer)

| Risk | Severity | Notes |
|---|---|---|
| Presigned GET URL + SSE-C key replay within 1800 seconds | High | both secrets travel together in the same API response and PTY frames |
| SSE-C key exposure across multiple channels | High | HTTP response body, S3 POST form fields, PTY `curl -H` arguments, session logs |
| Download URL issued before upload validation | High | race, partial upload, or content substitution will be delivered to the PTY |
| Multi-tenant shared bucket with no customer audit visibility | High | S3 object-level events are in AWS's CloudTrail, not the customer's |
| Content-length-range 0–1 GB, no integrity binding | Medium | no size or checksum check between the two transfer legs |
| PTY path injection via `FileUploadPath`/`FileDownloadPath` | Medium | caller-supplied path embedded in shell command; sanitization unconfirmed |
| Object overwrite via predictable key | Low | keys are server-generated UUIDv4; not predictable from any observed input |
| Cross-object write via POST policy | Low | policy `key` condition is exact-match; one credential set cannot write to another key |
| General bucket read or write via single presigned URL | Low | S3 cryptographic scoping holds; path, method, and signature are bound |

the narrative "Threat model" bullets immediately below give the prose form of the top rows of this register; both are about the file-transfer mechanics in [§5](#id-section-5).

**Threat model**
- **High**: presigned-GET + SSE-C key replay within the ~1800s expiry window; SSE-C key exposure across multiple channels simultaneously (HTTP response body, S3 POST form body, PTY `curl -H` arguments, and session logs) — see the cross-cutting mechanism in [§5](#id-section-5).
- **Medium**: unsanitized `FileUploadPath`/`FileDownloadPath` — potential PTY command injection via path parameters.
- Gaps: no post-upload integrity/checksum binding; no customer-visible CloudTrail logging into the shared staging bucket.

##### Threat themes

| Theme | Why it matters |
|---|---|
| token replay | stolen `TokenValue` could allow short-lived session attachment |
| confused deputy | service-generated transfer capabilities move data into or out of the environment |
| credential persistence risk | browser credentials and in-shell credentials are both protocol-relevant |
| logging-as-secret-store | session logs may improve forensics while also capturing presigned artifacts and SSE-C keys |
| PATH / shell-state influence | helper commands use bare `curl`, not an absolute path |


<a id="id-section-10-2"></a>
### 10.2 Access Policies


Deny CloudShell entirely (SCP or inline)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyCloudShell",
      "Effect": "Deny",
      "Action": "cloudshell:*",
      "Resource": "*"
    }
  ]
}
```

Deny only GUI file transfer (allow shell, block upload/download)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCloudShell",
      "Effect": "Allow",
      "Action": "cloudshell:*",
      "Resource": "*"
    },
    {
      "Sid": "DenyFileTransfer",
      "Effect": "Deny",
      "Action": [
        "cloudshell:GetFileUploadUrls",
        "cloudshell:GetFileDownloadUrls"
      ],
      "Resource": "*"
    }
  ]
}
```

In an AWS Organization, SCPs can deny all CloudShell actions explicitly (a common enterprise control); CloudShell is not denied by default by any AWS-managed SCP. Unlike GCP's more permissive default (any project member with billing can generally use Cloud Shell), CloudShell always requires an explicit IAM allow — there is no implicit grant based on account ownership.


<a id="id-section-10-3"></a>
### 10.3 Abuse Scenarios

<a id="id-section-10-3-1"></a>
#### 10.3.1 Scaling: 1 Identity to 16 Containers

<a id="id-container-scope-by-region"></a>
##### Container Scope: By Region

CloudShell allows one environment per principal **per region**. An identity holding CloudShell IAM permissions therefore reaches as many containers as there are regions. This is 16 by default.

```
  Identity                                   ┌─────────────┐
  ════════                                   │      16     │
                                             ├─────────────┤
  IAM User                                   │  us-east-1  │
   - with CloudShell IAM perms  ───┐         │  ...        │
                                   ├────────>│  us-west-1  │──>  16x
  Role                             │         │  us-west-2  │
   - with CloudShell IAM perms  ───┘         │  ...        │
                                             └─────────────┘
```

**Notes**
- **The multiplier is regions, not effort.** The same credential, used sixteen times, yields sixteen independent containers. They do not share a filesystem, a session, or a quota.
- **Both starting points are ordinary.** An IAM user and an assumed role with CloudShell permissions are exactly what a normal AWS estate contains. Nothing here requires a misconfiguration.

<a id="id-cloudbasher-1-16"></a>
##### CloudBasher

CloudBasher supports provisioning with one command against 1 or more regions e.g.

```
.provision region ALL
.provision region us-west-*
.provision region us-east-1,us-central-2
```

<table>
 <tr>
 <td>
 <img src="images/cb_16_nodes_5.png" width="800" alt="CloudBasher Provisiong 16 Nodes">
 <br>
 <div align="center"><strong>Figure 3: CloudBasher - 16 Nodes Per Identity - 1 Per Region</strong></div>
 </td>
 </tr>
</table>

<a id="id-section-10-3-2"></a>
#### 10.3.2 Half-Managed Dynamic Identities

The picture changes if we look at using AssumeRole and GetFederationToken identities in conjunction with CloudShell containers.

These identities are mostly-managed because although there is logging in CloudTrail of both the API call and anything done by the identity, there is a looseness by default in the creation of the identity (the full ARN). The sessions formed from an assumeRole or getFederationToken call have a final ARN that includes the role session name or federation name, and is set by the user during the API call. This has traditionally provided some openings for identity obfuscation if a threat actor purposely used an arbitrary name e.g. another user or even an EC2 instance id to match a real instance. There are IAM policy conditions you can specify for a role, where you can enforce that the role session name must match the calling identity's name (user name), but these are optional.

These identities are also ephemeral: they exist only as temporary tokens, and when a token expires the identity effectively ceases to exist. There are no CRUD or enumeration APIs for role or federation identities, so nothing records that it was ever there.

<a id="id-assume-role"></a>
##### sts:AssumeRole

Roles are 1st-class security principals / identities in AWS. When assuming a role, the resulting session has an identity with full ARN that includes the `role-session-name` specified by the caller. This can be restricted via policies to require it to be the username of the caller for clear identification and tracking in CloudTrail, but by default this is not required. The result is more dynamic than IAM user accounts, which are fully managed in the sense of having enumeration APIs and full visibility. The visibility of role sessions are seen in the logs (CloudTrail) which is not as robust as tracking these sessions centrally.


<table>
 <tr>
 <td>

```
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/MyRole \
  --role-session-name Jack \
  --region us-west-2
```

<div align="center"><strong>Figure 4: sts:AssumeRole API call</strong></div>

 </td>
 </tr>
</table>

<table>
 <tr>
 <td>

```
{
  "eventVersion": "1.11",
  "userIdentity": {
  "principalId": "AIDA****ZLS8****E296Q",
  "arn": "arn:aws:iam::123456789012:user/joe",
  "accountId": "123456789012",
  "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "userName": "joe"
  },
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "awsRegion": "us-west-2",
  "responseElements": {
  "assumedRoleUser": {
    "assumedRoleId": "AROA1234567890EXAMPLE:Jack",
    "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/Jack"
  }
 }
}
```

<div align="center"><strong>Figure 5: CloudTrail entry of sts:AssumeRole</strong></div>

 </td>
 </tr>
</table>

<a id="id-assume-role-sso"></a>
##### sts:AssumeRole (SSO)

<table>
 <tr>
 <td>

```
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAQ2********TZK4NYA:an_sso_admin",
    "arn": "arn:aws:sts::05********79:assumed-role/AWSReservedSSO_\
        AdministratorAccess_047********ae410/an_sso_admin",
    "accountId": "05********79",
    "accessKeyId": "ASIA********EXVP",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "principalId": "AROAQ2********TZK4NYA",
        "arn": "arn:aws:iam::05********79:role/aws-reserved/sso.amazonaws.com/ \
            us-west-1/AWSReservedSSO_AdministratorAccess_047********ae410",
        "accountId": "05********79",
        "userName": "AWSReservedSSO_AdministratorAccess_047********ae410"
      },
      "attributes": {
        "creationDate": "2026-08-03T23:58:58Z",
        "mfaAuthenticated": "false"
      }
    },
    "onBehalfOf": {
      "userId": "6939****-40**-70**-43**-61f******198",
      "identityStoreArn": "arn:aws:identitystore::854******965:identitystore/d-91******7d"
    }
```

<div align="center"><strong>Figure 6: CloudTrail entry of an SSO sts:AssumeRole</strong></div>

 </td>
 </tr>
</table>

<a id="id-get-federation-token"></a>
##### sts:GetFederationToken

Federation introduces a different but similar set of identities, a temporary token that takes as input a federation name, which ends up in the ARN of the resulting federated identity.

<table>
 <tr>
 <td>

```
aws sts get-federation-token \
  --name cloudbasher \
  --policy '{"Version":"2012-10-17", \
       "Statement":[{"Effect": "Allow", \
       "Action":"*","Resource":"*"}]}' \
  --region us-west-2
```

<div align="center"><strong>Figure 7: sts:GetFederationToken API call</strong></div>

 </td>
 </tr>
</table>

None of this is new, and on its own it is not a problem. It becomes one when it meets the unmanaged CloudShell resources, which are per-identity.

<a id="id-section-10-3-3"></a>
#### 10.3.3 Unmanaged Resources

A lot has already been said about CloudShells being unmanaged which may be obvious given there is no public API. While they have basic RBAC/IAM and logging sometimes, with AWS, they are bound to the creating identity. An admin cannot reliably enumerate the CloudShells created by users nor access them without a lot of work. This "unmanaged" aspect leads to greater abuse leverage.

Almost all of the important research takeaways stems from different aspects of this issue, and it's worth trying to define a more clear definition of managed vs unmanaged
- Authentication (credential type, token type, conversion especially manageability of)
- Authorization including RBAC (explicitness and granularity especially manageability of)
- Sessions (enumeration, auditing, revocation)
- Enumeration and Discovery (local vs global)
- CRUD (local vs global)
- Logging (granularity)
- Preventative controls (granularity)

<a id="id-section-10-3-4"></a>
#### 10.3.4 Scaling: 1 Identity to 160 Containers

<a id="id-unmanaged-identities-resources"></a>
##### Half-Managed Dynamic Identities Meet Unmanaged Resources

CloudShell abuse is magnified due to the intersection of two design areas that by themselves are not immediately risky

```
       .-------------.   .-------------.
   /                 /   \                 \
 /                 /       \                 \
/   Half-Managed  /   ***   \   Unmanaged     \
|      Dynamic    |  *****  |   Resources     |
\    Identities   \   ***   /                 /
 \                 \       /                 /
   \                 \   /                 /
       '-------------'   '-------------'
```

**Notes**
- **Unmanaged dynamic identities** — federated users and assumed-role sessions that are created on demand, exist for hours, and appear in no identity inventory. Nothing was provisioned, so nothing shows up as drift.
- **Unmanaged resources** — CloudShell containers, which are created implicitly by using them. There is no Terraform state, no CloudFormation stack, no tag.

<a id="id-procreation-identity"></a>
##### Procreation Identity

A **procreation identity** is one that can derive *other* target identities: it can `sts:AssumeRole` into a role holding CloudShell permissions, or `sts:GetFederationToken` from an IAM user holding them i.e. has the following criteria
1. Can sts:AssumeRole to a role that has CloudShell permissions **or**
2. Can call sts:GetFederationToken **and** has CloudShell permissions

```
  Procreation Identity
  ════════════════════
                                     ┌─────────┐          ┌─────────────┐
  Who can AssumeRole                 │    N    │          │      16     │
   - to role with                    ├─────────┤          ├─────────────┤
     CloudShell IAM perms     ───┐   │  Name1  │          │  us-east-1  │     
                                 │   │  Name2  │          │  ...        │      
  Who can GetFederationToken     ├──>│  Name3  │────────> │  us-west-1  │───> 160x
   - from IAM user with          │   │  Name4  │          │  us-west-2  │      
     CloudShell IAM perms     ───┘   │  ...    │          │  ...        │     
                                     └─────────┘          └─────────────┘
```

We can use this originating identity to dynamically derive 10 different target identities by calling AssumeRole (or GetFederationToken) with different role session names (or federation names), and use each target identity to create a CloudShell container in each region (16 by default). 10 x 16 = 160x from one compromised identity of the right type.

Why only 10? There is no limit from an AssumeRole or GetFederationToken, it's that we hit an AWS account quota of 10 active CloudShell containers per region, account-wide. Saved by the quota.

The bottom-line: 160x leverage for the threat actor or for the admin automating their CloudShell workflows.

###### Notes
- **The name is a namespace key, not a label.** CloudShell scopes `describeEnvironments` to the calling principal, and the role-session or federation name is *part* of that principal. `Name1` and `Name2` are two different principals to CloudShell, each with its own environment in each region — see [sts:GetFederationToken](#id-get-federation-token) and [sts:AssumeRole](#id-assume-role) and [sts:AssumeRole (SSO)](#id-assume-role-sso) for how the names land in the ARN.
- **So the multiplier compounds.** N names × 16 regions. At N = 10 that is 160 containers from a single starting credential, and N is chosen by the caller, not by AWS.
- **Nothing above is a privilege escalation.** Every step uses a documented STS call with permissions the credential already holds. The scale comes from the fact that the derived principal's *name* is an unbounded, caller-chosen namespace.

<a id="id-cloudbasher-1-160"></a>
##### CloudBasher

A single provision command on a **Procreation Identity**, deriving 10 target children identities, each with 16 CloudShell containers (per region)

```
provision selected region ALL 1-160
```

<table>
 <tr>
 <td>
 <img src="images/cb_160_nodes_9.png" width="800" alt="CloudBasher Provisiong 160 Nodes">
 <br>
 <div align="center"><strong>Figure 8: CloudBasher - 160 Nodes Per Identity - 10 Derived Identities x 16 Regions</strong></div>
 </td>
 </tr>
</table>
