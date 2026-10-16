# CloudShell Design — GCP

<a id="id-contents"></a>
## Contents

[1. Control-Plane Flow](#id-section-1)
[2. Container Lifecycle](#id-section-2)
[3. REST API](#id-section-3)
[4. WebSocket Protocol](#id-section-4)
[5. File Transfer](#id-section-5)
[6. Credential Types](#id-section-6)
[7. Authentication Flows](#id-section-7)
[8. Sessions](#id-section-8)
[9. IAM Permission Model](#id-section-9)
[10. Threat Modeling](#id-section-10)


<a id="id-section-1"></a>
## 1. Control-Plane Flow

Google publishes Cloud Shell API v1 for environment lifecycle and authorization. Compared with browser-private CloudShell control-plane paths, this documented surface reduces reliance on undocumented protocol behavior and gives clients a clearer supported contract—a security advantage, though not a guarantee that every Cloud Shell component is inherently more secure. The native Console still uses additional private calls; this v0.9 overview is intentionally concise while calling out those differences.

```text
 Google Account / OAuth                    Google Cloud Console
          │                                         │
          ├── public API: OAuth Bearer ─────────────┤ private Console session:
          │   cloudshell.googleapis.com/v1          │ cookies + XSRF
          │                                         │ shell.cloud.google.com
          └──────────────────┬──────────────────────┘
                             │ get / start / authorize / key operations
                             ▼
                   Cloud Shell environment
                  ┌──────────┴───────────┐
                  │                      │
          direct SSH (public path)   SSH over WebSocket
          sshHost:sshPort             (Console browser path)
                  │                      │
                  └──────────┬───────────┘
                             ▼
                  Interactive Linux shell
```

Both routes reach the user's Cloud Shell environment, but use different authentication and connection setup. The public path is the preferred documented interface for programmatic clients; Console-private calls are retained here only where observed behavior differs or adds functionality.

<a id="id-section-2"></a>
## 2. Container Lifecycle

Cloud Shell separates a temporarily allocated VM from the user's persistent home directory. A session starts or resumes the default environment, waits until it is ready, then connects over SSH. Google documents a 40-minute inactivity termination for the VM and a 12-hour maximum session duration; `$HOME` has 5 GB of persistent storage and is removed after 120 days without Cloud Shell use. [Cloud Shell quotas and limits](https://docs.cloud.google.com/shell/docs/quotas-limits)

The public API describes `SUSPENDED`, `PENDING`, and `RUNNING` states. A `start` request returns a long-running operation; poll the operation until its response indicates the environment is ready. [Environment resource](https://docs.cloud.google.com/shell/docs/reference/rest/v1/users.environments) · [start method](https://docs.cloud.google.com/shell/docs/reference/rest/v1/users.environments/start)

The active project is a Console-selected context that native Cloud Shell propagates into its own shell configuration. CloudBasher does not emulate that project propagation; users set the project in the shell when needed. Its explicit `project_id` setting is used for project-addressed discovery/API calls, not as a promise that `gcloud config get project` is preconfigured.

<a id="id-section-3"></a>
## 3. REST API

The documented service endpoint is `https://cloudshell.googleapis.com`, with REST paths under `/v1`. Requests use an OAuth 2.0 bearer token with the `https://www.googleapis.com/auth/cloud-platform` scope. The Cloud Shell REST reference publishes the following user-environment methods.

| Method | HTTP operation | Purpose |
|---|---|---|
| `get` | `GET /v1/{name=users/*/environments/*}` | Read an environment record and connection fields |
| `start` | `POST /v1/{name=users/*/environments/*}:start` | Start an environment; request may include `accessToken` and `publicKeys` |
| `authorize` | `POST /v1/{name=users/*/environments/*}:authorize` | Send OAuth credentials to a running environment |
| `addPublicKey` / `removePublicKey` | `POST...:addPublicKey` / `...:removePublicKey` | Add or remove an SSH public key |

`start` can combine initial token authorization and SSH-key registration. These fields can be updated later with separate `authorize` and key methods. The documented user-environment resource has no `delete` or `abandon` method. [Cloud Shell API REST reference](https://docs.cloud.google.com/shell/docs/reference/rest) · [start request fields](https://docs.cloud.google.com/shell/docs/reference/rest/v1/users.environments/start)

The Console has an additional private `POST /devshell/abandon` operation used by its Restart flow. It is not listed in the public Cloud Shell API. CloudBasher's observed Console path uses the signed-in browser session and XSRF token; OAuth-only credentials cannot use this private operation. Abandoning the Console session is not a documented guarantee of permanent environment or home-directory deletion.

<a id="id-section-4"></a>
## 4. WebSocket Protocol

The public API returns connection information for a standard SSH client. Native Console traffic instead tunnels SSH over a WebSocket on the environment's `cloudshell.dev` host. The data exchanged inside that tunnel is SSH protocol traffic, not an AWS-style CloudShell message protocol. Captures from different dates show endpoint-path variation; clients should use the current environment/session response rather than hard-code a captured hostname or route.

The SSH credential is a client-generated key pair. The public key is registered through `start` or `addPublicKey`; the corresponding private key remains with the client. A separate Console Editor connection may open additional WebSockets for editor services; those are not required for terminal-only access.

<a id="id-section-5"></a>
## 5. File Transfer

For a public-API SSH session, ordinary SSH-based transfer such as SFTP uses the already-established connection and avoids a second credential surface. Native Console file operations also use an HTTP file service on a hostname derived from the environment's `cloudshell.dev` host. The observed browser flow obtains a short-lived Cloud Shell JWT and uses it for listing, upload, and download requests; this is separate from the SSH session token.

The Console file-service host uses an `8080-` hostname prefix, not a TCP `:8080` port. When using the private file service, check response content type as well as HTTP status: an unauthenticated request can return an HTML sign-in page with status 200. Do not log or persist the bearer JWT or generated upload/download content.

<a id="id-section-6"></a>
## 6. Credential Types

| Credential | Cloud Shell path | Important boundary |
|---|---|---|
| Google Console session | Private browser API | Google session cookies and XSRF; permits native Console-only operations such as observed `/devshell/abandon` |
| OAuth access token | Public API | Must have the required `cloud-platform` scope and remain valid for the request |
| OAuth refresh token | Public API after exchanging it for an access token | Refresh may be subject to account reauthentication policy; protect and persist only when necessary |
| Service-account credential | Not a supported end-to-end interactive Cloud Shell path in the tested implementation | A service-account environment lookup did not establish a usable interactive shell; do not infer support from API authentication alone |

The credential that calls the API and the identity projected into the shell are related but distinct. `start` accepts an optional access token to pre-authenticate `gcloud`; `authorize` updates the OAuth credential in an already-running environment. Verify the resulting in-shell identity rather than treating a successful environment start as proof of credential binding.

<a id="id-section-7"></a>
## 7. Authentication Flows

For an OAuth client, the documented flow is: obtain an access token with `cloud-platform` scope; call `get` to inspect the default environment; call `start` with the SSH public key and, when desired, the access token; poll the returned operation; then connect using the returned SSH host, port, and username. For an already-running environment, use `addPublicKey` as needed and `authorize` to refresh the shell's delegated credential. [Cloud Shell API](https://docs.cloud.google.com/shell/docs/reference/rest)

The native Console flow uses Google browser cookies and private XSRF-protected endpoints to set up a session, then opens the terminal WebSocket and may project an OAuth token into the container. This private sequence is not the public API contract. CloudBasher's Console and OAuth flows are intentionally distinct; a refresh token is exchanged for an access token before public API calls.

If CloudBasher sends `x-goog-user-project` for a configured `quota_project_id`, the calling identity needs `serviceusage.services.use` on that quota project (commonly granted by Service Usage Consumer). This is separate from the `project_id` used to target resource discovery and does not establish the shell's active `gcloud` project.

<a id="id-section-8"></a>
## 8. Sessions

The public API supports starting and authorizing an environment and managing its SSH keys, but its documented user-environment methods do not provide a delete/abandon operation. The native Console's `/devshell/abandon` is a private browser-session operation; its presence in Console traffic should not be mistaken for a supported OAuth API call. `removePublicKey` revokes a registered SSH key, while deleting a local CloudBasher node only removes local state.

Cloud Shell's VM/session limits and persistent-home retention are service behavior, not a CloudBasher heartbeat guarantee. Use Google's documented limits and keep important data outside the ephemeral VM; treat `$HOME` as persistent user data with its own retention and exposure considerations.

<a id="id-section-9"></a>
## 9. IAM Permission Model

Google's public API reference requires the `cloud-platform` OAuth scope. Research for this project found no recognized `cloudshell.environments.*` IAM permissions or dedicated Cloud Shell role; access to the user's default environment appears tied to the authenticated account rather than a project-level Cloud Shell role. This is a research finding, not a substitute for evaluating the permissions required by commands run inside the shell.

When CloudBasher sends `x-goog-user-project`, the caller must also have `serviceusage.services.use` on that quota project. Without it, token refresh can succeed while the API rejects the request for quota-project authorization. The affected project is the quota project, not necessarily the resource-target `project_id`.

Workspace administrators can disable Cloud Shell for managed users through Google Admin controls. Project IAM, organization policies, billing/quota settings, OAuth scopes, and the permissions of the projected in-shell identity remain separate authorization layers. [Disable or reset Cloud Shell](https://docs.cloud.google.com/shell/docs/resetting-cloud-shell)

<a id="id-section-10"></a>
## 10. Threat Modeling

Cloud Shell brings together a browser or OAuth credential, a remote interactive shell, a persistent home directory, a registered SSH key, and any credentials projected into the container. Stolen browser cookies or OAuth refresh tokens can enable access beyond a single command; registered SSH keys and persisted startup files may outlive an individual access token. Use least privilege, short-lived credentials where practical, key removal when access is no longer needed, careful `$HOME` hygiene, and secret-safe logging.

Personal Gmail accounts can use Cloud Shell but are not governed by a Workspace administrator. They therefore lack organization-admin controls such as centrally disabling Cloud Shell for managed users or applying Google Cloud session controls to a managed population; account-level security and project IAM still apply. For Workspace/Cloud Identity users, admins can configure Google Cloud session control and reauthentication policies, including session length and stronger reauthentication methods for supported applications. Shorter Cloud sessions can limit the useful lifetime of stolen refresh credentials, but do not replace OAuth token revocation or incident response. [Google Cloud session controls](https://docs.cloud.google.com/access-context-manager/docs/session-controls-for-reauthentication) · [compromised credentials response](https://docs.cloud.google.com/docs/security/compromised-credentials)

This v0.9 threat section is intentionally concise. Later work should examine personal-account recovery and MFA, OAuth grant scope and token theft, persistent-home abuse, SSH-key lifecycle, project/quota boundaries, and the difference between public API capabilities and private Console behavior in greater depth.
