# Helper scripts and command examples

These are optional helpers; CloudBasher itself does not require them. Run from
the repository root unless a script's `--help` says otherwise.

| File | Use | Notes |
|---|---|---|
| `creds-inspect.py` | Check credential-block structure and identify parsed credential types | Secret values are withheld. |
| `aws/cloudshell-sweep.py` | Inventory CloudShell environments across AWS identities and regions | `--delete` is destructive; review its plan before confirming. Requires AWS permissions and the CloudBasher package. |
| `azure/decode_access_token.py` | Decode Azure access-token JWT claims locally | Does not verify the signature. Claims can contain user and tenant identifiers. Prefer `TOKEN` in the environment over a command-line argument. |
| `azure/msal-cache-inspect.py` | Inspect the local Azure MSAL token cache | Cache contents and decoded claims are sensitive; token output requires explicit options. |
| `gcp/gcp-token-discovery.sh` | Inspect metadata and API access associated with a GCP OAuth token | Sends the supplied token to Google token/API endpoints; output can include identity and project data. |
| `gcp/token-cache-inspect.py` | Read the local gcloud SQLite token caches | Read-only; token values are masked except when exporting an `rc` block. Treat that output as a credential. |
| `gcp/probe_gcloud_rt_refresh.py` | Test one refresh using the existing gcloud cache | Temporarily edits `access_tokens.db`; requires `--confirm-cache-write`. Avoid concurrent gcloud commands. Raw token output requires `--show-token`. |

The `testaws.cmd`, `testaz.cmd`, `testgcp.cmd`, and `testbash.cmd` files are
small interactive-shell examples for checking identity, basic commands, and
terminal behavior. Provider commands may access account resources; review each
file before running it.

Never commit a filled credential file, token-cache export, or command output
containing credentials or personal data. OAuth access and refresh tokens are
bearer credentials: protect them from shell history, process listings, logs,
and shared terminals. Conditional Access, MFA, token audience, and delegated
scopes continue to govern the authority of tokens used by these tools.
