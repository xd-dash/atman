# atman

Atman is the Google IAM boundary for [marai](https://github.com/xd-dash/marai).
It keeps two responsibilities separate:

1. `cmd/atman` validates a Google-signed ID token, requires one exact audience and
   one exact caller service-account email, then calls a colocated marai process over
   a Unix socket using marai's narrow application ACL.
2. `cmd/mint-token` and the token-minter deployment mint short-lived Google tokens
   through the IAM Credentials API. IAM grants, not caller input, decide which
   service accounts the minter can impersonate.

Atman never exposes Redis, Redis credentials, or marai key-administration operations
over HTTP. Key creation and rotation remain on the instance's local administrative
boundary.

## Marai gateway

Required environment variables:

| Name | Meaning |
|---|---|
| `ATMAN_AUDIENCE` | Exact ID-token audience for this tenant cell |
| `ATMAN_ALLOWED_SERVICE_ACCOUNT` | Exact caller service-account email |
| `ATMAN_TLS_CERT_FILE` / `ATMAN_TLS_KEY_FILE` | TLS identity |
| `MARAI_REDIS_SOCKET` | Colocated marai Unix socket |
| `MARAI_REDIS_USER` | Marai application ACL user |
| `MARAI_REDIS_PASSWORD_FILE` | Read-only file containing its password |

`ATMAN_ALLOW_INSECURE_HTTP=1` exists only for tests or a trusted local TLS
terminator. It must not be used on a routable listener.

The KMS API is:

- `POST /v1/keys/{key}/encrypt` with `{"data":"<base64>"}`
- `POST /v1/keys/{key}/decrypt` with `{"data":"<base64-envelope>"}`
- `POST /v1/keys/{key}/generate-data-key` with an empty body
- `GET /healthz`

The official Google validator checks the token signature, issuer, expiry, and exact
audience. Atman additionally requires `email_verified=true` and the configured exact
service-account email.

Use one Atman + one marai process per tenant. A shared gateway does not turn a shared
marai process into tenant isolation; marai's process is the master-key boundary.

## Token minting

`internal/mint` is the only package that calls the IAM Credentials API. The trusted
CLI and composite action can mint access or ID tokens for integration tests using
ambient Application Default Credentials, normally GitHub Actions WIF:

```sh
go run ./cmd/mint-token \
  -kind id \
  -target tenant-caller@PROJECT.iam.gserviceaccount.com \
  -audience https://atman.example \
  -include-email
```

For the deployed multi-tenant minter, `POST /v1/token` accepts only `tenant_id` plus
`X-API-Key`. Only SHA-256 API-key digests are placed in the runtime registry. The
registry supplies the target service account and exact audience; the HTTP caller
cannot choose token type, scopes, audience, or whether the email claim is present.
The endpoint always returns a short-lived ID token compatible with the Atman gateway.

Terraform in `terraform/token-minter` grants the minter
`roles/iam.serviceAccountTokenCreator` on each configured tenant caller identity
individually, never at project scope. A CI identity may delegate through the minter
identity, so `huram-abi-master` can exercise the production-shaped token path without
using service-account keys.

## Repository layout

- `cmd/atman`, `internal/gateway`, `internal/marai`: colocated KMS gateway.
- `cmd/mint-token`, `internal/mint`: trusted token-minting CLI and shared client.
- `router`, `internal/handler`, `internal/tenant`: constrained deployed minter.
- `terraform/token-minter`: per-resource IAM and Cloud Function deployment.
- `.github/actions/mint-token`: WIF/ADC integration-test helper.
- `.github/actions/deploy-token-minter`: Terraform deployment wrapper.

Run `go test ./...` for unit tests. The cross-repository integration test belongs in
`huram-abi-master`, where a protected environment can supply WIF and marai ACL
credentials without placing production identity or orchestration policy in either
runtime repository.
