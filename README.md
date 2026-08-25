# atman

Atman is the Google IAM authentication boundary for marai. It validates a
Google-signed ID token on every HTTP KMS request, requires one exact audience and one
exact service-account email, then calls a colocated marai process over a Unix socket.
Redis is never exposed to the network and callers never receive Redis credentials.

Atman deliberately has no key-administration endpoint. Key creation and rotation stay
on the instance's local administrative boundary.

## Runtime contract

Required environment variables:

| Name | Meaning |
|---|---|
| `ATMAN_AUDIENCE` | Exact Google ID-token audience for this tenant cell |
| `ATMAN_ALLOWED_SERVICE_ACCOUNT` | Exact caller service-account email |
| `ATMAN_TLS_CERT_FILE` / `ATMAN_TLS_KEY_FILE` | TLS identity |
| `MARAI_REDIS_SOCKET` | Colocated marai Unix socket |
| `MARAI_REDIS_USER` | Narrow marai application ACL user |
| `MARAI_REDIS_PASSWORD_FILE` | Read-only file containing that ACL password |

`ATMAN_ALLOW_INSECURE_HTTP=1` exists only for a trusted local TLS-terminating proxy
and tests. It must not be used on a routable listener.

## API

- `POST /v1/keys/{key}/encrypt` with `{"data":"<base64>"}`
- `POST /v1/keys/{key}/decrypt` with `{"data":"<base64-envelope>"}`
- `POST /v1/keys/{key}/generate-data-key` with an empty body
- `GET /healthz`

KMS endpoints require `Authorization: Bearer <google-id-token>`. The official
Google Cloud Go validator verifies the signature, issuer, expiry, and exact audience;
Atman additionally requires `email_verified=true` and an exact configured service
account email.

The production topology is one Atman + one marai process per tenant. Do not route
multiple tenants into one marai process: process-level separation is the master-key
isolation boundary.
