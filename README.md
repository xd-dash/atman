# atman

A multi-tenant GCP token minter: one small service account (`token-minter`)
whose only job is minting short-lived tokens that identify as *other*
service accounts, one per tenant, so users who sign up for a service built
on this project can authenticate to their own GCP Cloud Function (gen1 or
gen2) without ever holding a credential for this GCP project, and without
this project ever holding a credential that can do anything beyond
impersonate that one tenant's own service account.

## Why

Normally, letting an external caller invoke their own Cloud Function means
either (a) handing them a long-lived key for a service account in this
project, or (b) building a bespoke per-tenant IAM setup. Both couple the
tenant tightly to this project's identity model. Instead:

- Each tenant gets a dedicated GCP service account, scoped to invoke only
  that tenant's own function(s) - see `terraform/token-minter`.
- The `token-minter` service account is granted
  `roles/iam.serviceAccountTokenCreator` on that one tenant service
  account, and nothing else - not project-wide, not on any other tenant.
- A tenant calls `POST /v1/token` (their own `tenant_id` + `X-API-Key`)
  and gets back a short-lived access or ID token for their own service
  account, which they use to call their own function directly. This
  project never proxies the actual function call, and the tenant never
  sees this project's own credentials.

Onboarding or removing a tenant is exactly one entry in
`terraform/token-minter`'s `tenants` variable.

## Layout

- `router/` - the deployable HTTP router (`NewRouter() http.Handler`),
  imported by [dash-xd/gospace-minimal](https://github.com/dash-xd/gospace-minimal)'s
  generic Cloud Functions shell via `.github/actions/deploy-token-minter`.
- `internal/handler/` - the `POST /v1/token` and `GET /healthz` HTTP
  handlers.
- `internal/tenant/` - loads and authenticates tenants from `TENANTS_JSON`
  (set by Terraform from the `tenants` variable).
- `internal/mint/` - the one place this repo calls the IAM Credentials
  API (`GenerateAccessToken` / `GenerateIdToken`). Used by both the HTTP
  handler and `cmd/mint-token`, so minting logic exists exactly once.
- `cmd/mint-token/` - a local CLI wrapping `internal/mint`, for minting a
  tenant token straight from a CI job without going through the deployed
  function (see `.github/actions/mint-token`).
- `terraform/token-minter/` - creates the `token-minter` service account,
  per-tenant service accounts and `serviceAccountTokenCreator` grants, and
  deploys this repo's router as a Cloud Function (gen2) running as
  `token-minter`.
- `.github/actions/deploy-token-minter/` - composite action that deploys
  the above. Meant to be called remotely, e.g. from
  [xd-dash/huram-abi](https://github.com/xd-dash/huram-abi)'s
  `deploy-token-minter.yml` workflow.
- `.github/actions/mint-token/` - composite action wrapping
  `cmd/mint-token`, for other workflows (in this repo or elsewhere) that
  need a tenant token locally.

## Local development

```
go test ./...
go run ./cmd/mint-token -target <tenant-sa-email> -delegate <token-minter-sa-email>
```

`cmd/mint-token` needs Application Default Credentials already set up
(`gcloud auth application-default login`, or ambient Workload Identity
Federation in CI) belonging to an identity that holds
`roles/iam.serviceAccountTokenCreator` on `-delegate` (or directly on
`-target` if `-delegate` is omitted).
