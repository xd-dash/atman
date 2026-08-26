// Package mint is the one place this repo calls the IAM Credentials API.
// Both the HTTP handler (router/) and the local CLI (cmd/mint-token) call
// through here, so "how a token actually gets minted" exists exactly
// once, regardless of whether it's served over HTTP or run directly in
// CI.
//
// Every function here mints a token by impersonating a target service
// account using whatever Application Default Credentials the process
// already has - it never itself grants roles/iam.serviceAccountTokenCreator
// on that target. That grant lives entirely in terraform/token-minter
// (directly for the deployed function's own service account, or via a
// delegate chain for a caller impersonating the token-minter service
// account first). This package fails if the grant doesn't already exist;
// it has no way to create one and shouldn't.
package mint

import (
	"context"
	"fmt"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// resourceName returns the IAM Credentials API resource name for a
// service account email.
func resourceName(email string) string {
	return "projects/-/serviceAccounts/" + email
}

// delegateChain converts a list of service account emails into the
// resource-name form GenerateAccessToken/GenerateIdToken expect for
// their delegate chains.
func delegateChain(delegates []string) []string {
	if len(delegates) == 0 {
		return nil
	}

	names := make([]string, len(delegates))
	for i, d := range delegates {
		names[i] = resourceName(d)
	}

	return names
}

// AccessToken mints a short-lived OAuth2 access token that identifies as
// targetServiceAccount. delegates, if non-empty, is the impersonation
// chain the caller must already be authorized for - e.g. the
// token-minter service account, when the caller (such as a CI job
// impersonating it) only holds roles/iam.serviceAccountTokenCreator on
// the minter rather than directly on targetServiceAccount.
func AccessToken(ctx context.Context, targetServiceAccount string, scopes []string, lifetime time.Duration, delegates ...string) (string, time.Time, error) {
	client, err := credentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint: new iam credentials client: %w", err)
	}
	defer client.Close()

	resp, err := client.GenerateAccessToken(ctx, &credentialspb.GenerateAccessTokenRequest{
		Name:      resourceName(targetServiceAccount),
		Delegates: delegateChain(delegates),
		Scope:     scopes,
		Lifetime:  durationpb.New(lifetime),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("mint: generate access token for %s: %w", targetServiceAccount, err)
	}

	return resp.GetAccessToken(), resp.GetExpireTime().AsTime(), nil
}

// IDToken mints a short-lived OIDC ID token identifying as
// targetServiceAccount, scoped to audience - the form Cloud Run/Cloud
// Functions gen2's built-in authentication expects in the Authorization
// header to invoke a private tenant function. includeEmail asks the API
// to embed targetServiceAccount's email as a claim. See AccessToken for
// what delegates is for.
func IDToken(ctx context.Context, targetServiceAccount, audience string, includeEmail bool, delegates ...string) (string, error) {
	client, err := credentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return "", fmt.Errorf("mint: new iam credentials client: %w", err)
	}
	defer client.Close()

	resp, err := client.GenerateIdToken(ctx, &credentialspb.GenerateIdTokenRequest{
		Name:         resourceName(targetServiceAccount),
		Delegates:    delegateChain(delegates),
		Audience:     audience,
		IncludeEmail: includeEmail,
	})
	if err != nil {
		return "", fmt.Errorf("mint: generate id token for %s: %w", targetServiceAccount, err)
	}

	return resp.GetToken(), nil
}
