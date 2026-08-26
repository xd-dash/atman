// Command mint-token mints a short-lived GCP token for a target service
// account by calling internal/mint directly - the same package the
// deployed HTTP handler (router/) uses, so "how a token gets minted" is
// implemented exactly once whether it's exercised over HTTP or run
// standalone.
//
// It uses whatever Application Default Credentials the process already
// has. That identity needs roles/iam.serviceAccountTokenCreator on
// -target, either directly or via the -delegate chain (see
// terraform/token-minter's minter_impersonators, which is what grants a
// CI identity that permission on the token-minter service account
// itself). This is what .github/actions/mint-token wraps to let other
// workflows - in this repo or elsewhere, such as huram-abi's - mint a
// tenant token locally without going through the deployed function.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xd-dash/atman/internal/mint"
)

func main() {
	var (
		target       = flag.String("target", "", "email of the service account to mint a token for (required)")
		kind         = flag.String("kind", "access", `"access" or "id"`)
		scopesFlag   = flag.String("scopes", "https://www.googleapis.com/auth/cloud-platform", "comma-separated OAuth scopes (access tokens only)")
		audience     = flag.String("audience", "", "audience (required when -kind=id)")
		lifetime     = flag.Duration("lifetime", 10*time.Minute, "access token lifetime (access tokens only)")
		includeEmail = flag.Bool("include-email", false, "include -target's email as a claim (id tokens only)")
		delegateFlag = flag.String("delegate", "", "comma-separated impersonation delegate chain, e.g. the token-minter service account's email")
	)
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "mint-token: -target is required")
		os.Exit(2)
	}

	var delegates []string
	if *delegateFlag != "" {
		delegates = strings.Split(*delegateFlag, ",")
	}

	ctx := context.Background()

	switch *kind {
	case "access":
		var scopes []string
		if *scopesFlag != "" {
			scopes = strings.Split(*scopesFlag, ",")
		}

		token, expiresAt, err := mint.AccessToken(ctx, *target, scopes, *lifetime, delegates...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mint-token: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(token)
		fmt.Fprintf(os.Stderr, "expires_at=%s\n", expiresAt.Format(time.RFC3339))

	case "id":
		if *audience == "" {
			fmt.Fprintln(os.Stderr, "mint-token: -audience is required for -kind=id")
			os.Exit(2)
		}

		token, err := mint.IDToken(ctx, *target, *audience, *includeEmail, delegates...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mint-token: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(token)

	default:
		fmt.Fprintln(os.Stderr, `mint-token: -kind must be "access" or "id"`)
		os.Exit(2)
	}
}
