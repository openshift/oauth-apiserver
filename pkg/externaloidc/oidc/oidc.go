package oidc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication/conversion"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/oidc/resolvers/externalclaims"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	k8soidc "k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

type Options struct {
	// Authenticator is the authenticator that will be used to verify the JWT.
	Authenticator authentication.Authenticator

	// Optional KeySet to allow for synchronous initialization instead of fetching from the remote issuer.
	// Mutually exclusive with JWTAuthenticator.Issuer.DiscoveryURL.
	//
	// The following API server metrics for fetching JWKS and provider status will not be recorded if this is set.
	//  - apiserver_authentication_jwt_authenticator_jwks_fetch_last_timestamp_seconds
	//  - apiserver_authentication_jwt_authenticator_jwks_fetch_last_key_set_info
	KeySet oidc.KeySet

	// PEM encoded root certificate contents of the provider.  Mutually exclusive with Client.
	CAContentProvider k8soidc.CAContentProvider

	// Optional http.Client used to make all requests to the remote issuer.  Mutually exclusive with CAContentProvider and EgressLookup.
	Client *http.Client

	// Optional CEL compiler used to compile the CEL expressions. This is useful to use a shared instance
	// of the compiler as these compilers holding a CEL environment are expensive to create. If not provided,
	// a default compiler will be created.
	// Note: the compiler construction depends on feature gates and the compatibility version to be initialized.
	Compiler Compiler

	// SupportedSigningAlgs sets the accepted set of JOSE signing algorithms that
	// can be used by the provider to sign tokens.
	//
	// https://tools.ietf.org/html/rfc7518#section-3.1
	//
	// This value defaults to RS256, the value recommended by the OpenID Connect
	// spec:
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
	SupportedSigningAlgs []string

	DisallowedIssuers []string

	// APIServerID is the ID of the API server
	// This is used in metrics to identify the API server
	APIServerID string

	// now is used for testing. It defaults to time.Now.
	now func() time.Time
}

type Compiler interface {
	authenticationcel.Compiler
	CompileExternalSourceExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error)
}

func New(ctx context.Context, opts Options) (k8soidc.AuthenticatorTokenWithHealthCheck, error) {
	externalClaimsExpander, err := externalclaims.NewClaimsResolver(opts.Compiler, opts.Authenticator.ExternalClaimsSources...)
	if err != nil {
		return nil, fmt.Errorf("building external claims resolver: %w", err)
	}

	k8sOpts := k8soidc.Options{
		JWTAuthenticator:     conversion.ConvertAuthenticatorToApiserverJWTAuthenticator(opts.Authenticator),
		KeySet:               opts.KeySet,
		CAContentProvider:    opts.CAContentProvider,
		Client:               opts.Client,
		Compiler:             opts.Compiler,
		SupportedSigningAlgs: opts.SupportedSigningAlgs,
		DisallowedIssuers:    opts.DisallowedIssuers,
		APIServerID:          opts.APIServerID,
		ClaimsExpanders: []k8soidc.ClaimsExpander{
			externalClaimsExpander,
		},
	}

	return k8soidc.New(ctx, k8sOpts)
}
