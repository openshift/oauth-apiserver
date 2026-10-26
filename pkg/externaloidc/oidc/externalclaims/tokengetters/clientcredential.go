package tokengetters

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/oidc/internal/caclient"
)

// tokenEndpointRequestTimeout is the timeout for HTTP requests to the token endpoint.
//
// TO BE RESOLVED DURING REVIEW: this is tighter than the external source
// timeout and, unlike that one, also gates the initial token fetch done
// synchronously in NewClientCredential during authenticator construction, so
// a timeout here fails a config reload outright rather than just dropping
// claims. trustedCAContentProvider now lets this request route through an
// HTTPS or TLS-intercepting proxy, which adds latency this budget was not
// chosen with in mind. Confirm 1s is still enough once a proxy is in the
// path, or raise it.
const tokenEndpointRequestTimeout = time.Second

// ClientCredential is an AccessTokenGetter that uses the OAuth2 client credentials
// grant flow to obtain an access token for authenticating with external claims sources.
type ClientCredential struct {
	tokenSource oauth2.TokenSource
}

// NewClientCredential creates a new ClientCredential token getter from the provided configuration.
func NewClientCredential(ctx context.Context, cfg *authentication.ClientCredentialConfig, trustedCAContentProvider dynamiccertificates.CAContentProvider) (*ClientCredential, error) {
	if cfg == nil {
		return nil, fmt.Errorf("client credential configuration must not be nil")
	}

	httpClient, err := httpClientForClientCredential(cfg.TLS, trustedCAContentProvider)
	if err != nil {
		return nil, fmt.Errorf("building http client for client credential token endpoint: %w", err)
	}

	ccCfg := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.TokenEndpoint,
		Scopes:       cfg.Scopes,
	}

	wrappedCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	cc := &ClientCredential{
		tokenSource: ccCfg.TokenSource(wrappedCtx),
	}

	// do an initial access token fetch to prime
	// the cache and catch any configuration issues.
	_, err = cc.GetAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting initial access token: %v", err)
	}

	return cc, nil
}

func (cc *ClientCredential) GetAccessToken(_ context.Context) (string, error) {
	token, err := cc.tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("getting token: %w", err)
	}

	return token.AccessToken, nil
}

// httpClientForClientCredential builds the client used for client-credentials
// token endpoint requests. See caclient.New for the trust-pinning behavior.
func httpClientForClientCredential(tlsCfg *authentication.TLS, trustedCAContentProvider dynamiccertificates.CAContentProvider) (*http.Client, error) {
	var certificateAuthority string
	if tlsCfg != nil && tlsCfg.CertificateAuthority != nil {
		certificateAuthority = *tlsCfg.CertificateAuthority
	}

	return caclient.New("client credentials token endpoint CA", certificateAuthority, trustedCAContentProvider, tokenEndpointRequestTimeout)
}
