package tokengetters

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/caclient"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// tokenEndpointRequestTimeout is the timeout for HTTP requests to the token endpoint.
//
// TODO: revisit whether 1s is enough when routed through a proxy. A timeout
// on the initial fetch in NewClientCredential fails the whole config reload.
const tokenEndpointRequestTimeout = time.Second

// ClientCredential is an AccessTokenGetter that uses the OAuth2 client credentials
// grant flow to obtain an access token for authenticating with external claims sources.
type ClientCredential struct {
	tokenSource oauth2.TokenSource
}

// NewClientCredential creates a new ClientCredential token getter from the provided configuration.
func NewClientCredential(ctx context.Context, cfg *authentication.ClientCredentialConfig, buildHTTPClient caclient.ClientFactoryFunc) (*ClientCredential, error) {
	if cfg == nil {
		return nil, fmt.Errorf("client credential configuration must not be nil")
	}
	if buildHTTPClient == nil {
		return nil, fmt.Errorf("HTTP client factory must not be nil")
	}

	httpClient, err := httpClientForClientCredential(cfg.TLS, buildHTTPClient)
	if err != nil {
		return nil, fmt.Errorf("creating client credential HTTP client: %w", err)
	}

	wrappedCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	ccCfg := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     cfg.TokenEndpoint,
		Scopes:       cfg.Scopes,
	}
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

func httpClientForClientCredential(tlsCfg *authentication.TLS, buildHTTPClient caclient.ClientFactoryFunc) (*http.Client, error) {
	var certificateAuthority string
	if tlsCfg != nil && tlsCfg.CertificateAuthority != nil {
		certificateAuthority = *tlsCfg.CertificateAuthority
	}

	return buildHTTPClient("client credentials token endpoint CA", certificateAuthority, tokenEndpointRequestTimeout)
}
