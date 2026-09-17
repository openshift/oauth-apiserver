package tokengetters

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/openshift/library-go/pkg/network/httptransport"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

// tokenEndpointRequestTimeout is the timeout for HTTP requests to the token endpoint.
const tokenEndpointRequestTimeout = time.Second

// ClientCredential is an AccessTokenGetter that uses the OAuth2 client credentials
// grant flow to obtain an access token for authenticating with external claims sources.
type ClientCredential struct {
	tokenSource oauth2.TokenSource
}

// NewClientCredential creates a new ClientCredential token getter from the provided configuration.
func NewClientCredential(ctx context.Context, cfg *authentication.ClientCredentialConfig, proxyCAContentProvider ...dynamiccertificates.CAContentProvider) (*ClientCredential, error) {
	if cfg == nil {
		return nil, fmt.Errorf("client credential configuration must not be nil")
	}

	httpClient, err := httpClientForClientCredential(cfg.TLS, proxyCAContentProvider...)
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

func httpClientForClientCredential(tlsCfg *authentication.TLS, proxyCAContentProvider ...dynamiccertificates.CAContentProvider) (*http.Client, error) {
	client := &http.Client{
		Timeout: tokenEndpointRequestTimeout,
	}

	opts := []httptransport.Option{}
	if tlsCfg != nil && tlsCfg.CertificateAuthority != nil && len(*tlsCfg.CertificateAuthority) > 0 {
		opts = append(opts, httptransport.WithCAData("client credentials token endpoint CA", []byte(*tlsCfg.CertificateAuthority)))
	}
	for _, provider := range proxyCAContentProvider {
		if provider != nil {
			opts = append(opts, httptransport.WithCAContentProvider(provider))
		}
	}
	if len(opts) == 0 {
		return client, nil
	}
	transport, err := httptransport.NewRoundTripper(opts...)
	if err != nil {
		return nil, err
	}
	client.Transport = transport
	return client, nil
}
