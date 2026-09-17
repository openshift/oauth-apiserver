package tokengetters

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

type invalidProxyCAContentProvider struct{}

func (invalidProxyCAContentProvider) AddListener(dynamiccertificates.Listener) {}
func (invalidProxyCAContentProvider) Name() string                             { return "proxy-ca" }
func (invalidProxyCAContentProvider) CurrentCABundleContent() []byte {
	return []byte("not a certificate")
}
func (invalidProxyCAContentProvider) VerifyOptions() (x509.VerifyOptions, bool) {
	return x509.VerifyOptions{}, false
}

func TestHTTPClientForClientCredentialUsesProxyCAContentProvider(t *testing.T) {
	_, err := httpClientForClientCredential(nil, invalidProxyCAContentProvider{})
	if err == nil || !strings.Contains(err.Error(), "failed to parse CA content from provider \"proxy-ca\"") {
		t.Fatalf("expected proxy CA parsing error, got %v", err)
	}
}

func TestClientCredential(t *testing.T) {
	type testcase struct {
		name          string
		cfg           *authentication.ClientCredentialConfig
		tokenHandler  http.HandlerFunc
		err           string
		expectedToken string
	}

	testcases := []testcase{
		{
			name: "nil config, error",
			cfg:  nil,
			err:  "client credential configuration must not be nil",
		},
		{
			name: "valid config, no error",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "access-token",
					"token_type":   "Bearer",
				})
				if err != nil {
					panic(fmt.Sprintf("errored during response encoding: %v", err))
				}
			},
			cfg: &authentication.ClientCredentialConfig{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			expectedToken: "access-token",
		},
		{
			name: "valid config with scopes, no error",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "access-token",
					"token_type":   "Bearer",
				})
				if err != nil {
					panic(fmt.Sprintf("errored during response encoding: %v", err))
				}
			},
			cfg: &authentication.ClientCredentialConfig{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				Scopes:       []string{"https://graph.microsoft.com/.default"},
			},
			expectedToken: "access-token",
		},
		{
			name: "invalid certificate authority, error",
			cfg: &authentication.ClientCredentialConfig{
				ClientID:      "client-id",
				ClientSecret:  "client-secret",
				TokenEndpoint: "https://example.com/oauth2/token",
				TLS: &authentication.TLS{
					CertificateAuthority: func() *string {
						s := "not-a-valid-pem"
						return &s
					}(),
				},
			},
			err: "applying transport option 0 failed: failed to parse CA certificates from \"client credentials token endpoint CA\"",
		},
		{
			name: "initial token fetch fails, error",
			tokenHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				err := json.NewEncoder(w).Encode(map[string]interface{}{
					"error":             "invalid_client",
					"error_description": "client authentication failed",
				})
				if err != nil {
					panic(fmt.Sprintf("errored during response encoding: %v", err))
				}
			},
			cfg: &authentication.ClientCredentialConfig{
				ClientID:     "bad-client-id",
				ClientSecret: "bad-secret",
			},
			err: "getting initial access token: getting token: oauth2: \"invalid_client\" \"client authentication failed\"",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tokenHandler != nil {
				server := httptest.NewServer(tc.tokenHandler)
				defer server.Close()

				if tc.cfg != nil && tc.cfg.TokenEndpoint == "" {
					tc.cfg.TokenEndpoint = server.URL + "/oauth2/token"
				}
			}

			cc, err := NewClientCredential(t.Context(), tc.cfg)
			switch {
			case err == nil && len(tc.err) > 0:
				t.Fatalf("expected error containing %q but got none", tc.err)
			case err != nil && len(tc.err) == 0:
				t.Fatalf("received an unexpected error: %v", err)
			case err != nil && len(tc.err) > 0 && !strings.Contains(err.Error(), tc.err):
				t.Fatalf("error %v does not contain expected substring %q", err, tc.err)
			}

			if cc == nil {
				return
			}

			token, err := cc.GetAccessToken(t.Context())
			if err != nil {
				t.Fatalf("unexpected error when attempting to get token: %v", err)
			}

			if token != tc.expectedToken {
				t.Fatalf("actual token does not match expected token: actual: %q expected: %q", token, tc.expectedToken)
			}
		})
	}
}
