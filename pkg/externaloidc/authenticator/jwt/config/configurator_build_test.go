package config

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	externaloidccel "github.com/openshift/oauth-apiserver/pkg/externaloidc/cel"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/caclient"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/tlstest"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/oidc/externalclaims/tokengetters"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

func TestBuildExternalClaimsTokenGetter(t *testing.T) {
	srv, caPEM, _ := newTestIssuerServer(t)

	testcases := []struct {
		name        string
		authn       *authentication.Authentication
		wantType    any
		errContains string
	}{
		{
			name:     "nil authentication yields an anonymous getter",
			authn:    nil,
			wantType: &tokengetters.Anonymous{},
		},
		{
			name:        "nil type is rejected",
			authn:       &authentication.Authentication{},
			errContains: "no authentication type specified",
		},
		{
			name:     "request provided token",
			authn:    &authentication.Authentication{Type: new(authentication.AuthenticationTypeRequestProvidedToken)},
			wantType: &tokengetters.RequestProvided{},
		},
		{
			name:        "client credential without configuration is rejected",
			authn:       &authentication.Authentication{Type: new(authentication.AuthenticationTypeClientCredential)},
			errContains: "client credential configuration is required",
		},
		{
			name: "client credential",
			authn: &authentication.Authentication{
				Type: new(authentication.AuthenticationTypeClientCredential),
				ClientCredential: &authentication.ClientCredentialConfig{
					ClientID:      "client",
					ClientSecret:  "secret",
					TokenEndpoint: srv.URL + "/token",
					TLS:           &authentication.TLS{CertificateAuthority: new(caPEM)},
				},
			},
			wantType: &tokengetters.ClientCredential{},
		},
		{
			name:        "unknown type is rejected",
			authn:       &authentication.Authentication{Type: new(authentication.AuthenticationType("Bogus"))},
			errContains: `unknown authentication type "Bogus"`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildExternalClaimsTokenGetter(t.Context(), tc.authn, testHTTPClientFactory)
			if tc.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got: %v", tc.errContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tc.wantType) {
				t.Fatalf("expected token getter of type %T, got %T", tc.wantType, got)
			}
		})
	}
}

func TestBuildExternalClaimsExpanders(t *testing.T) {
	srv, caPEM, _ := newTestIssuerServer(t)
	compiler := externaloidccel.NewCompiler()

	validSource := func() authentication.ExternalClaimsSource {
		return authentication.ExternalClaimsSource{
			URL: &authentication.SourceURL{
				Hostname:       new("claims.example.com"),
				PathExpression: new(`["users", string(claims.sub)]`),
			},
			TLS: &authentication.TLS{CertificateAuthority: new(caPEM)},
			Authentication: &authentication.Authentication{
				Type: new(authentication.AuthenticationTypeClientCredential),
				ClientCredential: &authentication.ClientCredentialConfig{
					ClientID:      "client",
					ClientSecret:  "secret",
					TokenEndpoint: srv.URL + "/token",
					TLS:           &authentication.TLS{CertificateAuthority: new(caPEM)},
				},
			},
			Mappings: []authentication.SourcedClaimMapping{{Name: new("groups"), Expression: new("response.groups")}},
		}
	}

	t.Run("no sources yields no expanders", func(t *testing.T) {
		got, err := buildExternalClaimsExpanders(t.Context(), compiler, testHTTPClientFactory)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected no expanders, got %d", len(got))
		}
	})

	t.Run("one expander per source and the factory is used for token endpoint and source", func(t *testing.T) {
		var names []string
		factory := func(name, ca string, timeout time.Duration) (*http.Client, error) {
			if timeout <= 0 {
				t.Errorf("factory called with non-positive timeout %v for %q", timeout, name)
			}
			names = append(names, name)
			return caclient.New(name, ca, nil, timeout)
		}

		got, err := buildExternalClaimsExpanders(t.Context(), compiler, factory, validSource(), validSource())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 expanders, got %d", len(got))
		}

		want := []string{
			"client credentials token endpoint CA", "external claims source CA",
			"client credentials token endpoint CA", "external claims source CA",
		}
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("unexpected factory calls: want %v, got %v", want, names)
		}
	})
}

func TestTokenAuthenticatorForAuthenticationConfiguration(t *testing.T) {
	srv, caPEM, discoveryHits := newTestIssuerServer(t)
	compiler := externaloidccel.NewCompiler()

	newConfig := func(issuerCA string, sources ...authentication.ExternalClaimsSource) *authentication.AuthenticationConfiguration {
		return &authentication.AuthenticationConfiguration{
			JWT: []authentication.JWTAuthenticator{{
				Issuer: &authentication.Issuer{
					URL:                  srv.URL,
					CertificateAuthority: issuerCA,
					Audiences:            []string{"cluster"},
				},
				ClaimMappings: &authentication.ClaimMappings{
					Username: authentication.PrefixedClaimOrExpression{Claim: "sub", Prefix: new("")},
				},
				ExternalClaimsSources: sources,
			}},
		}
	}
	staticProvider := func(t *testing.T, pemData string) dynamiccertificates.CAContentProvider {
		t.Helper()
		p, err := dynamiccertificates.NewStaticCAContent("test", []byte(pemData))
		if err != nil {
			t.Fatalf("creating static CA provider: %v", err)
		}
		return p
	}

	testcases := []struct {
		name        string
		cfg         *authentication.AuthenticationConfiguration
		provider    func(t *testing.T) dynamiccertificates.CAContentProvider
		errContains string
	}{
		{
			name: "no trusted provider, issuer CA",
			cfg:  newConfig(caPEM),
		},
		{
			name:        "no trusted provider, invalid issuer CA",
			cfg:         newConfig("not a certificate"),
			errContains: "creating CA content provider",
		},
		{
			name: "trusted provider, invalid issuer CA",
			cfg:  newConfig("not a certificate"),
			provider: func(t *testing.T) dynamiccertificates.CAContentProvider {
				return staticProvider(t, tlstest.NewCAPEM(t, "test-ca"))
			},
			errContains: "building OIDC authenticator HTTP client",
		},
		{
			name: "invalid external claims source authentication",
			cfg: newConfig(caPEM, authentication.ExternalClaimsSource{
				Authentication: &authentication.Authentication{},
			}),
			errContains: "building external claims expanders",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var provider dynamiccertificates.CAContentProvider
			if tc.provider != nil {
				provider = tc.provider(t)
			}

			got, err := tokenAuthenticatorForAuthenticationConfiguration(t.Context(), tc.cfg, compiler, provider)
			if tc.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error containing %q, got: %v", tc.errContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("expected an authenticator")
			}
		})
	}

	t.Run("trusted CA provider is honored for the issuer", func(t *testing.T) {
		before := discoveryHits.Load()

		// The issuer CA is left empty on purpose: the server's certificate is
		// trusted solely through the dynamic trusted CA provider.
		_, err := tokenAuthenticatorForAuthenticationConfiguration(t.Context(), newConfig(""), compiler, staticProvider(t, caPEM))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// k8soidc.New does not perform OIDC discovery synchronously: it starts a
		// goroutine that polls oidc.NewProvider, with the first attempt made
		// immediately. Wait for that first request to reach the server, polling
		// the hit counter. If the provider were not honored, the TLS handshake
		// would fail, the server would never see a request, and the next retry
		// is 10s away, so the deadline below is hit.
		deadline := time.Now().Add(5 * time.Second)
		for discoveryHits.Load() == before {
			if time.Now().After(deadline) {
				t.Fatal("OIDC discovery never succeeded against the server trusted only through the CA provider")
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

// newTestIssuerServer starts a TLS server answering the OIDC discovery, JWKS
// and token endpoints. discoveryHits counts discovery requests.
func newTestIssuerServer(t *testing.T) (srv *httptest.Server, caPEM string, discoveryHits *atomic.Int32) {
	t.Helper()

	discoveryHits = &atomic.Int32{}
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			fmt.Fprint(w, `{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`)
		case "/.well-known/openid-configuration":
			discoveryHits.Add(1)
			fmt.Fprintf(w, `{"issuer":"https://%s","jwks_uri":"https://%s/keys"}`, r.Host, r.Host)
		case "/keys":
			fmt.Fprint(w, `{"keys":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	return srv, caPEM, discoveryHits
}

func testHTTPClientFactory(certAuthorityName, certAuthority string, timeout time.Duration) (*http.Client, error) {
	return caclient.New(certAuthorityName, certAuthority, nil, timeout)
}
