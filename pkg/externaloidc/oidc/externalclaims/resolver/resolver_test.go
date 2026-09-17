package resolver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	externaloidccel "github.com/openshift/oauth-apiserver/pkg/externaloidc/cel"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	k8soidc "k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/utils/ptr"
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

func TestHTTPClientForTLSConfigUsesProxyCAContentProvider(t *testing.T) {
	_, err := httpClientForTLSConfig(nil, invalidProxyCAContentProvider{})
	if err == nil || !strings.Contains(err.Error(), "failed to parse CA content from provider \"proxy-ca\"") {
		t.Fatalf("expected proxy CA parsing error, got %v", err)
	}
}

func TestNew(t *testing.T) {
	type testcase struct {
		name     string
		compiler Compiler
		source   authentication.ExternalClaimsSource
		err      string
	}

	testcases := []testcase{
		{
			name:     "invalid source, bad TLS CA certificate",
			compiler: nil,
			source: authentication.ExternalClaimsSource{
				TLS: &authentication.TLS{
					CertificateAuthority: ptr.To("not a real certificate"),
				},
			},
			err: "building http client for external source: applying transport option 0 failed: failed to parse CA certificates from \"external claims source CA\"",
		},
		{
			name:     "invalid source, bad source URL path expression",
			compiler: externaloidccel.NewCompiler(),
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					Hostname:       ptr.To("example.com"),
					PathExpression: ptr.To("!A&*^"),
				},
			},
			err: "building external claims url mapper: compiling path expression: compilation failed",
		},
		{
			name:     "invalid source, bad claim mapping expression",
			compiler: externaloidccel.NewCompiler(),
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					Hostname:       ptr.To("example.com"),
					PathExpression: ptr.To("['path']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("groups"),
						Expression: ptr.To("!^&*^"),
					},
				},
			},
			err: "building external claims response mapper: compiling sourced claim mapping for claim \"groups\": compilation failed",
		},
		{
			name:     "invalid source, bad condition expression",
			compiler: externaloidccel.NewCompiler(),
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					Hostname:       ptr.To("example.com"),
					PathExpression: ptr.To("['path']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("groups"),
						Expression: ptr.To("response.groups.join(',')"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("'notabool'"),
					},
				},
			},
			err: "building external claims conditions mapper: compiling condition \"'notabool'\": must evaluate to bool",
		},
		{
			name:     "valid source",
			compiler: externaloidccel.NewCompiler(),
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					Hostname:       ptr.To("example.com"),
					PathExpression: ptr.To("['path']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("groups"),
						Expression: ptr.To("response.groups.join(',')"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.groups)"),
					},
				},
			},
		},
		{
			name:     "valid source, mapping with no claim name is skipped",
			compiler: externaloidccel.NewCompiler(),
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					Hostname:       ptr.To("example.com"),
					PathExpression: ptr.To("['path']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("groups"),
						Expression: ptr.To("response.groups.join(',')"),
					},
					{
						Name:       nil,
						Expression: ptr.To("response.groups.join(',')"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.groups)"),
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.compiler, nil, tc.source)
			switch {
			case err == nil && len(tc.err) > 0:
				t.Fatalf("expected error containing %q but got none", tc.err)
			case err != nil && len(tc.err) == 0:
				t.Fatalf("received an unexpected error: %v", err)
			case err != nil && len(tc.err) > 0 && !strings.Contains(err.Error(), tc.err):
				t.Fatalf("error %v does not contain expected substring %q", err, tc.err)
			}
		})
	}
}

func TestExpandClaims(t *testing.T) {
	type testcase struct {
		name              string
		source            authentication.ExternalClaimsSource
		validToken        string
		tokenGetter       AccessTokenGetter
		startingClaims    k8soidc.ClaimsMap
		response          any
		expectedClaims    k8soidc.ClaimsMap
		requireAuthHeader bool
	}

	testcases := []testcase{
		{
			name: "conditions evaluate to false, no claims are sourced",
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					PathExpression: ptr.To("['claims']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("test"),
						Expression: ptr.To("response.existing"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("false"),
					},
				},
			},
			validToken:  "",
			tokenGetter: nil,
			startingClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			response: map[string]any{},
			expectedClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
		},
		{
			name: "conditions evaluate to true, getting access token fails, no claims are sourced",
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					PathExpression: ptr.To("['claims']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("test"),
						Expression: ptr.To("response.existing"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.existing)"),
					},
				},
			},
			validToken:  "",
			tokenGetter: &mockTokenGetter{err: errors.New("boom")},
			startingClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			response: map[string]any{
				"added": "value",
			},
			expectedClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
		},
		{
			name: "conditions evaluate to true, getting access token returns invalid access token, no claims are sourced",
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					PathExpression: ptr.To("['claims']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("test"),
						Expression: ptr.To("response.existing"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.existing)"),
					},
				},
			},
			validToken:  "validtoken",
			tokenGetter: &mockTokenGetter{token: "notvalid"},
			startingClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			response: map[string]any{
				"added": "value",
			},
			expectedClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			requireAuthHeader: true,
		},
		{
			name: "conditions evaluate to true, getting access token returns valid access token, URL mapping returns invalid type, no claims are sourced",
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					PathExpression: ptr.To("'claims'"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("test"),
						Expression: ptr.To("response.existing"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.existing)"),
					},
				},
			},
			validToken:  "validtoken",
			tokenGetter: &mockTokenGetter{token: "validtoken"},
			startingClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			response: map[string]any{
				"added": "value",
			},
			expectedClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			requireAuthHeader: true,
		},
		{
			name: "conditions evaluate to true, getting access token returns valid access token, URL mapping returns valid type, claim mapping returns invalid type, no claims are sourced",
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					PathExpression: ptr.To("['claims']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("test"),
						Expression: ptr.To("response.listkey"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.existing)"),
					},
				},
			},
			validToken:  "validtoken",
			tokenGetter: &mockTokenGetter{token: "validtoken"},
			startingClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			response: map[string]any{
				"added":   "value",
				"listkey": []string{"one", "two"},
			},
			expectedClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			requireAuthHeader: true,
		},
		{
			name: "conditions evaluate to true, getting access token returns valid access token, URL mapping returns valid type, claim mapping returns valid type, response body is map[string]any serializable, additional claims are sourced",
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					PathExpression: ptr.To("['claims']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("test"),
						Expression: ptr.To("response.body.listkey.join(',')"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.existing)"),
					},
				},
			},
			validToken:  "validtoken",
			tokenGetter: &mockTokenGetter{token: "validtoken"},
			startingClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			response: map[string]any{
				"added":   "value",
				"listkey": []string{"one", "two"},
			},
			expectedClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage([]byte("\"value\"")),
				"test":     json.RawMessage([]byte("\"one,two\"")),
			},
			requireAuthHeader: true,
		},
		{
			name: "conditions evaluate to true, getting access token returns valid access token, URL mapping returns valid type, claim mapping returns valid type, response body is not map[string]any serializable and is a complex list, additional claims are sourced",
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					PathExpression: ptr.To("['claims']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("test"),
						Expression: ptr.To("response.body.map(x, x.displayName).join(',')"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.existing)"),
					},
				},
			},
			validToken:  "validtoken",
			tokenGetter: &mockTokenGetter{token: "validtoken"},
			startingClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			response: []struct {
				ID          int    `json:"id"`
				Path        string `json:"path,omitempty"`
				DisplayName string `json:"displayName,omitempty"`
			}{
				{
					ID:          1234,
					Path:        "/groups/one",
					DisplayName: "one",
				},
				{
					ID:          5678,
					Path:        "/groups/two",
					DisplayName: "two",
				},
			},
			expectedClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage([]byte("\"value\"")),
				"test":     json.RawMessage([]byte("\"one,two\"")),
			},
			requireAuthHeader: true,
		},
		{
			name: "conditions evaluate to true, getting access token returns valid access token, URL mapping returns valid type, claim mapping returns valid type, response body is not map[string]any serializable and is a string, additional claims are sourced",
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					PathExpression: ptr.To("['claims']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("test"),
						Expression: ptr.To("response.body"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.existing)"),
					},
				},
			},
			validToken:  "validtoken",
			tokenGetter: &mockTokenGetter{token: "validtoken"},
			startingClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			response: "one,two",
			expectedClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage([]byte("\"value\"")),
				"test":     json.RawMessage([]byte("\"one,two\"")),
			},
			requireAuthHeader: true,
		},
		{
			name: "conditions evaluate to true, getting access token returns empty access token, anonymous auth, URL mapping returns valid type, claim mapping returns valid type, response body is not map[string]any serializable and is a string, additional claims are sourced",
			source: authentication.ExternalClaimsSource{
				URL: &authentication.SourceURL{
					PathExpression: ptr.To("['claims']"),
				},
				Mappings: []authentication.SourcedClaimMapping{
					{
						Name:       ptr.To("test"),
						Expression: ptr.To("response.body"),
					},
				},
				Conditions: []authentication.ExternalSourceCondition{
					{
						Expression: ptr.To("has(claims.existing)"),
					},
				},
			},
			validToken:  "",
			tokenGetter: &mockTokenGetter{token: ""},
			startingClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage("\"value\""),
			},
			response: "one,two",
			expectedClaims: k8soidc.ClaimsMap{
				"existing": json.RawMessage([]byte("\"value\"")),
				"test":     json.RawMessage([]byte("\"one,two\"")),
			},
			requireAuthHeader: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			compiler := externaloidccel.NewCompiler()

			srv := newTestServer(tc.response, tc.validToken, tc.requireAuthHeader)
			srv.StartTLS()
			defer srv.Close()

			url, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatalf("failed to parse mock server url: %v", err)
			}

			tc.source.URL.Hostname = &url.Host

			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: srv.Certificate().Raw,
			}
			pemBytes := pem.EncodeToMemory(pemBlock)

			tc.source.TLS = &authentication.TLS{
				CertificateAuthority: ptr.To(string(pemBytes)),
			}

			resolver, err := New(compiler, tc.tokenGetter, tc.source)
			if err != nil {
				t.Fatalf("expected to sucessfully create a new external claims resolver but received error: %v", err)
			}

			err = resolver.ExpandClaims(t.Context(), tc.startingClaims)
			if err != nil {
				t.Fatalf("external claims resolver should never return an error during claim expansion but received error: %v", err)
			}

			if diff := cmp.Diff(tc.startingClaims, tc.expectedClaims); len(diff) > 0 {
				t.Fatalf("starting claims (-) after expansion does not match expected claims (+): %s", diff)
			}
		})
	}
}

func newTestServer(response any, validToken string, requireAuthHeader bool) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/claims", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != fmt.Sprintf("Bearer %s", validToken) && requireAuthHeader {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		out, err := json.Marshal(response)
		if err != nil {
			panic("couldn't marshal response claims")
		}

		_, err = w.Write(out)
		if err != nil {
			panic(fmt.Sprintf("errored writing output %q to response writer: %v", string(out), err))
		}
	})

	return httptest.NewUnstartedServer(mux)
}

type mockTokenGetter struct {
	token string
	err   error
}

func (mtg *mockTokenGetter) GetAccessToken(_ context.Context) (string, error) {
	return mtg.token, mtg.err
}
