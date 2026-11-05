package config

import (
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"k8s.io/utils/ptr"
)

func TestConfigurator_Run(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/token":
			fmt.Fprint(w, `{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`)
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":"https://%s","jwks_uri":"https://%s/keys"}`, r.Host, r.Host)
		case "/keys":
			fmt.Fprint(w, `{"keys":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))

	configYAML := fmt.Sprintf(`apiVersion: authentication.openshift.io/v1alpha1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: %s
    certificateAuthority: %q
    audiences: [cluster]
  claimMappings:
    username:
      claim: sub
      prefix: ""
    groups:
      expression: claims.external_groups
  externalClaimsSources:
  - url:
      hostname: claims.example.com
      pathExpression: '["users", string(claims.sub)]'
    tls:
      certificateAuthority: %q
    authentication:
      type: ClientCredential
      clientCredential:
        clientID: claims-client
        clientSecret: test-secret
        tokenEndpoint: %s/token
        scopes: [read]
        tls:
          certificateAuthority: %q
    mappings:
    - name: external_groups
      expression: response.groups
    conditions:
    - expression: 'has(claims.sub)'
`, server.URL, caPEM, caPEM, server.URL, caPEM)
	want := &authentication.AuthenticationConfiguration{
		JWT: []authentication.JWTAuthenticator{{
			Issuer: &authentication.Issuer{URL: server.URL, CertificateAuthority: caPEM, Audiences: []string{"cluster"}},
			ClaimMappings: &authentication.ClaimMappings{
				Username: authentication.PrefixedClaimOrExpression{Claim: "sub", Prefix: ptr.To("")},
				Groups:   authentication.PrefixedClaimOrExpression{Expression: "claims.external_groups"},
			},
			ExternalClaimsSources: []authentication.ExternalClaimsSource{{
				URL: &authentication.SourceURL{Hostname: ptr.To("claims.example.com"), PathExpression: ptr.To(`["users", string(claims.sub)]`)},
				TLS: &authentication.TLS{CertificateAuthority: ptr.To(caPEM)},
				Authentication: &authentication.Authentication{
					Type: ptr.To(authentication.AuthenticationTypeClientCredential),
					ClientCredential: &authentication.ClientCredentialConfig{
						ClientID: "claims-client", ClientSecret: "test-secret",
						TokenEndpoint: server.URL + "/token", Scopes: []string{"read"},
						TLS: &authentication.TLS{CertificateAuthority: ptr.To(caPEM)},
					},
				},
				Mappings:   []authentication.SourcedClaimMapping{{Name: ptr.To("external_groups"), Expression: ptr.To("response.groups")}},
				Conditions: []authentication.ExternalSourceCondition{{Expression: ptr.To("has(claims.sub)")}},
			}},
		}},
	}

	type testcase struct {
		name          string
		configFile    string
		configContent string
		wantErr       bool
		errContains   string
		wantConfig    *authentication.AuthenticationConfiguration
	}

	testcases := []testcase{
		{
			name:        "empty config file path returns error",
			configFile:  "",
			wantErr:     true,
			errContains: "configuration file must be specified",
		},
		{
			name:        "non-existent config file returns error",
			configFile:  "/non/existent/file.yaml",
			wantErr:     true,
			errContains: "reading authentication configuration from config file",
		},
		{
			name:       "invalid YAML returns error",
			configFile: "config.yaml",
			configContent: `
invalid yaml content {{{
`,
			wantErr:     true,
			errContains: "reading authentication configuration from config file",
		},
		{
			name:       "no jwt authenticators specified fails validation",
			configFile: "config.yaml",
			configContent: `
apiVersion: authentication.openshift.io/v1alpha1
kind: AuthenticationConfiguration
jwt: []
`,
			wantErr:     true,
			errContains: "jwt is required and must not be empty",
		},
		{
			name:       "valid config with jwt authenticator passes validation",
			configFile: "config.yaml",
			configContent: `
apiVersion: authentication.openshift.io/v1alpha1
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://keycloak:8443/realms/k8s
      audiences:
        - k8s-client
    claimMappings:
      username:
        claim: "preferred_username"
        prefix: ""
`,
			wantErr: false,
		},
		{
			name:          "nested external claims",
			configFile:    "config.yaml",
			configContent: configYAML,
			wantConfig:    want,
		},
		{
			name:          "unknown top-level field",
			configFile:    "config.yaml",
			configContent: configYAML + "unknownField: true\n",
			wantErr:       true,
			errContains:   `unknown field "unknownField"`,
		},
		{
			name:          "unknown nested field",
			configFile:    "config.yaml",
			configContent: strings.Replace(configYAML, "clientID:", "unknownClientID:", 1),
			wantErr:       true,
			errContains:   `unknown field "unknownClientID"`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			configurator := NewConfigurator()
			cfgPath := tc.configFile

			if tc.configContent != "" {
				dir := t.TempDir()
				filePath := filepath.Join(dir, tc.configFile)
				file, err := os.Create(filePath)
				if err != nil {
					t.Fatalf("failed to create temporary config file: %v", err)
				}
				defer file.Close()

				if _, err := file.Write([]byte(tc.configContent)); err != nil {
					t.Fatalf("failed to write test config file: %v", err)
				}
				cfgPath = filePath
			}

			configurator.configFile = cfgPath

			err := configurator.Run(t.Context())

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("expected error to contain %q, got: %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				if tc.wantConfig != nil {
					got, hash, err := configurator.Validate()
					if err != nil {
						t.Fatalf("validating configuration: %v", err)
					}
					if diff := cmp.Diff(tc.wantConfig, got); diff != "" {
						t.Fatalf("configuration mismatch (-want +got):\n%s", diff)
					}
					wantHash := sha256.Sum256([]byte(tc.configContent))
					if hash != string(wantHash[:]) {
						t.Fatal("configuration hash does not match file contents")
					}
				}
			}
		})
	}
}
