package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
)

func TestConfigurator_Run(t *testing.T) {
	type testcase struct {
		name                 string
		configFile           string
		configContent        string
		trustedCAFileContent string
		wantErr              bool
		errContains          string
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
apiVersion: config.openshift.io/v1alpha1
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
apiVersion: config.openshift.io/v1alpha1
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
			name:       "trustedCAFilePath pointing at a missing file fails",
			configFile: "config.yaml",
			configContent: `
apiVersion: config.openshift.io/v1alpha1
kind: AuthenticationConfiguration
trustedCAFilePath: /non/existent/ca-bundle.pem
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
			wantErr:     true,
			errContains: `loading trusted CA from "/non/existent/ca-bundle.pem": open /non/existent/ca-bundle.pem: no such file or directory`,
		},
		{
			name:       "trustedCAFilePath pointing at an unparseable file fails",
			configFile: "config.yaml",
			configContent: `
apiVersion: config.openshift.io/v1alpha1
kind: AuthenticationConfiguration
trustedCAFilePath: {{caFile}}
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
			trustedCAFileContent: "not a valid CA bundle",
			wantErr:              true,
			// Deliberately matches only the parse failure, not the full
			// wrapping chain: the file path is a per-test temp directory, so
			// asserting on it would make this brittle across test runs.
			errContains: "data does not contain any valid RSA or ECDSA certificates",
		},
		{
			name:       "trustedCAFilePath pointing at a valid CA bundle is loaded",
			configFile: "config.yaml",
			configContent: `
apiVersion: config.openshift.io/v1alpha1
kind: AuthenticationConfiguration
trustedCAFilePath: {{caFile}}
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
			trustedCAFileContent: generateTestCAPEM(t),
			wantErr:              false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			configurator := NewConfigurator()
			cfgPath := tc.configFile

			if tc.configContent != "" {
				dir := t.TempDir()

				configContent := tc.configContent
				if tc.trustedCAFileContent != "" {
					caPath := filepath.Join(dir, "ca-bundle.pem")
					if err := os.WriteFile(caPath, []byte(tc.trustedCAFileContent), 0o644); err != nil {
						t.Fatalf("failed to write test CA file: %v", err)
					}
					configContent = strings.ReplaceAll(configContent, "{{caFile}}", caPath)
				}

				filePath := filepath.Join(dir, tc.configFile)
				file, err := os.Create(filePath)
				if err != nil {
					t.Fatalf("failed to create temporary config file: %v", err)
				}
				defer file.Close()

				if _, err := file.Write([]byte(configContent)); err != nil {
					t.Fatalf("failed to write test config file: %v", err)
				}
				cfgPath = filePath
			}

			configurator.configFile = cfgPath

			err := configurator.Run(context.TODO())

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("expected error to contain %q, got: %v", tc.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got: %v", err)
				}
			}
		})
	}
}

// generateTestCAPEM returns a PEM-encoded self-signed CA certificate suitable
// for use as a CA bundle in tests.
func generateTestCAPEM(t *testing.T) string {
	t.Helper()

	caConfig, err := crypto.MakeSelfSignedCAConfig("test-ca", time.Hour)
	if err != nil {
		t.Fatalf("generating self-signed CA: %v", err)
	}

	certBytes, _, err := caConfig.GetPEMBytes()
	if err != nil {
		t.Fatalf("encoding CA certificate: %v", err)
	}

	return string(certBytes)
}
