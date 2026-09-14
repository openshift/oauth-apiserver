package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/kubernetes/pkg/util/filesystem"
)

func TestConfigurator_Run(t *testing.T) {
	type testcase struct {
		name          string
		configFile    string
		configContent string
		wantErr       bool
		errContains   string
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

func TestProxyCAContentFromFile(t *testing.T) {
	proxyCAContent, err := proxyCAContentFromFile("")
	if err != nil {
		t.Fatalf("loading an empty proxy CA path: %v", err)
	}
	if proxyCAContent != nil {
		t.Fatal("expected no proxy CA content for an empty path")
	}

	if _, err := proxyCAContentFromFile("/nonexistent/proxy-ca.pem"); err == nil {
		t.Fatal("expected an error for a nonexistent proxy CA file")
	}
}

func TestAuthenticationConfigurationFromConfigurationFileReadsProxyTrustedCA(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "auth-config.json")
	if err := os.WriteFile(configFile, []byte(`{"proxyTrustedCA":"/etc/proxy-ca/ca-bundle.crt"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	config, _, err := AuthenticationConfigurationFromConfigurationFile(&filesystem.DefaultFs{}, configFile)
	if err != nil {
		t.Fatalf("reading authentication configuration: %v", err)
	}
	if got, want := config.ProxyTrustedCA, "/etc/proxy-ca/ca-bundle.crt"; got != want {
		t.Fatalf("proxy trusted CA = %q, want %q", got, want)
	}
}
