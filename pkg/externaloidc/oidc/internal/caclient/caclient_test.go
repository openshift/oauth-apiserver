package caclient

import (
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"github.com/openshift/library-go/pkg/crypto"
)

type invalidCAContentProvider struct{}

func (invalidCAContentProvider) AddListener(dynamiccertificates.Listener) {}
func (invalidCAContentProvider) Name() string                             { return "invalid-ca" }
func (invalidCAContentProvider) CurrentCABundleContent() []byte {
	return []byte("not a certificate")
}
func (invalidCAContentProvider) VerifyOptions() (x509.VerifyOptions, bool) {
	return x509.VerifyOptions{}, false
}

func TestNewUsesTrustedCA(t *testing.T) {
	_, err := New("test-ca", "", invalidCAContentProvider{}, time.Second)
	if err == nil || !strings.Contains(err.Error(), `failed to parse CA content from provider "invalid-ca"`) {
		t.Fatalf("expected trusted CA parsing error, got %v", err)
	}
}

// TestNewPinsConfiguredCA asserts that a configured certificate authority
// replaces the system trust roots instead of extending them.
func TestNewPinsConfiguredCA(t *testing.T) {
	caConfig, err := crypto.MakeSelfSignedCAConfig("test-ca", time.Hour)
	if err != nil {
		t.Fatalf("generating self-signed CA: %v", err)
	}

	pemBytes, _, err := caConfig.GetPEMBytes()
	if err != nil {
		t.Fatalf("encoding CA certificate: %v", err)
	}

	client, err := New("test-ca", string(pemBytes), nil, time.Second)
	if err != nil {
		t.Fatalf("building http client: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected transport of type *http.Transport, got %T", client.Transport)
	}

	want := x509.NewCertPool()
	if !want.AppendCertsFromPEM(pemBytes) {
		t.Fatal("building the expected certificate pool")
	}

	if !want.Equal(transport.TLSClientConfig.RootCAs) {
		t.Error("expected the configured certificate authority to be the only trust root")
	}
}

func TestNewSetsTimeout(t *testing.T) {
	client, err := New("test-ca", "", nil, 7*time.Second)
	if err != nil {
		t.Fatalf("building http client: %v", err)
	}

	if client.Timeout != 7*time.Second {
		t.Errorf("expected timeout %s, got %s", 7*time.Second, client.Timeout)
	}
}
