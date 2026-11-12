package caclient

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/tlstest"
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

func TestNewPinsConfiguredCA(t *testing.T) {
	pemBytes := []byte(tlstest.NewCAPEM(t, "test-ca"))

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

func TestNewTrustsEndpointCAAndTrustedCA(t *testing.T) {
	endpointCAServer, endpointCAPEM := tlstest.NewServer(t, "endpoint-ca", http.NotFoundHandler())
	trustedCAServer, trustedCAPEM := tlstest.NewServer(t, "trusted-ca", http.NotFoundHandler())
	unrelatedServer, _ := tlstest.NewServer(t, "unrelated-ca", http.NotFoundHandler())

	trustedCAProvider, err := dynamiccertificates.NewStaticCAContent("trusted-ca", []byte(trustedCAPEM))
	if err != nil {
		t.Fatalf("creating trusted CA provider: %v", err)
	}

	testcases := []struct {
		name             string
		certAuthority    string
		trustedCA        dynamiccertificates.CAContentProvider
		server           *httptest.Server
		wantUntrustedErr bool
	}{
		{
			name:          "certificate signed by the endpoint CA is accepted",
			certAuthority: endpointCAPEM,
			trustedCA:     trustedCAProvider,
			server:        endpointCAServer,
		},
		{
			name:          "certificate signed by the trusted CA is accepted",
			certAuthority: endpointCAPEM,
			trustedCA:     trustedCAProvider,
			server:        trustedCAServer,
		},
		{
			name:             "certificate signed by an unrelated CA is rejected",
			certAuthority:    endpointCAPEM,
			trustedCA:        trustedCAProvider,
			server:           unrelatedServer,
			wantUntrustedErr: true,
		},
		{
			name:             "without the trusted CA the endpoint CA is the only trust",
			certAuthority:    endpointCAPEM,
			server:           trustedCAServer,
			wantUntrustedErr: true,
		},
		{
			name:             "without an endpoint CA, only the system roots and the trusted CA apply",
			trustedCA:        trustedCAProvider,
			server:           endpointCAServer,
			wantUntrustedErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New("endpoint-ca", tc.certAuthority, tc.trustedCA, 5*time.Second)
			if err != nil {
				t.Fatalf("building http client: %v", err)
			}

			resp, err := client.Get(tc.server.URL)
			if resp != nil {
				resp.Body.Close()
			}

			var unknownAuthority x509.UnknownAuthorityError
			switch {
			case tc.wantUntrustedErr && err == nil:
				t.Fatal("expected the certificate to be rejected, but the request succeeded")
			case tc.wantUntrustedErr && !errors.As(err, &unknownAuthority):
				t.Fatalf("expected an unknown authority error, got: %v", err)
			case !tc.wantUntrustedErr && err != nil:
				t.Fatalf("expected the certificate to be accepted, got: %v", err)
			}
		})
	}
}
