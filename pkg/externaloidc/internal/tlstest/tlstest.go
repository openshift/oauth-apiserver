// Package tlstest provides helpers generating CAs, serving certificates and TLS
// servers for tests.
package tlstest

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/crypto"
)

const lifetime = time.Hour

// NewCAPEM generates a self-signed CA and returns it PEM encoded.
func NewCAPEM(t testing.TB, name string) string {
	t.Helper()

	_, caPEM := newCA(t, name)
	return caPEM
}

// NewServerCert generates a new CA and a serving certificate for 127.0.0.1
// signed by it. It returns the serving certificate and the PEM encoded CA,
// which is what a bundle trusting the certificate contains.
func NewServerCert(t testing.TB, name string) (tls.Certificate, string) {
	t.Helper()

	ca, caPEM := newCA(t, name)

	serverConfig, err := ca.MakeServerCert(sets.New("127.0.0.1"), lifetime)
	if err != nil {
		t.Fatalf("generating serving certificate: %v", err)
	}

	certPEM, keyPEM, err := serverConfig.GetPEMBytes()
	if err != nil {
		t.Fatalf("encoding serving certificate: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("loading serving certificate: %v", err)
	}

	return cert, caPEM
}

// NewServer starts a TLS server serving handler with a certificate signed by a
// newly generated CA. It returns the server, closed when the test ends, and the
// PEM encoded CA.
func NewServer(t testing.TB, name string, handler http.Handler) (*httptest.Server, string) {
	t.Helper()

	cert, caPEM := NewServerCert(t, name)

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv, caPEM
}

func newCA(t testing.TB, name string) (*crypto.CA, string) {
	t.Helper()

	caConfig, err := crypto.MakeSelfSignedCAConfig(name, lifetime)
	if err != nil {
		t.Fatalf("generating self-signed CA: %v", err)
	}

	caPEM, _, err := caConfig.GetPEMBytes()
	if err != nil {
		t.Fatalf("encoding CA: %v", err)
	}

	return &crypto.CA{Config: caConfig, SerialGenerator: &crypto.RandomSerialGenerator{}}, string(caPEM)
}
