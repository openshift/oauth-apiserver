package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
)

func TestDynamicCAHTTPClientCombinesIssuerAndProxyCAs(t *testing.T) {
	issuerCAPEM, issuerCACert, issuerCAKey := generateCA(t)
	issuerServer := startTLSServer(t, generateServerCert(t, issuerCACert, issuerCAKey))

	proxyCAPEM, proxyCACert, proxyCAKey := generateCA(t)
	proxyServer := startTLSServer(t, generateServerCert(t, proxyCACert, proxyCAKey))

	proxyCAFile := filepath.Join(t.TempDir(), "proxy-ca.pem")
	writeFile(t, proxyCAFile, proxyCAPEM)
	proxyCAContent, err := dynamiccertificates.NewDynamicCAContentFromFile("proxy-ca", proxyCAFile)
	if err != nil {
		t.Fatalf("loading proxy CA: %v", err)
	}

	client, err := newDynamicCAHTTPClient(proxyCAContent, issuerCAPEM)
	if err != nil {
		t.Fatalf("creating HTTP client: %v", err)
	}
	mustGet(t, client, issuerServer.URL, "issuer CA")
	mustGet(t, client, proxyServer.URL, "proxy CA")
}

func TestDynamicCAHTTPClientReloadsProxyCA(t *testing.T) {
	proxyCA1PEM, proxyCA1Cert, proxyCA1Key := generateCA(t)
	server1 := startTLSServer(t, generateServerCert(t, proxyCA1Cert, proxyCA1Key))

	proxyCA2PEM, proxyCA2Cert, proxyCA2Key := generateCA(t)
	server2 := startTLSServer(t, generateServerCert(t, proxyCA2Cert, proxyCA2Key))

	proxyCAFile := filepath.Join(t.TempDir(), "proxy-ca.pem")
	writeFile(t, proxyCAFile, proxyCA1PEM)
	proxyCAContent, err := dynamiccertificates.NewDynamicCAContentFromFile("proxy-ca", proxyCAFile)
	if err != nil {
		t.Fatalf("loading proxy CA: %v", err)
	}
	client, err := newDynamicCAHTTPClient(proxyCAContent, nil)
	if err != nil {
		t.Fatalf("creating HTTP client: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go proxyCAContent.Run(ctx, 1)

	mustGet(t, client, server1.URL, "initial proxy CA")
	writeFile(t, proxyCAFile, proxyCA2PEM)

	err = wait.PollUntilContextTimeout(t.Context(), 50*time.Millisecond, 10*time.Second, false, func(context.Context) (bool, error) {
		response, err := client.Get(server2.URL)
		if err != nil {
			return false, nil
		}
		_ = response.Body.Close()
		return response.StatusCode == http.StatusOK, nil
	})
	if err != nil {
		t.Fatalf("waiting for proxy CA reload: %v", err)
	}
}

func generateCA(t *testing.T) ([]byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), certificate, key
}

func generateServerCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
}

func startTLSServer(t *testing.T, certificate tls.Certificate) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func writeFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustGet(t *testing.T, client *http.Client, url, name string) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("request using %s: %v", name, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("request using %s returned %d, want %d", name, response.StatusCode, http.StatusOK)
	}
}
