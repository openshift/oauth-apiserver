package config

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/go-jose/go-jose.v2"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openshift/library-go/pkg/crypto"
)

// skippedInvalidCABundle, when set, receives a signal each time the dynamic CA
// content loader reports a bundle with no valid certificates. The loader keeps
// the last valid bundle in that case and only reports the error through
// utilruntime.HandleError, which is the sole hook available to observe it.
var skippedInvalidCABundle atomic.Pointer[chan struct{}]

// The handler is registered in init so that the global utilruntime.ErrorHandlers
// is never modified while the loader goroutines of any test are running.
func init() {
	utilruntime.ErrorHandlers = append(utilruntime.ErrorHandlers, func(_ context.Context, err error, _ string, _ ...interface{}) {
		// A truncated file is reported differently ("missing content"), so
		// matching on the parse error means the invalid content itself was read.
		if ch := skippedInvalidCABundle.Load(); ch != nil && strings.Contains(err.Error(), "does not contain any valid RSA or ECDSA certificates") {
			select {
			case *ch <- struct{}{}:
			default:
			}
		}
	})
}

// TestConfigurator_TrustedCAReload verifies that changing the content of the
// trusted CA bundle at trustedCAFilePath, without touching the authentication
// configuration, affects the trust of new TLS connections made by an already
// built authenticator, and that an invalid update retains the last valid trust.
//
// The external claims source is the observable: it is only reachable over TLS
// and is trusted solely through the trusted CA bundle, so every successful
// authentication proves the bundle currently in effect trusts the certificate
// the source presents.
func TestConfigurator_TrustedCAReload(t *testing.T) {
	const (
		keyID    = "test-key"
		audience = "cluster"
	)

	// Issuer: serves discovery and JWKS. It is trusted via the issuer's own
	// certificateAuthority, so it does not depend on the trusted CA bundle.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	jwk := &jose.JSONWebKey{Key: privateKey, KeyID: keyID, Use: "sig", Algorithm: string(jose.RS256)}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &privateKey.PublicKey, KeyID: keyID, Use: "sig", Algorithm: string(jose.RS256)}}}

	issuer := httptest.NewTLSServer(nil)
	issuer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer.URL, issuer.URL+"/keys")
		case "/keys":
			_ = json.NewEncoder(w).Encode(jwks)
		default:
			http.NotFound(w, r)
		}
	})
	t.Cleanup(issuer.Close)
	issuerCAPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw}))

	// External claims source: its serving certificate can be swapped at runtime.
	cert1, cert1PEM := newServerCertWithCA(t, "source-1")
	cert2, cert2PEM := newServerCertWithCA(t, "source-2")

	var servingCert atomic.Pointer[tls.Certificate]
	servingCert.Store(&cert1)

	source := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"groups":["one","two"]}`)
	}))
	// GetConfigForClient is used instead of GetCertificate: httptest.StartTLS
	// adds its own certificate to Certificates, and GetCertificate is then
	// ignored for clients that do not send a server name, such as ones dialing an IP.
	source.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: []tls.Certificate{*servingCert.Load()}}, nil
	}}
	source.StartTLS()
	t.Cleanup(source.Close)

	switchSourceCert := func(cert *tls.Certificate) {
		servingCert.Store(cert)
		source.CloseClientConnections()
	}

	dir := t.TempDir()
	caBundlePath := filepath.Join(dir, "ca-bundle.pem")
	writeCABundle := func(content string) {
		t.Helper()
		if err := os.WriteFile(caBundlePath, []byte(content), 0o644); err != nil {
			t.Fatalf("writing CA bundle: %v", err)
		}
	}
	writeCABundle(cert1PEM)

	configPath := filepath.Join(dir, "config.yaml")
	configYAML := fmt.Sprintf(`apiVersion: authentication.openshift.io/v1alpha1
kind: AuthenticationConfiguration
trustedCAFilePath: %s
jwt:
- issuer:
    url: %s
    certificateAuthority: %q
    audiences: [%s]
  claimMappings:
    username:
      claim: sub
      prefix: ""
    groups:
      expression: "claims.groups.split(',')"
  externalClaimsSources:
  - url:
      hostname: %s
      pathExpression: '["userinfo"]'
    mappings:
    - name: groups
      expression: "response.body.groups.join(',')"
`, caBundlePath, issuer.URL, issuerCAPEM, audience, strings.TrimPrefix(source.URL, "https://"))
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	configurator := NewConfigurator()
	configurator.configFile = configPath
	if err := configurator.Run(t.Context()); err != nil {
		t.Fatalf("running configurator: %v", err)
	}
	initialAuthenticator := configurator.TokenAuthenticator()

	signer, err := jose.NewSigner(jose.SigningKey{Key: jwk, Algorithm: jose.RS256}, nil)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": issuer.URL,
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"sub": "testuser",
	})
	if err != nil {
		t.Fatalf("marshaling claims: %v", err)
	}
	jws, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing token: %v", err)
	}

	// authenticate returns nil only if the token was authenticated with the
	// groups obtained from the external claims source.
	authenticate := func() error {
		resp, ok, err := configurator.TokenAuthenticator().AuthenticateToken(t.Context(), token)
		switch {
		case err != nil:
			return err
		case !ok:
			return fmt.Errorf("token not authenticated")
		case !slices.Equal(resp.User.GetGroups(), []string{"one", "two"}):
			return fmt.Errorf("unexpected groups %v", resp.User.GetGroups())
		}
		return nil
	}
	// authenticateOnNewConnection forces a new TLS handshake with the source first.
	authenticateOnNewConnection := func() error {
		source.CloseClientConnections()
		return authenticate()
	}

	const pollInterval = 50 * time.Millisecond

	eventually := func(what string, f func() error) {
		t.Helper()
		var lastErr error
		err := wait.PollUntilContextTimeout(t.Context(), pollInterval, 10*time.Second, true, func(context.Context) (bool, error) {
			lastErr = f()
			return lastErr == nil, nil
		})
		if err != nil {
			t.Fatalf("timed out waiting for %s, last error: %v", what, lastErr)
		}
	}

	// The discovery of the issuer is asynchronous, wait for the authenticator to become ready.
	eventually("initial authentication with the initial CA bundle", authenticate)

	// A bundle that cannot be loaded must not replace the last valid one.
	// Wait until the loader reports that it skipped the invalid bundle, then
	// check that the retained trust still works for a new connection.
	skipped := make(chan struct{}, 1)
	skippedInvalidCABundle.Store(&skipped)
	t.Cleanup(func() { skippedInvalidCABundle.Store(nil) })

	writeCABundle("not a valid CA bundle")
	select {
	case <-skipped:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the invalid CA bundle to be skipped")
	}
	if err := authenticateOnNewConnection(); err != nil {
		t.Fatalf("authentication failed after an invalid CA bundle update, the last valid trust was not retained: %v", err)
	}

	// The retained trust is still the initial bundle (cert1), so a source
	// presenting cert2 must not be trusted yet.
	switchSourceCert(&cert2)
	if err := authenticate(); err == nil {
		t.Fatal("expected authentication to fail against a source presenting a certificate that is not trusted")
	}

	// A valid update at the same path is picked up without any configuration change.
	writeCABundle(cert2PEM)
	eventually("authentication after the CA bundle was updated", authenticateOnNewConnection)

	// The update replaced the bundle, the former trust is gone.
	switchSourceCert(&cert1)
	if err := authenticate(); err == nil {
		t.Fatal("expected authentication to fail against a certificate trusted only by the replaced CA bundle")
	}

	if got := configurator.TokenAuthenticator(); got != initialAuthenticator {
		t.Fatal("the authenticator was rebuilt, the CA bundle update must not require an authentication configuration reload")
	}
}

// newServerCertWithCA creates a new CA and a serving certificate for 127.0.0.1
// signed by it. It returns the serving certificate and the PEM encoded CA, which
// is what a trusted CA bundle contains.
func newServerCertWithCA(t *testing.T, name string) (tls.Certificate, string) {
	t.Helper()

	caConfig, err := crypto.MakeSelfSignedCAConfig(name, time.Hour)
	if err != nil {
		t.Fatalf("generating self-signed CA: %v", err)
	}
	ca := &crypto.CA{Config: caConfig, SerialGenerator: &crypto.RandomSerialGenerator{}}

	serverConfig, err := ca.MakeServerCert(sets.New("127.0.0.1"), time.Hour)
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

	caPEM, _, err := caConfig.GetPEMBytes()
	if err != nil {
		t.Fatalf("encoding CA: %v", err)
	}

	return cert, string(caPEM)
}
