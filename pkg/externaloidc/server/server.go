package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/handlers"
	"github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

const (
	authenticatePath = "/apis/oauth.openshift.io/v1/tokenreviews"
)

func New(at authenticator.Token) *Instance {
	return &Instance{
		tokenAuthenticator: at,
	}
}

type Instance struct {
	securePort         string
	tlsPrivateKeyFile  string
	tlsCertFile        string
	tlsCipherSuites    []string
	tlsMinVersion      string
	tokenAuthenticator authenticator.Token
}

func (i *Instance) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&i.securePort, "secure-port", "6443", "The port on which to serve HTTPS with authentication and authorization. It cannot be switched off with 0.")
	fs.StringVar(&i.tlsPrivateKeyFile, "tls-private-key-file", "tls.key", "The file path of the private key to use for TLS connections")
	fs.StringVar(&i.tlsCertFile, "tls-cert-file", "tls.crt", "The file path to the certificate to use for TLS connections")
	fs.StringVar(&i.tlsMinVersion, "tls-min-version", "", fmt.Sprintf("The minimum TLS version to use for the webhook authenticator server. Must be one of %v. If not specified, it means no opinion and a default value that is subject to change over time will be used.", crypto.ValidTLSVersions()))
	fs.StringArrayVar(&i.tlsCipherSuites, "tls-cipher-suites", []string{}, fmt.Sprintf("The TLS cipher suites to use for serving. Valid ciphers are %v. If not specified, it means no opinion and a default value that is subject to change over time will be used.", crypto.ValidCipherSuites()))
}

func (i *Instance) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle(authenticatePath, handlers.NewAuthenticate(i.tokenAuthenticator))

	cipherSuites := crypto.DefaultCiphers()
	tlsMinVersion := crypto.DefaultTLSVersion()

	if len(i.tlsCipherSuites) > 0 {
		cipherSuites = crypto.CipherSuitesOrDie(i.tlsCipherSuites)
	}

	if len(i.tlsMinVersion) > 0 {
		tlsMinVersion = crypto.TLSVersionOrDie(i.tlsMinVersion)
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", i.securePort),
		Handler: mux,

		// Match default API server values as seen in
		// https://github.com/kubernetes/apiserver/blob/9ee59078fe09d86c6dd041c05907df0cf3fba1ad/pkg/server/secure_serving.go#L165-L173
		ReadHeaderTimeout: 32 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20, // ~1MB

		ReadTimeout: 60 * time.Second, // ~ double the ReadHeaderTimeout

		TLSConfig: &tls.Config{
			CipherSuites: cipherSuites,
			MinVersion:   tlsMinVersion,
		},
	}

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.ListenAndServeTLS(i.tlsCertFile, i.tlsPrivateKeyFile)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown failed: %w", err)
		}

		if err := <-serverErr; err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}

		return nil
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	}
}
