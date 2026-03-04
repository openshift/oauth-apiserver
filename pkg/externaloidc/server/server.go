package server

import (
	"fmt"
	"net/http"
	"time"

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
	tokenAuthenticator authenticator.Token
}

func (i *Instance) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&i.securePort, "secure-port", "6443", "The port on which to serve HTTPS with authentication and authorization. It cannot be switched off with 0.")
	fs.StringVar(&i.tlsPrivateKeyFile, "tls-private-key-file", "tls.key", "The file path of the private key to use for TLS connections")
	fs.StringVar(&i.tlsCertFile, "tls-cert-file", "tls.crt", "The file path to the certificate to use for TLS connections")
}

// TODO: add metrics handler
func (i *Instance) Serve() error {
	mux := http.NewServeMux()
	mux.Handle(authenticatePath, handlers.NewAuthenticate(i.tokenAuthenticator))

	srv := &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%s", i.securePort),
		Handler: mux,

		// Match default API server values as seen in
		// https://github.com/kubernetes/apiserver/blob/9ee59078fe09d86c6dd041c05907df0cf3fba1ad/pkg/server/secure_serving.go#L165-L173
		ReadHeaderTimeout: 32 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20, // ~1MB

		ReadTimeout: 5 * time.Second,
	}

	return srv.ListenAndServeTLS(i.tlsCertFile, i.tlsPrivateKeyFile)
}
