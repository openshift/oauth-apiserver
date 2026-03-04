package server

import (
	"fmt"
	"net/http"

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
	fs.StringVar(&i.tlsPrivateKeyFile, "tls-cert-file", "tls.crt", "The file path to the certificate to use for TLS connections")
}

// TODO: add metrics handler
// TODO: Does this need to build it's own http.Server instance that can watch serving certificate/key files?
func (i *Instance) Serve() error {
	mux := http.NewServeMux()
	mux.Handle(authenticatePath, handlers.NewAuthenticate(i.tokenAuthenticator))

	return http.ListenAndServeTLS(fmt.Sprintf("0.0.0.0:%s", i.securePort), i.tlsCertFile, i.tlsPrivateKeyFile, mux)
}
