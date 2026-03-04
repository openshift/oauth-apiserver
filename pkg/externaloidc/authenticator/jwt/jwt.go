package jwt

import (
	"context"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/authenticator/jwt/config"
	"github.com/spf13/pflag"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

type Configurator interface {
	Validate() error
	TokenAuthenticator() authenticator.Token
	Run(context.Context) error
	AddFlags(*pflag.FlagSet)
}

func New() *JWT {
	return &JWT{
		configurator: config.NewConfigurator(),
	}
}

type JWT struct {
	configurator Configurator
}

func (j *JWT) AddFlags(fs *pflag.FlagSet) {
	j.configurator.AddFlags(fs)
}

func (j *JWT) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return j.configurator.TokenAuthenticator().AuthenticateToken(ctx, token)
}

func (j *JWT) Run(ctx context.Context) error {
	return j.configurator.Run(ctx)
}
