package config

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver"
	apiserverv1 "github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver/v1"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/thirdparty/kubernetes/apiserver/pkg/authentication/cel"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/thirdparty/kubernetes/apiserver/plugin/pkg/authenticator/token/oidc"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/kubernetes/pkg/util/filesystem"
	"sigs.k8s.io/yaml"

	"github.com/spf13/pflag"
)

func NewConfigurator() *Configurator {
	return &Configurator{
		fs: &filesystem.DefaultFs{},
	}
}

type authenticatorWithCancel struct {
	authenticator authenticator.Token
	cancel        context.CancelFunc
}

type Configurator struct {
	configFile              string
	authenticatorWithCancel *authenticatorWithCancel
	fs                      filesystem.Filesystem
}

func (c *Configurator) TokenAuthenticator() authenticator.Token {
	if c.authenticatorWithCancel == nil {
		return nil
	}

	return c.authenticatorWithCancel.authenticator
}

func (c *Configurator) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.configFile, "config", "", "path to the authentication configuration file")
}

func (c *Configurator) Validate() error {
	if c.configFile == "" {
		return errors.New("configuration file must be specified")
	}

	authnConfig, err := AuthenticationConfigurationFromConfigurationFile(c.fs, c.configFile)
	if err != nil {
		return fmt.Errorf("reading authentication configuration from config file: %w", err)
	}

	compiler := authenticationcel.NewDefaultCompiler()
	fieldErrs := validation.ValidateAuthenticationConfiguration(compiler, authnConfig, nil)
	if err := fieldErrs.ToAggregate(); err != nil {
		return fmt.Errorf("validating authentication configuration: %w", err)
	}

	return nil
}

func (c *Configurator) Run(ctx context.Context) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("validating configuration: %w", err)
	}

	go filesystem.WatchUntil(ctx, time.Minute, c.configFile, func() {
		err := c.handleConfigChange(ctx)
		if err != nil {
			fmt.Println("error reloading configuration", err)
		}
	}, func(err error) {
		if err != nil {
			fmt.Println("error watching configuration", err)
		}
	})

	return nil
}

func (c *Configurator) handleConfigChange(ctx context.Context) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("validating configuration: %w", err)
	}

	authnCfg, err := AuthenticationConfigurationFromConfigurationFile(c.fs, c.configFile)
	if err != nil {
		return fmt.Errorf("loading authentication configuration from configuration file: %w", err)
	}

	wrappedCtx, cancel := context.WithCancel(ctx)
	compiler := authenticationcel.NewDefaultCompiler()
	tokenAuthenticator, err := TokenAuthenticatorForAuthenticationConfiguration(wrappedCtx, authnCfg, compiler)
	if err != nil {
		defer cancel()
		return fmt.Errorf("creating token authenticator: %w", err)
	}

	if c.authenticatorWithCancel != nil {
		c.authenticatorWithCancel.cancel()
	}

	c.authenticatorWithCancel = &authenticatorWithCancel{
		authenticator: tokenAuthenticator,
		cancel:        cancel,
	}

	return nil
}

func AuthenticationConfigurationFromConfigurationFile(fs filesystem.Filesystem, cfgPath string) (*apiserver.AuthenticationConfiguration, error) {
	if cfgPath == "" {
		return nil, errors.New("configuration file must be specified")
	}

	configBytes, err := fs.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("reading configuration file: %w", err)
	}

	config := &apiserverv1.AuthenticationConfiguration{}
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling configuration: %w", err)
	}

	out := &apiserver.AuthenticationConfiguration{}

	err = apiserverv1.Convert_v1_AuthenticationConfiguration_To_apiserver_AuthenticationConfiguration(config, out, nil)
	if err != nil {
		return nil, fmt.Errorf("converting external representation to internal representation: %w", err)
	}

	return out, nil
}

func TokenAuthenticatorForAuthenticationConfiguration(ctx context.Context, cfg *apiserver.AuthenticationConfiguration, compiler authenticationcel.Compiler) (authenticator.Token, error) {
	jwtAuthenticators := []authenticator.Token{}

	for _, jwt := range cfg.JWT {
		caContentProvider, err := dynamiccertificates.NewStaticCAContent("oidc-authenticator", []byte(jwt.Issuer.CertificateAuthority))
		if err != nil {
			return nil, fmt.Errorf("creating CA content provider: %w", err)
		}

		tokenAuthenticator, err := oidc.New(ctx, oidc.Options{
			JWTAuthenticator:  jwt,
			CAContentProvider: caContentProvider,
			Compiler:          compiler,
		})
		if err != nil {
			return nil, fmt.Errorf("creating token authenticator: %w", err)
		}

		jwtAuthenticators = append(jwtAuthenticators, tokenAuthenticator)
	}

	return union.New(jwtAuthenticators...), nil
}
