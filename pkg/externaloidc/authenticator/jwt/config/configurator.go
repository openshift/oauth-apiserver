package config

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"k8s.io/apiserver/pkg/apis/apiserver"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/klog/v2"

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
		mu: sync.Mutex{},
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
	configHash              string
	mu                      sync.Mutex
}

func (c *Configurator) TokenAuthenticator() authenticator.Token {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.authenticatorWithCancel == nil {
		return nil
	}

	return c.authenticatorWithCancel.authenticator
}

func (c *Configurator) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.configFile, "config", "", "path to the authentication configuration file")
}

func (c *Configurator) Validate() (*apiserver.AuthenticationConfiguration, string, error) {
	if c.configFile == "" {
		return nil, "", errors.New("configuration file must be specified")
	}

	authnConfig, hash, err := AuthenticationConfigurationFromConfigurationFile(c.fs, c.configFile)
	if err != nil {
		return nil, "", fmt.Errorf("reading authentication configuration from config file: %w", err)
	}

	compiler := authenticationcel.NewDefaultCompiler()
	fieldErrs := validation.ValidateAuthenticationConfiguration(compiler, authnConfig, nil)
	if err := fieldErrs.ToAggregate(); err != nil {
		return nil, "", fmt.Errorf("validating authentication configuration: %w", err)
	}

	return authnConfig, hash, nil
}

func (c *Configurator) Run(ctx context.Context) error {
	// Attempt an initial loading of the configuration so we can fail out early
	// if the configuration couldn't be properly loaded the first time.
	// filesystem.WatchUntil will immediately call this again, but we
	// hash the contents of the config file to prevent unnecessary churn
	// in the underlying authenticator.
	if err := c.handleConfigChange(ctx); err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}

	go filesystem.WatchUntil(ctx, time.Minute, c.configFile, func() {
		err := c.handleConfigChange(ctx)
		if err != nil {
			klog.Errorf("reloading configuration: %v", err)
		}
	}, func(err error) {
		if err != nil {
			klog.Errorf("watching configuration: %v", err)
		}
	})

	return nil
}

func (c *Configurator) handleConfigChange(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	authnCfg, cfgHash, err := c.Validate()
	if err != nil {
		return fmt.Errorf("validating configuration: %w", err)
	}

	// configuration file contents are the same as they were before
	// so no need for any change to the underlying authenticator.
	if c.configHash != "" && cfgHash == c.configHash {
		return nil
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
	c.configHash = cfgHash

	return nil
}

func AuthenticationConfigurationFromConfigurationFile(fs filesystem.Filesystem, cfgPath string) (*apiserver.AuthenticationConfiguration, string, error) {
	if cfgPath == "" {
		return nil, "", errors.New("configuration file must be specified")
	}

	configBytes, err := fs.ReadFile(cfgPath)
	if err != nil {
		return nil, "", fmt.Errorf("reading configuration file: %w", err)
	}

	configHash := sha256.Sum256(configBytes)

	config := &apiserverv1.AuthenticationConfiguration{}
	err = yaml.UnmarshalStrict(configBytes, config)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshalling configuration: %w", err)
	}

	out := &apiserver.AuthenticationConfiguration{}

	err = apiserverv1.Convert_v1_AuthenticationConfiguration_To_apiserver_AuthenticationConfiguration(config, out, nil)
	if err != nil {
		return nil, "", fmt.Errorf("converting external representation to internal representation: %w", err)
	}

	return out, string(configHash[:]), nil
}

func TokenAuthenticatorForAuthenticationConfiguration(ctx context.Context, cfg *apiserver.AuthenticationConfiguration, compiler authenticationcel.Compiler) (authenticator.Token, error) {
	jwtAuthenticators := []authenticator.Token{}

	for _, jwt := range cfg.JWT {
		var caContentProvider oidc.CAContentProvider
		var err error
		if len(jwt.Issuer.CertificateAuthority) > 0 {
			caContentProvider, err = dynamiccertificates.NewStaticCAContent("oidc-authenticator", []byte(jwt.Issuer.CertificateAuthority))
			if err != nil {
				return nil, fmt.Errorf("creating CA content provider: %w", err)
			}
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
