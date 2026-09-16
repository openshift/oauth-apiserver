package config

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	apiserverfilesystem "k8s.io/apiserver/pkg/util/filesystem"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/util/filesystem"
	"sigs.k8s.io/yaml"

	"github.com/openshift/library-go/pkg/network"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	authenticationv1alpha1 "github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication/v1alpha1"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication/validation"
	externaloidccel "github.com/openshift/oauth-apiserver/pkg/externaloidc/cel"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/oidc"
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
	proxyCAContent          *dynamiccertificates.DynamicFileCAContent
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

func (c *Configurator) Validate() (*authentication.AuthenticationConfiguration, string, error) {
	if c.configFile == "" {
		return nil, "", errors.New("configuration file must be specified")
	}

	authnConfig, hash, err := AuthenticationConfigurationFromConfigurationFile(c.fs, c.configFile)
	if err != nil {
		return nil, "", fmt.Errorf("reading authentication configuration from config file: %w", err)
	}

	compiler := externaloidccel.NewCompiler()
	fieldErrs := validation.ValidateAuthenticationConfiguration(compiler, authnConfig)
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

	go apiserverfilesystem.WatchUntil(ctx, time.Minute, c.configFile, func() {
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

	proxyCAContent, err := proxyCAContentFromFile(authnCfg.ProxyTrustedCA)
	if err != nil {
		return err
	}

	wrappedCtx, cancel := context.WithCancel(ctx)
	compiler := externaloidccel.NewCompiler()
	tokenAuthenticator, err := tokenAuthenticatorForAuthenticationConfiguration(wrappedCtx, authnCfg, compiler, proxyCAContent)
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
	c.proxyCAContent = proxyCAContent
	c.configHash = cfgHash
	if proxyCAContent != nil {
		go proxyCAContent.Run(wrappedCtx, 1)
	}

	return nil
}

// proxyCAContentFromFile loads the initial component-proxy CA bundle. The
// returned DynamicFileCAContent is shared by every issuer transport created
// for the rendered authentication configuration.
func proxyCAContentFromFile(proxyCAFile string) (*dynamiccertificates.DynamicFileCAContent, error) {
	if proxyCAFile == "" {
		return nil, nil
	}

	proxyCAContent, err := dynamiccertificates.NewDynamicCAContentFromFile("proxy-ca", proxyCAFile)
	if err != nil {
		return nil, fmt.Errorf("loading proxy CA from %q: %w", proxyCAFile, err)
	}
	return proxyCAContent, nil
}

func AuthenticationConfigurationFromConfigurationFile(fs filesystem.Filesystem, cfgPath string) (*authentication.AuthenticationConfiguration, string, error) {
	if cfgPath == "" {
		return nil, "", errors.New("configuration file must be specified")
	}

	configBytes, err := fs.ReadFile(cfgPath)
	if err != nil {
		return nil, "", fmt.Errorf("reading configuration file: %w", err)
	}

	configHash := sha256.Sum256(configBytes)

	config := &authenticationv1alpha1.AuthenticationConfiguration{}
	err = yaml.UnmarshalStrict(configBytes, config)
	if err != nil {
		return nil, "", fmt.Errorf("unmarshalling configuration: %w", err)
	}

	out := &authentication.AuthenticationConfiguration{}

	err = authenticationv1alpha1.Convert_v1alpha1_AuthenticationConfiguration_To_authentication_AuthenticationConfiguration(config, out, nil)
	if err != nil {
		return nil, "", fmt.Errorf("converting external representation to internal representation: %w", err)
	}

	return out, string(configHash[:]), nil
}

func tokenAuthenticatorForAuthenticationConfiguration(ctx context.Context, cfg *authentication.AuthenticationConfiguration, compiler oidc.Compiler, proxyCAContent *dynamiccertificates.DynamicFileCAContent) (authenticator.Token, error) {
	jwtAuthenticators := make([]authenticator.Token, 0, len(cfg.JWT))

	for _, jwt := range cfg.JWT {
		var opts []network.TransportOption
		if len(jwt.Issuer.CertificateAuthority) > 0 {
			opts = append(opts, network.WithCAData("issuer CA", []byte(jwt.Issuer.CertificateAuthority)))
		}
		if proxyCAContent != nil {
			opts = append(opts, network.WithCAContentProvider(proxyCAContent))
		}

		rt, err := network.NewRoundTripper(opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP transport for token authenticator: %w", err)
		}

		tokenAuthenticator, err := oidc.New(ctx, oidc.Options{
			JWTAuthenticator: jwt,
			Client:           &http.Client{Transport: rt},
			Compiler:         compiler,
		})
		if err != nil {
			return nil, fmt.Errorf("creating token authenticator: %w", err)
		}

		jwtAuthenticators = append(jwtAuthenticators, tokenAuthenticator)
	}

	return union.New(jwtAuthenticators...), nil
}
