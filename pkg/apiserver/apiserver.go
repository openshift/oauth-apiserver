package apiserver

import (
	"github.com/openshift/oauth-apiserver/pkg/serverscheme"
	genericapiserver "k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"

	openshiftcontrolplanev1 "github.com/openshift/api/openshiftcontrolplane/v1"
	oauthapiserver "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver"
	userapiserver "github.com/openshift/oauth-apiserver/pkg/user/apiserver"
	"github.com/openshift/oauth-apiserver/pkg/version"
)

type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
}

type OAuthAPIServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ClientConfig  *restclient.Config
}

// CompletedConfig embeds a private pointer that cannot be instantiated outside of this package.
type CompletedConfig struct {
	*completedConfig
}

func NewConfig() *Config {
	return &Config{
		GenericConfig: genericapiserver.NewRecommendedConfig(serverscheme.Codecs),
	}
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (cfg *Config) Complete() CompletedConfig {
	c := completedConfig{
		GenericConfig: cfg.GenericConfig.Complete(),
		ClientConfig:  cfg.GenericConfig.ClientConfig,
	}

	v := version.Get()
	c.GenericConfig.Version = &v

	return CompletedConfig{&c}
}

// New returns a new instance of WardleServer from the given config.
func (c completedConfig) New(delegationTarget genericapiserver.DelegationTarget) (*OAuthAPIServer, error) {
	delegateAPIServer := delegationTarget
	var err error

	delegateAPIServer, err = c.withOAuthAPIServer(delegateAPIServer)
	if err != nil {
		return nil, err
	}
	delegateAPIServer, err = c.withUserAPIServer(delegateAPIServer)
	if err != nil {
		return nil, err
	}

	genericServer, err := c.GenericConfig.New("oauth-apiserver", delegateAPIServer)
	if err != nil {
		return nil, err
	}

	s := &OAuthAPIServer{
		GenericAPIServer: genericServer,
	}

	return s, nil
}

func (c *completedConfig) withOAuthAPIServer(delegateAPIServer genericapiserver.DelegationTarget) (genericapiserver.DelegationTarget, error) {
	cfg := &oauthapiserver.OAuthAPIServerConfig{
		GenericConfig: &genericapiserver.RecommendedConfig{Config: *c.GenericConfig.Config, SharedInformerFactory: c.GenericConfig.SharedInformerFactory, ClientConfig: c.ClientConfig},
		ExtraConfig: oauthapiserver.ExtraConfig{
			// no one is allowed to set this today
			ServiceAccountMethod: string(openshiftcontrolplanev1.GrantHandlerPrompt),
		},
	}
	config := cfg.Complete()
	server, err := config.New(delegateAPIServer)
	if err != nil {
		return nil, err
	}

	return server.GenericAPIServer, nil
}

func (c *completedConfig) withUserAPIServer(delegateAPIServer genericapiserver.DelegationTarget) (genericapiserver.DelegationTarget, error) {
	cfg := &userapiserver.UserConfig{
		GenericConfig: &genericapiserver.RecommendedConfig{Config: *c.GenericConfig.Config, SharedInformerFactory: c.GenericConfig.SharedInformerFactory, ClientConfig: c.ClientConfig},
		ExtraConfig:   userapiserver.ExtraConfig{},
	}
	config := cfg.Complete()
	server, err := config.New(delegateAPIServer)
	if err != nil {
		return nil, err
	}

	return server.GenericAPIServer, nil
}
