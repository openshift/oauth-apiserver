package oauth_apiserver

import (
	"fmt"
	"io"
	"net"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/server/options/encryptionconfig"
	apiserverstorage "k8s.io/apiserver/pkg/server/storage"

	"github.com/openshift/library-go/pkg/serviceability"

	"github.com/openshift/oauth-apiserver/pkg/apiserver"
	"github.com/openshift/oauth-apiserver/pkg/cmd/oauth-apiserver/openapiconfig"
	"github.com/openshift/oauth-apiserver/pkg/serverscheme"

	// register api groups
	_ "github.com/openshift/oauth-apiserver/pkg/api/install"

	// to force compiling
	_ "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver"
	_ "github.com/openshift/oauth-apiserver/pkg/user/apiserver"
)

const (
	// etcdStoragePrefix matches the historical value used by openshift so the resource migrate cleanly.
	etcdStoragePrefix = "openshift.io"
)

type OAuthAPIServerOptions struct {
	GenericServerRunOptions *genericapiserveroptions.ServerRunOptions
	RecommendedOptions      *genericapiserveroptions.RecommendedOptions

	Output io.Writer
}

func NewOAuthAPIServerOptions(out io.Writer) *OAuthAPIServerOptions {
	o := &OAuthAPIServerOptions{
		GenericServerRunOptions: genericapiserveroptions.NewServerRunOptions(),
		RecommendedOptions: genericapiserveroptions.NewRecommendedOptions(
			etcdStoragePrefix,
			serverscheme.Codecs.LegacyCodec(serverscheme.Scheme.PrioritizedVersionsAllGroups()...),
		),
		Output: out,
	}
	o.RecommendedOptions.Etcd.StorageConfig.Paging = true
	return o
}

func (o *OAuthAPIServerOptions) AddFlags(fs *pflag.FlagSet) {
	o.GenericServerRunOptions.AddUniversalFlags(fs)
	o.RecommendedOptions.AddFlags(fs)
}

func (o OAuthAPIServerOptions) Validate(args []string) error {
	errors := []error{}
	errors = append(errors, o.GenericServerRunOptions.Validate()...)
	errors = append(errors, o.RecommendedOptions.Validate()...)
	return utilerrors.NewAggregate(errors)
}

func (o *OAuthAPIServerOptions) Complete() error {
	return nil
}

func NewOAuthAPIServerCommand(name string, out io.Writer) *cobra.Command {
	stopCh := genericapiserver.SetupSignalHandler()
	o := NewOAuthAPIServerOptions(out)

	cmd := &cobra.Command{
		Use:   name,
		Short: "Launch OpenShift OAuth API Server",
		RunE: func(c *cobra.Command, args []string) error {
			serviceability.StartProfiler()

			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			return RunOAuthAPIServer(o, stopCh)
		},
	}

	flags := cmd.Flags()
	o.AddFlags(flags)

	return cmd
}

func RunOAuthAPIServer(serverOptions *OAuthAPIServerOptions, stopCh <-chan struct{}) error {
	oauthAPIServerConfig, err := serverOptions.NewOAuthAPIServerConfig()
	if err != nil {
		return err
	}
	completedOAuthAPIServerConfig := oauthAPIServerConfig.Complete()

	oauthAPIServer, err := completedOAuthAPIServerConfig.New(genericapiserver.NewEmptyDelegate())
	if err != nil {
		return err
	}
	preparedOAuthServer := oauthAPIServer.GenericAPIServer.PrepareRun()
	if err := completedOAuthAPIServerConfig.WithOpenAPIAggregationController(preparedOAuthServer.GenericAPIServer); err != nil {
		return err
	}
	return preparedOAuthServer.Run(stopCh)
}

func (o *OAuthAPIServerOptions) NewOAuthAPIServerConfig() (*apiserver.Config, error) {
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	serverConfig := apiserver.NewConfig()
	serverConfig.GenericConfig.OpenAPIConfig = openapiconfig.DefaultOpenAPIConfig()

	if err := o.RecommendedOptions.ApplyTo(serverConfig.GenericConfig); err != nil {
		return nil, err
	}

	// the following section overwrites RESTOptionsGetter
	// note we don't call ApplyWithStorageFactoryTo explicitly to prevent double registration of storage related health checks
	o.RecommendedOptions.Etcd.DefaultStorageMediaType = "application/vnd.kubernetes.protobuf"
	storageFactory := apiserverstorage.NewDefaultStorageFactory(
		o.RecommendedOptions.Etcd.StorageConfig,
		o.RecommendedOptions.Etcd.DefaultStorageMediaType,
		serverscheme.Codecs,
		apiserverstorage.NewDefaultResourceEncodingConfig(serverscheme.Scheme),
		&apiserverstorage.ResourceConfig{},
		specialDefaultResourcePrefixes,
	)
	if len(o.RecommendedOptions.Etcd.EncryptionProviderConfigFilepath) != 0 {
		transformerOverrides, err := encryptionconfig.GetTransformerOverrides(o.RecommendedOptions.Etcd.EncryptionProviderConfigFilepath)
		if err != nil {
			return nil, err
		}
		for groupResource, transformer := range transformerOverrides {
			storageFactory.SetTransformer(groupResource, transformer)
		}
	}
	serverConfig.GenericConfig.RESTOptionsGetter = &genericapiserveroptions.StorageFactoryRestOptionsFactory{Options: *o.RecommendedOptions.Etcd, StorageFactory: storageFactory}

	return serverConfig, nil
}

// specialDefaultResourcePrefixes are a custom storage prefixes (we must be backward compatible with OpenShift API)
var specialDefaultResourcePrefixes = map[schema.GroupResource]string{
	{Resource: "oauthaccesstokens", Group: "oauth.openshift.io"}:    "oauth/accesstokens",
	{Resource: "oauthauthorizetokens", Group: "oauth.openshift.io"}: "oauth/authorizetokens",

	{Resource: "oauthclients", Group: "oauth.openshift.io"}:              "oauth/clients",
	{Resource: "oauthclientauthorizations", Group: "oauth.openshift.io"}: "oauth/clientauthorizations",

	{Resource: "identities", Group: "user.openshift.io"}: "useridentities",
}
