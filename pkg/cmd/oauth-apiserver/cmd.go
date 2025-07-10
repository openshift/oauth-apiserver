package oauth_apiserver

import (
	goflag "flag"
	"fmt"
	"io"
	"net"

	apifeatures "github.com/openshift/api/features"
	"github.com/openshift/library-go/pkg/features"
	"github.com/openshift/library-go/pkg/serviceability"
	"github.com/openshift/oauth-apiserver/pkg/apiserver"
	"github.com/openshift/oauth-apiserver/pkg/authorization/hardcodedauthorizer"
	"github.com/openshift/oauth-apiserver/pkg/cmd/oauth-apiserver/openapiconfig"
	"github.com/openshift/oauth-apiserver/pkg/serverscheme"
	tokenvalidationoptions "github.com/openshift/oauth-apiserver/pkg/tokenvalidation/options"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authorization/union"
	"k8s.io/apiserver/pkg/endpoints/discovery/aggregated"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"
	apiserverstorage "k8s.io/apiserver/pkg/server/storage"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/featuregate"

	// register api groups
	_ "github.com/openshift/oauth-apiserver/pkg/api/install"
)

const (
	// etcdStoragePrefix matches the historical value used by openshift so the resource migrate cleanly.
	etcdStoragePrefix = "openshift.io"
)

type OAuthAPIServerOptions struct {
	GenericServerRunOptions *genericapiserveroptions.ServerRunOptions
	RecommendedOptions      *genericapiserveroptions.RecommendedOptions
	TokenValidationOptions  *tokenvalidationoptions.TokenValidationOptions

	// TODO: The operator needs to be able to filter the feature gate names that are supported
	// by this component and pass only those.
	FeatureGateOptions *features.FeatureGateOptions

	Output io.Writer
}

func NewOAuthAPIServerOptions(out io.Writer, featureGate featuregate.MutableFeatureGate) *OAuthAPIServerOptions {
	o := &OAuthAPIServerOptions{
		GenericServerRunOptions: genericapiserveroptions.NewServerRunOptions(),
		RecommendedOptions: genericapiserveroptions.NewRecommendedOptions(
			etcdStoragePrefix,
			serverscheme.Codecs.LegacyCodec(serverscheme.Scheme.PrioritizedVersionsAllGroups()...),
		),
		TokenValidationOptions: tokenvalidationoptions.NewTokenValidationOptions(),
		FeatureGateOptions:     features.NewFeatureGateOptionsOrDie(featureGate, apifeatures.SelfManaged),
		Output:                 out,
	}
	return o
}

func (o *OAuthAPIServerOptions) AddFlags(fs *pflag.FlagSet) {
	// FeatureGateOptions wants a stdlib *flag.FlagSet, not a *pflag.FlagSet.
	gfs := goflag.NewFlagSet("", goflag.ContinueOnError)
	o.FeatureGateOptions.AddFlagsToGoFlagSet(gfs)
	fs.AddGoFlagSet(gfs)

	// Taking advantage of the contract of (*pflag.FlagSet).AddFlagSet, which skips flags that
	// are already registered in the destination set, to make sure our filtered --feature-gates
	// flag is the one that takes effect.
	tmp := pflag.NewFlagSet("", pflag.ContinueOnError)
	o.GenericServerRunOptions.AddUniversalFlags(tmp)
	fs.AddFlagSet(tmp)

	o.RecommendedOptions.AddFlags(fs)
	o.TokenValidationOptions.AddFlags(fs)
}

func (o OAuthAPIServerOptions) Validate(args []string) error {
	errors := []error{}
	errors = append(errors, o.GenericServerRunOptions.Validate()...)
	errors = append(errors, o.RecommendedOptions.Validate()...)
	errors = append(errors, o.TokenValidationOptions.Validate()...)
	return utilerrors.NewAggregate(errors)
}

func (o *OAuthAPIServerOptions) Complete(featureGates featuregate.MutableFeatureGate) error {
	_, err := o.FeatureGateOptions.ApplyTo(featureGates)
	return err
}

func NewOAuthAPIServerCommand(name string, out io.Writer) *cobra.Command {
	stopCh := genericapiserver.SetupSignalHandler()
	o := NewOAuthAPIServerOptions(out, utilfeature.DefaultMutableFeatureGate)

	cmd := &cobra.Command{
		Use:   name,
		Short: "Launch OpenShift OAuth API Server",
		RunE: func(c *cobra.Command, args []string) error {
			serviceability.StartProfiler()

			if err := o.Complete(utilfeature.DefaultMutableFeatureGate); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			cliflag.PrintFlags(c.Flags())
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

	// this **must** be done after PrepareRun() as it sets up the openapi endpoints
	if err := completedOAuthAPIServerConfig.WithOpenAPIAggregationController(preparedOAuthServer.GenericAPIServer, completedOAuthAPIServerConfig.GenericConfig.OpenAPIConfig); err != nil {
		return err
	}
	if err := completedOAuthAPIServerConfig.WithOpenAPIV3AggregationController(preparedOAuthServer.GenericAPIServer); err != nil {
		return err
	}
	return preparedOAuthServer.Run(stopCh)
}

func (o *OAuthAPIServerOptions) NewOAuthAPIServerConfig() (*apiserver.Config, error) {
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	serverConfig := apiserver.NewConfig()

	if err := o.GenericServerRunOptions.ApplyTo(&serverConfig.GenericConfig.Config); err != nil {
		return nil, err
	}

	serverConfig.GenericConfig.OpenAPIConfig = openapiconfig.DefaultOpenAPIConfig()
	serverConfig.GenericConfig.OpenAPIV3Config = openapiconfig.DefaultOpenAPIV3Config()
	serverConfig.GenericConfig.AggregatedDiscoveryGroupManager = aggregated.NewResourceManager("apis")
	// do not to install the default OpenAPI handler in the aggregated apiserver
	// as it will be handled by openapi aggregator (both v2 and v3)
	// non-root apiservers must set this value to false
	serverConfig.GenericConfig.Config.SkipOpenAPIInstallation = true

	if err := o.RecommendedOptions.ApplyTo(serverConfig.GenericConfig); err != nil {
		return nil, err
	}

	// the oauth-apiserver provides an autentication webhook.  To avoid cyclical authorization checks, we will hardcode
	// the expected user to a tokenreview permission.  Since this rule could never logically be removed in an openshift
	// cluster, this is acceptable.
	serverConfig.GenericConfig.Authorization.Authorizer = union.New(
		hardcodedauthorizer.NewHardCodedTokenReviewAuthorizer(),
		serverConfig.GenericConfig.Authorization.Authorizer,
	)

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

	// ApplyTo was called already which set up etcd health endpoints
	o.RecommendedOptions.Etcd.SkipHealthEndpoints = true
	err := o.RecommendedOptions.Etcd.ApplyWithStorageFactoryTo(storageFactory, &serverConfig.GenericConfig.Config)
	if err != nil {
		return nil, err
	}

	serverConfig.ExtraConfig.AccessTokenInactivityTimeout = o.TokenValidationOptions.AccessTokenInactivityTimeout
	serverConfig.ExtraConfig.APIAudiences = o.TokenValidationOptions.APIAudiences

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
