package oauth_apiserver

import (
	"io"

	"github.com/spf13/cobra"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"

	"github.com/openshift/library-go/pkg/serviceability"
	"github.com/openshift/oauth-apiserver/pkg/apiserver"

	// to force compiling
	_ "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver"
	"github.com/openshift/oauth-apiserver/pkg/serverscheme"
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
	return &OAuthAPIServerOptions{
		GenericServerRunOptions: genericapiserveroptions.NewServerRunOptions(),
		RecommendedOptions: genericapiserveroptions.NewRecommendedOptions(
			etcdStoragePrefix,
			serverscheme.Codecs.LegacyCodec(serverscheme.Scheme.PrioritizedVersionsAllGroups()...),
			nil),
		Output: out,
	}
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
			if err := o.Run(stopCh); err != nil {
				return err
			}

			return nil
		},
	}

	flags := cmd.Flags()
	o.GenericServerRunOptions.AddUniversalFlags(flags)
	o.RecommendedOptions.AddFlags(flags)

	return cmd
}

// Run takes the options, starts the API server and waits until stopCh is closed or initial listening fails.
func (o *OAuthAPIServerOptions) Run(stopCh <-chan struct{}) error {
	serverConfig := apiserver.NewConfig()
	if err := o.RecommendedOptions.ApplyTo(serverConfig.GenericConfig); err != nil {
		return err
	}
	server, err := serverConfig.Complete().New(genericapiserver.NewEmptyDelegate())
	if err != nil {
		return err
	}
	return server.GenericAPIServer.PrepareRun().Run(stopCh)
}
