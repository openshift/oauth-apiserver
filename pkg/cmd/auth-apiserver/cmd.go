package oauth_apiserver

import (
	"io"

	genericapiserver "k8s.io/apiserver/pkg/server"

	"github.com/openshift/oauth-apiserver/pkg/apiserver"

	"github.com/openshift/library-go/pkg/serviceability"
	"github.com/spf13/cobra"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/klog"

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
	RecommendedOptions *genericapiserveroptions.RecommendedOptions

	Output io.Writer
}

func NewOAuthAPIServerOptions(out io.Writer) *OAuthAPIServerOptions {
	return &OAuthAPIServerOptions{
		RecommendedOptions: genericapiserveroptions.NewRecommendedOptions(
			etcdStoragePrefix,
			serverscheme.Codecs.LegacyCodec(serverscheme.Scheme.PrioritizedVersionsAllGroups()...),
			nil),
		Output: out,
	}
}

func NewOpenShiftAPIServerCommand(name string, out io.Writer) *cobra.Command {
	stopCh := genericapiserver.SetupSignalHandler()
	o := NewOAuthAPIServerOptions(out)

	cmd := &cobra.Command{
		Use:   name,
		Short: "Launch OpenShift OAuth API Server",
		Run: func(c *cobra.Command, args []string) {
			serviceability.StartProfiler()

			if err := o.Run(stopCh); err != nil {
				klog.Fatal(err)
			}
		},
	}

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
