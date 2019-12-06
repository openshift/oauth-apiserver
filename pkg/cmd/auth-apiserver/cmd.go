package oauth_apiserver

import (
	"io"

	"github.com/openshift/library-go/pkg/serviceability"
	"github.com/spf13/cobra"
	"k8s.io/klog"

	// to force compiling
	_ "github.com/openshift/oauth-apiserver/pkg/oauth/apiserver"
	_ "github.com/openshift/oauth-apiserver/pkg/user/apiserver"
)

type OAuthAPIServerOptions struct {
	Output io.Writer
}

func NewOpenShiftAPIServerCommand(name string, out, errout io.Writer, stopCh <-chan struct{}) *cobra.Command {
	options := &OAuthAPIServerOptions{Output: out}

	cmd := &cobra.Command{
		Use:   name,
		Short: "Launch OpenShift OAuth API Server",
		Run: func(c *cobra.Command, args []string) {
			serviceability.StartProfiler()

			if err := options.Run(stopCh); err != nil {
				klog.Fatal(err)
			}
		},
	}

	return cmd
}

// Run takes the options, starts the API server and waits until stopCh is closed or initial listening fails.
func (o *OAuthAPIServerOptions) Run(stopCh <-chan struct{}) error {
	return nil
}
