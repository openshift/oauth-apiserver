package main

import (
	"os"
	"runtime"

	"github.com/spf13/cobra"

	"k8s.io/component-base/cli"

	"github.com/openshift/library-go/pkg/serviceability"

	oauth_apiserver "github.com/openshift/oauth-apiserver/pkg/cmd/oauth-apiserver"
	"github.com/openshift/oauth-apiserver/pkg/version"
)

func main() {
	defer serviceability.BehaviorOnPanic(os.Getenv("OPENSHIFT_ON_PANIC"), version.Get())()
	defer serviceability.Profile(os.Getenv("OPENSHIFT_PROFILE")).Stop()

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	command := NewOAuthAPIServerCommand()
	code := cli.Run(command)
	os.Exit(code)
}

func NewOAuthAPIServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oauth-apiserver",
		Short: "Command for the OpenShift OAuth API Server",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(1)
		},
	}
	start := oauth_apiserver.NewOAuthAPIServerCommand("start", os.Stdout)
	cmd.AddCommand(start)

	return cmd
}
