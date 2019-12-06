package main

import (
	goflag "flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"time"

	"github.com/openshift/library-go/pkg/serviceability"
	oauth_apiserver "github.com/openshift/oauth-apiserver/pkg/cmd/auth-apiserver"
	"github.com/openshift/oauth-apiserver/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	genericapiserver "k8s.io/apiserver/pkg/server"
	utilflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/logs"
)

func main() {
	stopCh := genericapiserver.SetupSignalHandler()

	rand.Seed(time.Now().UTC().UnixNano())

	pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	logs.InitLogs()
	defer logs.FlushLogs()
	defer serviceability.BehaviorOnPanic(os.Getenv("OPENSHIFT_ON_PANIC"), version.Get())()
	defer serviceability.Profile(os.Getenv("OPENSHIFT_PROFILE")).Stop()

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	command := NewOpenshiftApiServerCommand(stopCh)
	if err := command.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func NewOpenshiftApiServerCommand(stopCh <-chan struct{}) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oauth-apiserver",
		Short: "Command for the OpenShift OAuth API Server",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
			os.Exit(1)
		},
	}
	start := oauth_apiserver.NewOpenShiftAPIServerCommand("start", os.Stdout, os.Stderr, stopCh)
	cmd.AddCommand(start)

	return cmd
}
