package cmd

import (
	"fmt"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/authenticator/jwt"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/server"
	"github.com/spf13/cobra"
)

func NewExternalOIDCCommand() *cobra.Command {
	authn := jwt.New()
	srv := server.New(authn)

	cmd := &cobra.Command{
		Use: "external-oidc",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := authn.Run(cmd.Context())
			if err != nil {
				return fmt.Errorf("running authenticator: %w", err)
			}

			return srv.Serve(cmd.Context())
		},
		// For compatibility with existing flag injection behavior done by
		// the cluster-authentication-operator without having to support
		// every possible flag in the initial implementation, ignore
		// flag parsing errors related to unknown flags being provided.
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
	}

	srv.AddFlags(cmd.Flags())
	authn.AddFlags(cmd.Flags())

	return cmd
}
