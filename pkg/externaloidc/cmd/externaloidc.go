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

			return srv.Serve()
		},
	}

	srv.AddFlags(cmd.Flags())
	authn.AddFlags(cmd.Flags())

	return cmd
}
