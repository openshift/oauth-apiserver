package cmd

import (
	"log"

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
			go func() {
				err := authn.Run(cmd.Context())
				if err != nil {
					log.Fatalf("running authenticator: %v", err)
				}
			}()

			return srv.Serve()
		},
	}

	srv.AddFlags(cmd.Flags())
	authn.AddFlags(cmd.Flags())

	return cmd
}
