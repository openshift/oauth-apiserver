package internalversion

import (
	"testing"

	"github.com/stretchr/testify/require"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/oauth-apiserver/pkg/printers"
	userapi "github.com/openshift/oauth-apiserver/pkg/user/apis/user"
)

func TestUserPrintersWithDeepCopy(t *testing.T) {
	tests := []struct {
		name    string
		printer func() ([]metav1.TableRow, error)
	}{
		{
			name: "userPrinter",
			printer: func() ([]metav1.TableRow, error) {
				return printUser(&userapi.User{}, printers.GenerateOptions{})
			},
		},
		{
			name: "groupPrinter",
			printer: func() ([]metav1.TableRow, error) {
				return printGroup(&userapi.Group{}, printers.GenerateOptions{})
			},
		},
		{
			name: "identityPrinter",
			printer: func() ([]metav1.TableRow, error) {
				return printIdentity(&userapi.Identity{}, printers.GenerateOptions{})
			},
		},
		{
			name: "identityMapperPrinter",
			printer: func() ([]metav1.TableRow, error) {
				return printUserIdentityMapping(&userapi.UserIdentityMapping{}, printers.GenerateOptions{})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := tt.printer()

			require.NoError(t, err)
			require.Positive(t, len(rows))

			//should not panic
			rows[0].DeepCopy()
		})
	}
}
