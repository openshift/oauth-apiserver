package internalversion

import (
	"testing"

	oauthapi "github.com/openshift/oauth-apiserver/pkg/oauth/apis/oauth"
	"github.com/openshift/oauth-apiserver/pkg/printers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPrintOAuthWithDeepCopy(t *testing.T) {
	tests := []struct {
		name    string
		printer func() ([]metav1.TableRow, error)
	}{
		{
			name: "OAuthClient",
			printer: func() ([]metav1.TableRow, error) {
				return printOAuthClient(&oauthapi.OAuthClient{}, printers.GenerateOptions{})
			},
		},
		{
			name: "OAuthClientAuthorization",
			printer: func() ([]metav1.TableRow, error) {
				return printOAuthClientAuthorization(&oauthapi.OAuthClientAuthorization{}, printers.GenerateOptions{})
			},
		},
		{
			name: "OAuthAccessToken",
			printer: func() ([]metav1.TableRow, error) {
				return printOAuthAccessToken(&oauthapi.OAuthAccessToken{}, printers.GenerateOptions{})
			},
		},
		{
			name: "UserOAuthAccessToken",
			printer: func() ([]metav1.TableRow, error) {
				return printUserOAuthAccessToken(&oauthapi.UserOAuthAccessToken{}, printers.GenerateOptions{})
			},
		},
		{
			name: "OAuthAuthorizeToken",
			printer: func() ([]metav1.TableRow, error) {
				return printOAuthAuthorizeToken(&oauthapi.OAuthAuthorizeToken{}, printers.GenerateOptions{})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows, err := test.printer()
			if err != nil {
				t.Fatalf("expected no error, but got: %#v", err)
			}
			if len(rows) <= 0 {
				t.Fatalf("expected to have at least one TableRow, but got: %d", len(rows))
			}

			// should not panic
			rows[0].DeepCopy()
		})
	}
}
