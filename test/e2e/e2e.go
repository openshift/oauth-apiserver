package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	g "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"

	kauthenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	oauthv1 "github.com/openshift/api/oauth/v1"
	userv1 "github.com/openshift/api/user/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
)

var _ = g.Describe("[sig-auth] OAuth", func() {
	g.It("should successfully review valid and invalid tokens [Component][Serial][apigroup:oauth.openshift.io]", func(ctx context.Context) {
		testTokenReviews(ctx, g.GinkgoTB())
	})
})

// tokenName computes the OAuthAccessToken resource name from a raw token secret.
// The server hashes the secret part (after "sha256~") and stores it as sha256~<base64(hash)>.
func tokenName(rawSecret string) string {
	h := sha256.Sum256([]byte(rawSecret))
	return "sha256~" + base64.RawURLEncoding.EncodeToString(h[:])
}

func testTokenReviews(ctx context.Context, t testing.TB) {
	adminConfig := NewClientConfigForTest(t)
	trashBin := NewResourceTrashbin(t, adminConfig)
	defer trashBin.Empty(t)

	userClient, err := userclient.NewForConfig(adminConfig)
	require.NoError(t, err)
	oauthClient, err := oauthv1client.NewForConfig(adminConfig)
	require.NoError(t, err)

	user, err := userClient.UserV1().Users().Create(ctx, &userv1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "tokenreviews-e2e-testuser"},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	trashBin.AddResource(userv1.GroupVersion.WithResource("users"), user.GetObjectMeta())

	_, err = oauthClient.OAuthClients().Create(ctx, &oauthv1.OAuthClient{
		ObjectMeta:   metav1.ObjectMeta{Name: "tokenreviews-e2e-client"},
		GrantMethod:  oauthv1.GrantHandlerAuto,
		RedirectURIs: []string{"https://localhost/callback"},
		ScopeRestrictions: []oauthv1.ScopeRestriction{
			{ExactValues: []string{"user:info"}},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	trashBin.AddResource(oauthv1.GroupVersion.WithResource("oauthclients"), &metav1.ObjectMeta{Name: "tokenreviews-e2e-client"})

	// rawSecret is the value that will be sent in the TokenReview spec.
	// The resource name is derived by hashing it.
	const rawSecret = "tokenreviews-e2e-secret-value-for-testing"
	accessToken, err := oauthClient.OAuthAccessTokens().Create(ctx, &oauthv1.OAuthAccessToken{
		ObjectMeta:  metav1.ObjectMeta{Name: tokenName(rawSecret)},
		ClientName:  "tokenreviews-e2e-client",
		Scopes:      []string{"user:info"},
		RedirectURI: "https://localhost/callback",
		ExpiresIn:   3600,
		UserName:    user.Name,
		UserUID:     string(user.UID),
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	trashBin.AddResource(oauthv1.GroupVersion.WithResource("oauthaccesstokens"), accessToken.GetObjectMeta())

	// review a token that does not exist — expect not authenticated
	result := &kauthenticationv1.TokenReview{}
	err = oauthClient.RESTClient().Post().
		Resource("tokenreviews").
		Body(&kauthenticationv1.TokenReview{
			Spec: kauthenticationv1.TokenReviewSpec{Token: "sha256~doesnotexist"},
		}).
		Do(ctx).Into(result)
	require.NoError(t, err)
	require.False(t, result.Status.Authenticated)

	// review the valid token — expect authenticated
	result = &kauthenticationv1.TokenReview{}
	err = oauthClient.RESTClient().Post().
		Resource("tokenreviews").
		Body(&kauthenticationv1.TokenReview{
			Spec: kauthenticationv1.TokenReviewSpec{Token: "sha256~" + rawSecret},
		}).
		Do(ctx).Into(result)
	require.NoError(t, err)
	require.True(t, result.Status.Authenticated)
}
