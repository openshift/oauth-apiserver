package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	kauthenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apiserver/pkg/storage/names"

	oauthv1 "github.com/openshift/api/oauth/v1"
	userv1 "github.com/openshift/api/user/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
)

// tokenName computes the OAuthAccessToken resource name from a raw token secret.
// The server hashes the secret part (after "sha256~") and stores it as sha256~<base64(hash)>.
func tokenName(rawSecret string) string {
	h := sha256.Sum256([]byte(rawSecret))
	return "sha256~" + base64.RawURLEncoding.EncodeToString(h[:])
}

var _ = g.Describe("[sig-auth] OAuth", func() {
	g.It("should successfully review valid and invalid tokens [Component][apigroup:oauth.openshift.io]", func(ctx context.Context) {
		t := g.GinkgoTB()
		adminConfig := NewClientConfigForTest(t)
		trashBin := NewResourceTrashbin(t, adminConfig)
		defer trashBin.Empty(t)

		userClient, err := userclient.NewForConfig(adminConfig)
		o.Expect(err).NotTo(o.HaveOccurred())
		oauthClient, err := oauthv1client.NewForConfig(adminConfig)
		o.Expect(err).NotTo(o.HaveOccurred())

		// Use unique per-run names so that stale resources from a previous run or a
		// parallel CI job cannot cause creation to fail with a name collision.
		userName := names.SimpleNameGenerator.GenerateName("tokenreviews-e2e-testuser-")
		clientName := names.SimpleNameGenerator.GenerateName("tokenreviews-e2e-client-")

		user, err := userClient.UserV1().Users().Create(ctx, &userv1.User{
			ObjectMeta: metav1.ObjectMeta{Name: userName},
		}, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		trashBin.AddResource(userv1.GroupVersion.WithResource("users"), user.GetObjectMeta())

		oauthClientObj, err := oauthClient.OAuthClients().Create(ctx, &oauthv1.OAuthClient{
			ObjectMeta:   metav1.ObjectMeta{Name: clientName},
			GrantMethod:  oauthv1.GrantHandlerAuto,
			RedirectURIs: []string{"https://localhost/callback"},
			ScopeRestrictions: []oauthv1.ScopeRestriction{
				{ExactValues: []string{"user:info"}},
			},
		}, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		trashBin.AddResource(oauthv1.GroupVersion.WithResource("oauthclients"), oauthClientObj.GetObjectMeta())

		// rawSecret is the value that will be sent in the TokenReview spec.
		// The resource name is derived by hashing it. It is generated per run so
		// the derived token name is unique too.
		rawSecret := names.SimpleNameGenerator.GenerateName("tokenreviews-e2e-secret-")
		accessToken, err := oauthClient.OAuthAccessTokens().Create(ctx, &oauthv1.OAuthAccessToken{
			ObjectMeta:  metav1.ObjectMeta{Name: tokenName(rawSecret)},
			ClientName:  clientName,
			Scopes:      []string{"user:info"},
			RedirectURI: "https://localhost/callback",
			ExpiresIn:   3600,
			UserName:    user.Name,
			UserUID:     string(user.UID),
		}, metav1.CreateOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		trashBin.AddResource(oauthv1.GroupVersion.WithResource("oauthaccesstokens"), accessToken.GetObjectMeta())

		// review a token that does not exist — expect not authenticated
		result := &kauthenticationv1.TokenReview{}
		err = oauthClient.RESTClient().Post().
			Resource("tokenreviews").
			Body(&kauthenticationv1.TokenReview{
				Spec: kauthenticationv1.TokenReviewSpec{Token: "sha256~doesnotexist"}, // notsecret
			}).
			Do(ctx).Into(result)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(result.Status.Authenticated).To(o.BeFalse())

		// review the valid token — expect authenticated
		result = &kauthenticationv1.TokenReview{}
		err = oauthClient.RESTClient().Post().
			Resource("tokenreviews").
			Body(&kauthenticationv1.TokenReview{
				Spec: kauthenticationv1.TokenReviewSpec{Token: "sha256~" + rawSecret},
			}).
			Do(ctx).Into(result)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(result.Status.Authenticated).To(o.BeTrue())
		// Assert the authenticated identity so a regression that authenticates the
		// wrong principal is caught, not just the boolean.
		o.Expect(result.Status.User.Username).To(o.Equal(user.Name))
		o.Expect(result.Status.User.UID).To(o.Equal(string(user.UID)))
	})
})
