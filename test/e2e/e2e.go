package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"

	g "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"

	kauthenticationv1 "k8s.io/api/authentication/v1"

	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
)

var _ = g.Describe("[sig-auth] OAuth", func() {
	g.It("should successfully review valid and invalid tokens [apigroup:oauth.openshift.io]", func(ctx context.Context) {
		testTokenReviewsGinkgo(g.GinkgoTB())
	})
})

func testTokenReviewsGinkgo(t testing.TB) {
	// Type assert to *testing.T for compatibility with existing helper functions
	tt, ok := t.(*testing.T)
	if !ok {
		t.Fatal("test context is not *testing.T")
	}

	adminConfig := NewClientConfigForTest(tt)
	trashBin := NewResourceTrashbin(tt, adminConfig)
	defer trashBin.Empty(tt)

	userClient, err := userclient.NewForConfig(adminConfig)
	require.NoError(t, err)
	oauthClient, err := oauthv1client.NewForConfig(adminConfig)
	require.NoError(t, err)

	user := createTestUser(tt, trashBin, userClient)
	createTestOAuthClient(tt, trashBin, oauthClient.OAuthClients())
	accessToken := createTestAccessToken(tt, trashBin, oauthClient.OAuthAccessTokens(), user.Name, string(user.UID))

	pforwardCancel := PortForwardSvc(tt, "openshift-oauth-apiserver", "api", "11443:443")
	defer pforwardCancel()

	insecureClient := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				// we'll be reaching service-ca signed endpoints, service-ca
				// certs are not a part of kubeconfig's ca bundle
				InsecureSkipVerify: true,
			},
		},
	}

	// test token review for a token that should not exist in the cluster
	failedReviewReq := createTokenReviewRequestForToken(tt, "notaveryrandomnameforanything")
	resp, err := insecureClient.Do(failedReviewReq)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)

	tokenReviewResp := &kauthenticationv1.TokenReview{}
	err = json.Unmarshal(respBodyBytes, tokenReviewResp)
	require.NoError(t, err)

	require.False(t, tokenReviewResp.Status.Authenticated)

	// test token review for a token that we previously created
	successfulReviewReq := createTokenReviewRequestForToken(tt, accessToken.Name)
	resp, err = insecureClient.Do(successfulReviewReq)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBodyBytes, err = ioutil.ReadAll(resp.Body)
	require.NoError(t, err)

	tokenReviewResp = &kauthenticationv1.TokenReview{}
	err = json.Unmarshal(respBodyBytes, tokenReviewResp)
	require.NoError(t, err)

	require.True(t, tokenReviewResp.Status.Authenticated)
}
