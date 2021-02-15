package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	kauthenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	oauthv1 "github.com/openshift/api/oauth/v1"
	userv1 "github.com/openshift/api/user/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
)

func TestTokenReviews(t *testing.T) {
	adminConfig := NewClientConfigForTest(t)
	trashBin := NewResourceTrashbin(t, adminConfig)
	defer trashBin.Empty(t)

	userClient, err := userclient.NewForConfig(adminConfig)
	require.NoError(t, err)
	oauthClient, err := oauthv1client.NewForConfig(adminConfig)
	require.NoError(t, err)

	user := createTestUser(t, trashBin, userClient)
	createTestOAuthClient(t, trashBin, oauthClient.OAuthClients())
	accessToken := createTestAccessToken(t, trashBin, oauthClient.OAuthAccessTokens(), user.Name, string(user.UID))

	pforwardCancel := PortForwardSvc(t, "openshift-oauth-apiserver", "api", "11443:443")
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
	failedReviewReq := createTokenReviewRequestForToken(t, "notaveryrandomnameforanything")
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
	successfulReviewReq := createTokenReviewRequestForToken(t, accessToken.Name)
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

func createTestUser(t *testing.T, trashBin *ResourceTrashbin, userClient userclient.Interface) *userv1.User {
	user, err := userClient.UserV1().Users().Create(context.Background(),
		&userv1.User{
			ObjectMeta: metav1.ObjectMeta{
				Name: "testuser",
			},
		},
		metav1.CreateOptions{})
	require.NoError(t, err)

	trashBin.AddResource(userv1.GroupVersion.WithResource("users"), user.GetObjectMeta())
	return user
}

func createTestOAuthClient(t *testing.T, trashBin *ResourceTrashbin, oauthClient oauthv1client.OAuthClientInterface) {
	client, err := oauthClient.Create(context.Background(), &oauthv1.OAuthClient{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-oauth-client",
		},
		RedirectURIs: []string{"https://somewhere.on.the.internets.com/callback"},
		ScopeRestrictions: []oauthv1.ScopeRestriction{
			{ExactValues: []string{"user:info"}},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	trashBin.AddResource(oauthv1.GroupVersion.WithResource("oauthclients"), client.GetObjectMeta())
}

func createTestAccessToken(t *testing.T, trashBin *ResourceTrashbin, oauthClient oauthv1client.OAuthAccessTokenInterface, username, userUID string) *oauthv1.OAuthAccessToken {
	accessToken, err := oauthClient.Create(context.Background(), &oauthv1.OAuthAccessToken{
		ObjectMeta: metav1.ObjectMeta{
			Name: "nameofatokenwhichisprettylongtosatisfytokennamevalidation",
		},
		ClientName:  "test-oauth-client",
		Scopes:      []string{"user:info"},
		RedirectURI: "https://somewhere.on.the.internets.com/callback",
		ExpiresIn:   3600,
		UserName:    username,
		UserUID:     userUID,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	trashBin.AddResource(oauthv1.GroupVersion.WithResource("oauthaccesstokens"), accessToken.GetObjectMeta())
	return accessToken
}

func createTokenReviewRequestForToken(t *testing.T, tokenName string) *http.Request {
	tokenReview := &kauthenticationv1.TokenReview{
		Spec: kauthenticationv1.TokenReviewSpec{
			Token: tokenName,
		},
	}

	reviewBytes, err := json.Marshal(tokenReview)
	require.NoError(t, err)

	reviewBytesBuffer := bytes.NewBuffer(reviewBytes)

	reviewReq, err := http.NewRequest(http.MethodPost, "https://localhost:11443/apis/oauth.openshift.io/v1/tokenreviews", reviewBytesBuffer)
	require.NoError(t, err)

	return reviewReq
}
