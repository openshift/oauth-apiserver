package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"testing"

	g "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/require"

	kauthenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	oauthv1 "github.com/openshift/api/oauth/v1"
	userv1 "github.com/openshift/api/user/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
)

// Ginkgo wrapper for OTE framework
var _ = g.Describe("[sig-auth] OAuth API Server", func() {
	g.It("[Serial] should successfully review tokens", func() {
		testTokenReviews(g.GinkgoTB())
	})
})

// testTokenReviews is the shared test function that works with both standard Go tests and Ginkgo/OTE
// It uses testing.TB interface for dual compatibility
func testTokenReviews(t testing.TB) {
	adminConfig := getClientConfigGinkgo(t)
	trashBin := newResourceTrashbinGinkgo(t, adminConfig)
	defer emptyResourceTrashbinGinkgo(t, trashBin)

	userClient, err := userclient.NewForConfig(adminConfig)
	require.NoError(t, err)
	oauthClient, err := oauthv1client.NewForConfig(adminConfig)
	require.NoError(t, err)

	user := createTestUserGinkgo(t, trashBin, userClient)
	createTestOAuthClientGinkgo(t, trashBin, oauthClient.OAuthClients())
	accessToken := createTestAccessTokenGinkgo(t, trashBin, oauthClient.OAuthAccessTokens(), user.Name, string(user.UID))

	pforwardCancel := portForwardSvcGinkgo(t, "openshift-oauth-apiserver", "api", "11443:443")
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
	failedReviewReq := createTokenReviewRequestForTokenGinkgo(t, "notaveryrandomnameforanything")
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
	successfulReviewReq := createTokenReviewRequestForTokenGinkgo(t, accessToken.Name)
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

// getClientConfigGinkgo returns a Kubernetes client config for e2e tests.
// Priority: KUBECONFIG env → /tmp/admin.conf
func getClientConfigGinkgo(t testing.TB) *rest.Config {
	// Check KUBECONFIG environment variable first
	kubeconfigEnv := os.Getenv("KUBECONFIG")
	if kubeconfigEnv != "" {
		if _, err := os.Stat(kubeconfigEnv); err == nil {
			return getClientConfigFromPathGinkgo(t, kubeconfigEnv)
		}
		// KUBECONFIG set but file doesn't exist - will try fallback
	}

	// Then check /tmp/admin.conf (placed by ci-operator)
	const defaultConfPath = "/tmp/admin.conf"
	if _, err := os.Stat(defaultConfPath); err == nil {
		return getClientConfigFromPathGinkgo(t, defaultConfPath)
	}

	// Neither kubeconfig is available - fail with detailed error
	if kubeconfigEnv != "" {
		t.Fatalf("no kubeconfig available: KUBECONFIG env set to %q but file not found, and %s not found", kubeconfigEnv, defaultConfPath)
	}
	t.Fatalf("no kubeconfig available: KUBECONFIG env not set and %s not found", defaultConfPath)
	return nil
}

func getClientConfigFromPathGinkgo(t testing.TB, confPath string) *rest.Config {
	config, err := clientcmd.BuildConfigFromFlags("", confPath)
	if err != nil {
		t.Fatalf("error loading config from %s: %v", confPath, err)
	}
	return config
}

// getKubeClientGinkgo returns a Kubernetes client for e2e tests.
// Priority: KUBECONFIG env → /tmp/admin.conf
func getKubeClientGinkgo() (*kubernetes.Clientset, error) {
	// Check KUBECONFIG environment variable first
	kubeconfigEnv := os.Getenv("KUBECONFIG")
	if kubeconfigEnv != "" {
		if _, err := os.Stat(kubeconfigEnv); err == nil {
			return getKubeClientFromPathGinkgo(kubeconfigEnv)
		}
		// KUBECONFIG set but file doesn't exist - will try fallback
	}

	// Then check /tmp/admin.conf (placed by ci-operator)
	const defaultConfPath = "/tmp/admin.conf"
	if _, err := os.Stat(defaultConfPath); err == nil {
		return getKubeClientFromPathGinkgo(defaultConfPath)
	}

	// Neither kubeconfig is available - return detailed error
	if kubeconfigEnv != "" {
		return nil, fmt.Errorf("no kubeconfig available: KUBECONFIG env set to %q but file not found, and %s not found", kubeconfigEnv, defaultConfPath)
	}
	return nil, fmt.Errorf("no kubeconfig available: KUBECONFIG env not set and %s not found", defaultConfPath)
}

func getKubeClientFromPathGinkgo(confPath string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", confPath)
	if err != nil {
		return nil, fmt.Errorf("error loading config from %s: %w", confPath, err)
	}
	return kubernetes.NewForConfig(config)
}

// newResourceTrashbinGinkgo wraps NewResourceTrashbin for testing.TB compatibility
func newResourceTrashbinGinkgo(t testing.TB, adminKubeconfig *rest.Config) *ResourceTrashbin {
	// For Ginkgo tests, g.GinkgoTB() doesn't implement all *testing.T methods
	// We need to adapt it
	if ginkgoT, ok := t.(interface{ Helper() }); ok {
		ginkgoT.Helper()
	}
	// Create a minimal testing.T-like wrapper
	// ResourceTrashbin.Empty requires *testing.T for t.Logf
	// Since we can't create a real *testing.T, we'll create the trashbin differently
	return newResourceTrashbinDirectGinkgo(adminKubeconfig)
}

func newResourceTrashbinDirectGinkgo(adminKubeconfig *rest.Config) *ResourceTrashbin {
	dynamicClient, err := dynamic.NewForConfig(adminKubeconfig)
	if err != nil {
		panic(fmt.Sprintf("failed to create dynamic client: %v", err))
	}
	return &ResourceTrashbin{
		dynamicClient:     dynamicClient,
		resourcesToDelete: []resourceRef{},
	}
}

// emptyResourceTrashbinGinkgo wraps ResourceTrashbin.Empty for testing.TB compatibility
func emptyResourceTrashbinGinkgo(t testing.TB, b *ResourceTrashbin) {
	for _, r := range b.resourcesToDelete {
		err := b.dynamicClient.
			Resource(r.Resource).
			Namespace(r.Namespace).
			Delete(context.Background(), r.Name, metav1.DeleteOptions{})
		t.Logf("Deleted %v, err: %v", r, err)
	}
	b.resourcesToDelete = []resourceRef{}
}

// portForwardSvcGinkgo wraps PortForwardSvc for testing.TB compatibility
func portForwardSvcGinkgo(t testing.TB, svcNS, svcName, portMapping string) context.CancelFunc {
	var err error
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if err != nil {
			cancel()
		}
	}()

	portFwdCmd := exec.CommandContext(ctx, "oc", "port-forward", "svc/"+svcName, portMapping, "-n", svcNS)

	stdOut, err := portFwdCmd.StdoutPipe()
	require.NoError(t, err)

	require.NoError(t, portFwdCmd.Start())

	scanner := bufio.NewScanner(stdOut)
	scan := scanner.Scan()
	err = scanner.Err()
	require.NoError(t, err)
	require.True(t, scan)

	output := scanner.Text()
	t.Logf("port-forward command output: %s", output)

	return cancel
}

func createTestUserGinkgo(t testing.TB, trashBin *ResourceTrashbin, userClient userclient.Interface) *userv1.User {
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

func createTestOAuthClientGinkgo(t testing.TB, trashBin *ResourceTrashbin, oauthClient oauthv1client.OAuthClientInterface) {
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

func createTestAccessTokenGinkgo(t testing.TB, trashBin *ResourceTrashbin, oauthClient oauthv1client.OAuthAccessTokenInterface, username, userUID string) *oauthv1.OAuthAccessToken {
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

func createTokenReviewRequestForTokenGinkgo(t testing.TB, tokenName string) *http.Request {
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
