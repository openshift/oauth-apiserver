package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	oauthv1 "github.com/openshift/api/oauth/v1"
	userv1 "github.com/openshift/api/user/v1"
	oauthv1client "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	projectclient "github.com/openshift/client-go/project/clientset/versioned"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
)

func setupTokenStorage(t *testing.T, adminConfig *rest.Config, testNS string) (user1uid, user2uid, user1token, user2token string, trashBin *ResourceTrashbin, errors []error) {
	testCtx := context.Background()
	trashBin = NewResourceTrashbin(t, adminConfig)
	defer func() {
		if len(errors) != 0 {
			trashBin.Empty(t)
		}
	}()

	userClient, err := userclient.NewForConfig(adminConfig)
	require.NoError(t, err)
	oauthClient, err := oauthv1client.NewForConfig(adminConfig)
	require.NoError(t, err)

	frantaToken := []byte(testNS + "ifonlythiswasrandom") // for franta the user
	mirkaToken := []byte(testNS + "nothingness")          // for mirka the user
	user1token = "sha256~" + string(frantaToken)
	user2token = "sha256~" + string(mirkaToken)

	frantaSha := sha256.Sum256(frantaToken)
	mirkaSha := sha256.Sum256(mirkaToken)

	frantaObj, err := userClient.UserV1().Users().Create(testCtx, &userv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "franta",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	trashBin.AddResource(userv1.GroupVersion.WithResource("users"), frantaObj.GetObjectMeta())

	mirkaObj, err := userClient.UserV1().Users().Create(testCtx, &userv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "mirka",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	trashBin.AddResource(userv1.GroupVersion.WithResource("users"), mirkaObj.GetObjectMeta())

	user1uid = string(frantaObj.GetUID())
	user2uid = string(mirkaObj.GetUID())

	tokens := []*oauthv1.OAuthAccessToken{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sha256~" + base64.RawURLEncoding.EncodeToString(frantaSha[:]),
				Labels: map[string]string{
					"myfavoritetokens": "franta", // for labelselector testing
				},
			},
			ClientName:  "openshift-challenging-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "franta",
			UserUID:     string(frantaObj.UID),
			Scopes:      []string{"user:full"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sha256~" + base64.RawURLEncoding.EncodeToString(mirkaSha[:]),
			},
			ClientName:  "openshift-challenging-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "mirka",
			UserUID:     string(mirkaObj.UID),
			Scopes:      []string{"user:full"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sha256~" + testNS + "mirka0",
			},
			ClientName:  "openshift-browser-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "mirka",
			UserUID:     string(mirkaObj.UID),
			Scopes:      []string{"user:full"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sha256~" + testNS + "franta0",
			},
			ClientName:  "openshift-browser-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "franta",
			UserUID:     string(frantaObj.UID),
			Scopes:      []string{"user:full"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sha256~" + testNS + "franta1",
			},
			ClientName:  "openshift-browser-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "franta",
			UserUID:     string(frantaObj.UID),
			Scopes:      []string{"user:full"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sha256~" + testNS + "pepa0",
			},
			ClientName:  "openshift-challenging-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "pepa",
			UserUID:     "pepauid",
			Scopes:      []string{"user:full"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sha256~" + testNS + "tonda0",
			},
			ClientName:  "openshift-challenging-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "tonda",
			UserUID:     "tondauid",
			Scopes:      []string{"user:full"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sha256~" + testNS + "franta2",
			},
			ClientName:  "openshift-challenging-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "franta",
			UserUID:     string(frantaObj.UID),
			Scopes:      []string{"user:full"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNS + "nonshatoken",
			},
			ClientName:  "openshift-challenging-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "franta",
			UserUID:     string(frantaObj.UID),
			Scopes:      []string{"user:full"},
		},
	}

	for _, token := range tokens {
		_, err := oauthClient.OAuthAccessTokens().Create(testCtx, token, metav1.CreateOptions{})
		if err != nil {
			errors = append(errors, err)
		}
		trashBin.AddResource(oauthv1.GroupVersion.WithResource("oauthaccesstokens"), token.GetObjectMeta())
	}

	return
}

type userOAuthAccessTokenTestFunc func(t *testing.T, adminConfig *rest.Config, testNS, user1uid, user2uid, user1token, user2token string)

func testUserOAuthAccessAPI(t *testing.T, test userOAuthAccessTokenTestFunc) {
	adminConfig := NewClientConfigForTest(t)
	testTrashBin := NewResourceTrashbin(t, adminConfig)
	defer testTrashBin.Empty(t)

	kubeClient, err := kubernetes.NewForConfig(adminConfig)
	require.NoError(t, err)
	projectClient, err := projectclient.NewForConfig(adminConfig)
	require.NoError(t, err)

	testNS := CreateTestProject(t, kubeClient, projectClient)
	testTrashBin.AddResource(corev1.SchemeGroupVersion.WithResource("namespaces"), testNS.GetObjectMeta())

	frantaUID, mirkaUID, frantaTokenString, mirkaTokenString, trashBin, errors := setupTokenStorage(t, adminConfig, testNS.Name)
	require.Equal(t, len(errors), 0)
	testTrashBin.Merge(trashBin)

	test(t, adminConfig, testNS.Name, frantaUID, mirkaUID, frantaTokenString, mirkaTokenString)
}

func TestUserOAuthAccessTokensList(t *testing.T) {
	testUserOAuthAccessAPI(t, listTokens)
}

func TestUserOAuthAccessTokensGet(t *testing.T) {
	testUserOAuthAccessAPI(t, getTokens)
}

func TestUserOAuthAccessTokensDelete(t *testing.T) {
	testUserOAuthAccessAPI(t, deleteTokens)
}

func TestUserOAuthAccessTokensWatch(t *testing.T) {
	testUserOAuthAccessAPI(t, watchTokens)
}

func listTokens(t *testing.T, adminConfig *rest.Config, testNS, _, _, frantaTokenString, mirkaTokenString string) {
	testCtx := context.Background()

	tests := []struct {
		name            string
		userToken       string
		userName        string
		fieldSelector   fields.Selector
		labelSelector   labels.Selector
		expectedResults int
		expectedError   string
	}{
		{
			name:            "happy path",
			userToken:       mirkaTokenString,
			userName:        "mirka",
			expectedResults: 2,
		},
		{
			name:          "invalid field selector taken from oauthaccesstokens to match another username",
			userToken:     frantaTokenString,
			fieldSelector: fields.OneTermEqualSelector("userName", "pepa"),
			expectedError: "is not a known field selector",
		},
		{
			name:            "single-equal field selector to get own tokens by client",
			userToken:       frantaTokenString,
			userName:        "franta",
			fieldSelector:   fields.OneTermEqualSelector("clientName", "openshift-browser-client"),
			expectedResults: 2,
		},
		{
			name:            "set label selector to get own tokens and of others",
			userToken:       mirkaTokenString,
			userName:        "mirka",
			labelSelector:   parseLabelSelectorOrDie("randomLabel notin (mirka,franta)"),
			expectedResults: 2,
		},
		{
			name:            "a valid label selector for tokens of a different user",
			userToken:       mirkaTokenString,
			userName:        "mirka",
			labelSelector:   parseLabelSelectorOrDie("myfavoritetokens=franta"),
			expectedResults: 0,
		},
		{
			name:            "a valid label selector for own tokens",
			userToken:       frantaTokenString,
			userName:        "franta",
			labelSelector:   parseLabelSelectorOrDie("myfavoritetokens=franta"),
			expectedResults: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userConfig := rest.AnonymousClientConfig(adminConfig)
			userConfig.BearerToken = tc.userToken

			tokenClient, err := oauthv1client.NewForConfig(userConfig)
			require.NoError(t, err)

			lopts := metav1.ListOptions{}
			if tc.fieldSelector != nil {
				lopts.FieldSelector = tc.fieldSelector.String()
			}
			if tc.labelSelector != nil {
				lopts.LabelSelector = tc.labelSelector.String()
			}
			tokenList, err := tokenClient.UserOAuthAccessTokens().List(testCtx, lopts)
			if len(tc.expectedError) != 0 {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, len(tokenList.Items), tc.expectedResults, "unexpected number of results, expected %d, got %d: %v", len(tokenList.Items), tc.expectedResults, tokenList.Items)
			for _, token := range tokenList.Items {
				require.Equal(t, token.UserName, tc.userName)
			}

		})
	}
}

func getTokens(t *testing.T, adminConfig *rest.Config, testNS, _, _, frantaTokenString, mirkaTokenString string) {
	testCtx := context.Background()
	adminTokenClient, err := oauthv1client.NewForConfig(adminConfig)
	require.NoError(t, err)

	tests := []struct {
		name          string
		userToken     string
		userName      string
		getTokenName  string
		expectedError bool
	}{
		{
			name:         "get own token",
			userToken:    mirkaTokenString,
			userName:     "mirka",
			getTokenName: "sha256~" + testNS + "mirka0",
		},
		{
			name:          "get someone else's token",
			userToken:     mirkaTokenString,
			getTokenName:  "sha256~" + testNS + "franta0",
			expectedError: true,
		},
		{
			name:          "get non-sha256 token",
			userToken:     frantaTokenString,
			getTokenName:  testNS + "nonshatoken",
			expectedError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userConfig := rest.AnonymousClientConfig(adminConfig)
			userConfig.BearerToken = tc.userToken

			tokenClient, err := oauthv1client.NewForConfig(userConfig)
			require.NoError(t, err)

			token, err := tokenClient.UserOAuthAccessTokens().Get(testCtx, tc.getTokenName, metav1.GetOptions{})
			if tc.expectedError {
				if !errors.IsNotFound(err) {
					t.Fatalf("expected to not find any tokens, instead got err: %v and result: %v", err, token)
				}
				return
			}

			var tokenList []oauthv1.OAuthAccessToken
			tokens, lerr := adminTokenClient.OAuthAccessTokens().List(testCtx, metav1.ListOptions{})
			if lerr == nil {
				tokenList = tokens.Items
			}
			require.NoError(t, err, "tokens dump: %v", tokenList)
			require.Equal(t, tc.userName, token.UserName)

		})
	}
}

func deleteTokens(t *testing.T, adminConfig *rest.Config, testNS, _, _, frantaTokenString, mirkaTokenString string) {
	testCtx := context.Background()
	adminTokenClient, err := oauthv1client.NewForConfig(adminConfig)
	require.NoError(t, err)

	tests := []struct {
		name            string
		userToken       string
		deleteTokenName string
		tokenForUID     string
		expectedError   string
	}{
		{
			name:            "delete someone else's token",
			userToken:       mirkaTokenString,
			deleteTokenName: "sha256~" + testNS + "franta0",
			expectedError:   "not found",
		},
		{
			name:            "delete an own token",
			userToken:       frantaTokenString,
			deleteTokenName: "sha256~" + testNS + "franta0",
		},
		{
			name:            "delete own token with someone else's token uid",
			userToken:       mirkaTokenString,
			deleteTokenName: "sha256~" + testNS + "mirka0",
			tokenForUID:     "sha256~" + testNS + "franta1",
			expectedError:   "does not match the UID in record",
		},
		{
			name:            "delete someone else's token with their token uid",
			userToken:       mirkaTokenString,
			deleteTokenName: "sha256~" + testNS + "franta1",
			tokenForUID:     "sha256~" + testNS + "franta1",
			expectedError:   "not found",
		},
		{
			name:            "delete someone else's token with own token uid",
			userToken:       mirkaTokenString,
			deleteTokenName: "sha256~" + testNS + "franta1",
			tokenForUID:     "sha256~" + testNS + "mirka0",
			expectedError:   "not found",
		},
		{
			name:            "delete own token with own uid",
			userToken:       mirkaTokenString,
			deleteTokenName: "sha256~" + testNS + "mirka0",
			tokenForUID:     "sha256~" + testNS + "mirka0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userConfig := rest.AnonymousClientConfig(adminConfig)
			userConfig.BearerToken = tc.userToken

			tokenClient, err := oauthv1client.NewForConfig(userConfig)
			require.NoError(t, err)

			delOpts := metav1.DeleteOptions{}
			if len(tc.tokenForUID) > 0 {
				tokForUID, err := adminTokenClient.OAuthAccessTokens().Get(testCtx, tc.tokenForUID, metav1.GetOptions{})
				require.NoError(t, err)
				delOpts.Preconditions = metav1.NewUIDPreconditions(string(tokForUID.UID))
			}

			err = tokenClient.UserOAuthAccessTokens().Delete(testCtx, tc.deleteTokenName, delOpts)
			if len(tc.expectedError) > 0 {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
				return
			}

			var tokenList []oauthv1.OAuthAccessToken
			tokens, lerr := adminTokenClient.OAuthAccessTokens().List(testCtx, metav1.ListOptions{})
			if lerr == nil {
				tokenList = tokens.Items
			}
			require.NoError(t, err, "tokens dump: %v", tokenList)

		})
	}
}

func watchTokens(t *testing.T, adminConfig *rest.Config, testNS, frantaUID, mirkaUID, frantaTokenString, mirkaTokenString string) {
	testCtx := context.Background()
	testTrashBin := NewResourceTrashbin(t, adminConfig)
	defer testTrashBin.Empty(t)

	oauthTokenClient, err := oauthv1client.NewForConfig(adminConfig)
	require.NoError(t, err)

	frantaTokenNum := 0
	createAndDeleteFrantaTokens := func() {
		// Create and delete tokens for this user, should be listed later
		token, err := oauthTokenClient.OAuthAccessTokens().Create(context.Background(), &oauthv1.OAuthAccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sha256~" + testNS + "watchfranta" + strconv.Itoa(frantaTokenNum),
				Labels: map[string]string{
					"myfavoritetokens": "franta",
				},
			},
			ClientName:  "openshift-browser-client",
			ExpiresIn:   10000,
			RedirectURI: "https://test.testingstuff.test.test",
			UserName:    "franta",
			UserUID:     frantaUID,
			Scopes:      []string{"user:full"},
		}, metav1.CreateOptions{})
		frantaTokenNum++
		require.NoError(t, err)

		err = oauthTokenClient.OAuthAccessTokens().Delete(context.Background(), token.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}

	tests := []struct {
		name            string
		userToken       string
		userName        string
		fieldSelector   fields.Selector
		labelSelector   labels.Selector
		expectedResults int
		expectedError   string
		watchActions    func()
	}{
		{
			name:            "happy path",
			userToken:       mirkaTokenString,
			userName:        "mirka",
			expectedResults: 2,
			watchActions: func() {
				// Create a token for another user, should not trigger anything
				token, err := oauthTokenClient.OAuthAccessTokens().Create(context.Background(), &oauthv1.OAuthAccessToken{
					ObjectMeta: metav1.ObjectMeta{
						Name: "sha256~" + testNS + "watchtondaformirka",
					},
					ClientName:  "openshift-browser-client",
					ExpiresIn:   10000,
					RedirectURI: "https://test.testingstuff.test.test",
					UserName:    "tonda",
					UserUID:     "tondauid",
					Scopes:      []string{"user:full"},
				}, metav1.CreateOptions{})
				testTrashBin.AddResource(oauthv1.GroupVersion.WithResource("oauthaccesstokens"), token.GetObjectMeta())
				require.NoError(t, err)
			},
		},
		{
			name:          "invalid field selector taken from oauthaccesstokens to match another username",
			userToken:     frantaTokenString,
			fieldSelector: fields.OneTermEqualSelector("userName", "pepa"),
			expectedError: "rejected our request",
		},
		{
			name:            "single-equal field selector to get own tokens by client",
			userToken:       frantaTokenString,
			userName:        "franta",
			fieldSelector:   fields.OneTermEqualSelector("clientName", "openshift-browser-client"),
			expectedResults: 2 + 2,
			watchActions:    createAndDeleteFrantaTokens,
		},
		{
			name:            "set label selector to get own tokens and of others",
			userToken:       mirkaTokenString,
			userName:        "mirka",
			labelSelector:   parseLabelSelectorOrDie("randomLabel notin (mirka,franta)"),
			watchActions:    createAndDeleteFrantaTokens,
			expectedResults: 2,
		},
		{
			name:            "a valid label selector for tokens of a different user",
			userToken:       mirkaTokenString,
			userName:        "mirka",
			labelSelector:   parseLabelSelectorOrDie("myfavoritetokens=franta"),
			watchActions:    createAndDeleteFrantaTokens,
			expectedResults: 0,
		},
		{
			name:            "a valid label selector for own tokens",
			userToken:       frantaTokenString,
			userName:        "franta",
			labelSelector:   parseLabelSelectorOrDie("myfavoritetokens=franta"),
			watchActions:    createAndDeleteFrantaTokens,
			expectedResults: 3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userConfig := rest.AnonymousClientConfig(adminConfig)
			userConfig.BearerToken = tc.userToken

			tokenClient, err := oauthv1client.NewForConfig(userConfig)
			require.NoError(t, err)

			lopts := metav1.ListOptions{
				Watch: true,
			}
			if tc.fieldSelector != nil {
				lopts.FieldSelector = tc.fieldSelector.String()
			}
			if tc.labelSelector != nil {
				lopts.LabelSelector = tc.labelSelector.String()
			}
			tokenWatcher, err := tokenClient.UserOAuthAccessTokens().Watch(testCtx, lopts)
			if tokenWatcher != nil {
				defer tokenWatcher.Stop()
			}
			if len(tc.expectedError) != 0 {
				require.NotNil(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
			}

			if tokenWatcher == nil {
				return
			}

			tokensObserved := []*oauthv1.UserOAuthAccessToken{}

			finished := make(chan bool)
			timedCtx, timedCtxCancel := context.WithTimeout(context.Background(), 15*time.Second)
			go func() {
				tokenChan := tokenWatcher.ResultChan()
				for {
					select {
					case tokenEvent := <-tokenChan:
						token, ok := tokenEvent.Object.(*oauthv1.UserOAuthAccessToken)
						require.True(t, ok)
						require.Equal(t, tc.userName, token.UserName)
						tokensObserved = append(tokensObserved, token)
					case <-timedCtx.Done():
						finished <- true
						return
					}
				}
			}()

			go func() {
				if tc.watchActions != nil {
					tc.watchActions()

					// give the watch a little time
					time.Sleep(2 * time.Second)
					timedCtxCancel()
				}
			}()

			<-finished

			require.Equal(t, tc.expectedResults, len(tokensObserved), "unexpected number of results, expected %d, got %d: %v", tc.expectedResults, len(tokensObserved), tokensObserved)
			oauthTokenClient.OAuthAccessTokens()
		})
	}
}

func parseLabelSelectorOrDie(s string) labels.Selector {
	selector, err := labels.Parse(s)
	if err != nil {
		panic(err)
	}
	return selector
}
