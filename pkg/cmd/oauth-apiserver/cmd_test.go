package oauth_apiserver_test

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	etcdtesting "k8s.io/apiserver/pkg/storage/etcd3/testing"

	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	userclient "github.com/openshift/client-go/user/clientset/versioned"

	oauthapiservertesting "github.com/openshift/oauth-apiserver/pkg/cmd/oauth-apiserver/testing"
)

func TestServerStartUp(t *testing.T) {
	etcd, storageConfig := etcdtesting.NewUnsecuredEtcd3TestClientServer(t)
	defer etcd.Terminate(t)

	tearDown, config, err := oauthapiservertesting.StartDefaultTestServer(t, storageConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer tearDown()

	oauthClient, err := oauthclient.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oauthClient.OauthV1().OAuthAccessTokens().List(metav1.ListOptions{}); err != nil {
		t.Fatal(err)
	}

	userClient, err := userclient.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userClient.UserV1().Groups().List(metav1.ListOptions{}); err != nil {
		t.Fatal(err)
	}
}
