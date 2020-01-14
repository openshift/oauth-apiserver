package oauth_apiserver_test

import (
	"testing"

	etcdtesting "k8s.io/apiserver/pkg/storage/etcd3/testing"

	oauthapiservertesting "github.com/openshift/oauth-apiserver/pkg/cmd/oauth-apiserver/testing"
)

func TestServerStartUp(t *testing.T) {
	etcd, storageConfig := etcdtesting.NewUnsecuredEtcd3TestClientServer(t)
	defer etcd.Terminate(t)

	tearDown, _, err := oauthapiservertesting.StartDefaultTestServer(t, storageConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer tearDown()
}
