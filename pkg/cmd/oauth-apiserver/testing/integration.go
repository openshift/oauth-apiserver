package testing

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/google/uuid"
	"k8s.io/apiserver/pkg/storage/storagebackend"

	"k8s.io/client-go/rest"
)

// StartDefaultTestServer starts a test server with default test flags.
func StartDefaultTestServer(t Logger, storageConfig *storagebackend.Config, flags ...string) (func(), *rest.Config, error) {
	// create kubeconfig which will not actually be used. But authz/authn needs it to startup.
	fakeKubeConfig, err := ioutil.TempFile("", "kubeconfig")
	if err != nil {
		return nil, nil, err
	}
	fakeKubeConfig.WriteString(`
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://127.1.2.3:12345
  name: integration
contexts:
- context:
    cluster: integration
    user: test
  name: default-context
current-context: default-context
users:
- name: test
  user:
    password: test
    username: test
`)
	fakeKubeConfig.Close()
	storageConfig.EventsHistoryWindow = max(storageConfig.EventsHistoryWindow, storagebackend.DefaultEventsHistoryWindow)
	s, err := StartTestServer(t, append([]string{
		"--authentication-skip-lookup",
		"--authentication-kubeconfig", fakeKubeConfig.Name(),
		"--authorization-kubeconfig", fakeKubeConfig.Name(),
		"--kubeconfig", fakeKubeConfig.Name(),
		"--disable-admission-plugins", "NamespaceLifecycle,MutatingAdmissionWebhook,ValidatingAdmissionWebhook"},
		flags...,
	), storageConfig)
	if err != nil {
		os.Remove(fakeKubeConfig.Name())
		return nil, nil, err
	}

	tearDownFn := func() {
		defer os.Remove(fakeKubeConfig.Name())
		s.TearDownFn()
	}

	return tearDownFn, s.ClientConfig, nil
}

// StartDefaultIntegrationTestServer starts a default test server against an
// pre-launched etcd cluster.
func StartDefaultIntegrationTestServer(t Logger, flags ...string) (func(), *rest.Config, error) {
	return StartDefaultTestServer(t, nil, append(flags,
		"--etcd-prefix", uuid.New().String(),
		"--etcd-servers", strings.Join(integrationEtcdServers(), ","),
	)...)
}

func integrationEtcdServers() []string {
	if etcdURL, ok := os.LookupEnv("KUBE_INTEGRATION_ETCD_URL"); ok {
		return []string{etcdURL}
	}
	return []string{"http://127.0.0.1:2379"}
}
