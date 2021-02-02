package e2e

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"

	projectclient "github.com/openshift/client-go/project/clientset/versioned"
)

// NewClientConfigForTest returns a config configured to connect to the api server
func NewClientConfigForTest(t *testing.T) *rest.Config {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{ClusterInfo: api.Cluster{InsecureSkipTLSVerify: true}})
	config, err := clientConfig.ClientConfig()
	if err == nil {
		fmt.Printf("Found configuration for host %v.\n", config.Host)
	}

	require.NoError(t, err)
	return config
}

func CreateTestProject(t *testing.T, kubeClient kubernetes.Interface, projectClient *projectclient.Clientset) *corev1.Namespace {
	newNamespaceName := names.SimpleNameGenerator.GenerateName("e2e-oauth-proxy-")

	// e2e.Logf("Creating project %q", newNamespace)
	newNamespace, err := kubeClient.CoreV1().Namespaces().Create(context.Background(),
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: newNamespaceName,
				Labels: map[string]string{
					"test": "oauth-proxy",
				},
			},
		}, metav1.CreateOptions{})
	require.NoError(t, err)

	err = waitForSelfSAR(1*time.Second, 60*time.Second, kubeClient, authorizationv1.SelfSubjectAccessReviewSpec{
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Namespace: newNamespaceName,
			Verb:      "create",
			Group:     "",
			Resource:  "pods",
		},
	})
	require.NoError(t, err)

	return newNamespace
}

func waitForSelfSAR(interval, timeout time.Duration, c kubernetes.Interface, selfSAR authorizationv1.SelfSubjectAccessReviewSpec) error {
	err := wait.PollImmediate(interval, timeout, func() (bool, error) {
		res, err := c.AuthorizationV1().SelfSubjectAccessReviews().Create(
			context.Background(),
			&authorizationv1.SelfSubjectAccessReview{
				Spec: selfSAR,
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			return false, err
		}

		return res.Status.Allowed, nil
	})

	if err != nil {
		return fmt.Errorf("failed to wait for SelfSAR (ResourceAttributes: %#v, NonResourceAttributes: %#v), err: %v", selfSAR.ResourceAttributes, selfSAR.NonResourceAttributes, err)
	}

	return nil
}

// PortForwardSvc forwards a remote service's port to localhost
// portMapping is a string "localPort:remotePort"
func PortForwardSvc(t *testing.T, svcNS, svcName, portMapping string) context.CancelFunc {
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

// resourceRef is a reference to a specific API resource
type resourceRef struct {
	Resource  schema.GroupVersionResource
	Namespace string
	Name      string
}

// ResourceTrashbin serves to put your API resources into in order to remove them
// at the end of a test
type ResourceTrashbin struct {
	dynamicClient dynamic.Interface

	resourcesToDelete []resourceRef
}

// NewResourceTrashbin creates an instance of a ResourceTrashbin
func NewResourceTrashbin(t *testing.T, adminKubeconfig *rest.Config) *ResourceTrashbin {
	dynamicClient, err := dynamic.NewForConfig(adminKubeconfig)
	require.NoError(t, err)

	return &ResourceTrashbin{
		dynamicClient: dynamicClient,

		resourcesToDelete: []resourceRef{},
	}

}

// AddResource adds a resource to the trashbin so that it can eventually be deleted
func (b *ResourceTrashbin) AddResource(resource schema.GroupVersionResource, objectMeta metav1.Object) {
	b.resourcesToDelete = append(b.resourcesToDelete,
		resourceRef{
			Resource:  resource,
			Namespace: objectMeta.GetNamespace(),
			Name:      objectMeta.GetName(),
		})
}

// Empty deletes all of the cached resources
func (b *ResourceTrashbin) Empty(t *testing.T) {
	for _, r := range b.resourcesToDelete {
		err := b.dynamicClient.
			Resource(r.Resource).
			Namespace(r.Namespace).
			Delete(context.Background(), r.Name, metav1.DeleteOptions{})
		t.Logf("Deleted %v, err: %v", r, err)
	}

	b.resourcesToDelete = []resourceRef{}
}

// Merge merges resources to be deleted from another trash bin instance
func (b *ResourceTrashbin) Merge(other *ResourceTrashbin) {
	for _, ref := range other.resourcesToDelete {
		b.resourcesToDelete = append(b.resourcesToDelete, ref)
	}
}
