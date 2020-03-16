package testing

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/spf13/pflag"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	oauthapiservercmd "github.com/openshift/oauth-apiserver/pkg/cmd/oauth-apiserver"
)

// TearDownFunc is to be called to tear down a test server.
type TearDownFunc func()

// TestServerInstanceOptions Instance options the TestServer
type TestServerInstanceOptions struct {
	// DisableStorageCleanup Disable the automatic storage cleanup
	DisableStorageCleanup bool
}

// TestServer is the result of test server startup.
type TestServer struct {
	ClientConfig *restclient.Config // Rest client config
	TearDownFn   TearDownFunc       // TearDown function
	TmpDir       string             // Temp Dir used, by the apiserver
}

// Logger allows t.Testing and b.Testing to be passed to StartTestServer and StartTestServerOrDie
type Logger interface {
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Logf(format string, args ...interface{})
}

// NewDefaultTestServerOptions Default options for TestServer instances
func NewDefaultTestServerOptions() *TestServerInstanceOptions {
	return &TestServerInstanceOptions{
		DisableStorageCleanup: false,
	}
}

// StartTestServer starts a oauth-apiserver. A rest client config and a tear-down func,
// and location of the tmpdir are returned.
//
// Note: we return a tear-down func instead of a stop channel because the later will leak temporary
// 		 files that because Golang testing's call to os.Exit will not give a stop channel go routine
// 		 enough time to remove temporary files.
func StartTestServer(t Logger, instanceOptions *TestServerInstanceOptions, customFlags []string, storageConfig *storagebackend.Config) (result TestServer, err error) {
	if instanceOptions == nil {
		instanceOptions = NewDefaultTestServerOptions()
	}

	// TODO : Remove TrackStorageCleanup below when PR
	// https://github.com/kubernetes/kubernetes/pull/50690
	// merges as that shuts down storage properly
	if !instanceOptions.DisableStorageCleanup {
		registry.TrackStorageCleanup()
	}

	stopCh := make(chan struct{})
	tearDown := func() {
		if !instanceOptions.DisableStorageCleanup {
			registry.CleanupStorage()
		}
		close(stopCh)
		if len(result.TmpDir) != 0 {
			os.RemoveAll(result.TmpDir)
		}
	}
	defer func() {
		if result.TearDownFn == nil {
			tearDown()
		}
	}()

	result.TmpDir, err = ioutil.TempDir("", "openshift-apiserver")
	if err != nil {
		return result, fmt.Errorf("failed to create temp dir: %v", err)
	}

	fs := pflag.NewFlagSet("test", pflag.PanicOnError)
	o := oauthapiservercmd.NewOAuthAPIServerOptions(os.Stdout)
	o.AddFlags(fs)

	// use dynamic port
	o.RecommendedOptions.SecureServing.Listener, o.RecommendedOptions.SecureServing.BindPort, err = createLocalhostListenerOnFreePort()
	if err != nil {
		return result, fmt.Errorf("failed to create listener: %v", err)
	}
	o.RecommendedOptions.SecureServing.ServerCert.CertDirectory = result.TmpDir
	o.RecommendedOptions.SecureServing.ExternalAddress = o.RecommendedOptions.SecureServing.Listener.Addr().(*net.TCPAddr).IP // use listener addr although it is a loopback device

	// create cert fixtures in temp dir
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return result, fmt.Errorf("failed to get current file")
	}
	o.RecommendedOptions.SecureServing.ServerCert.FixtureDirectory = path.Join(path.Dir(thisFile), "testdata")

	// use special etcd if specified only, preserving codecs
	if storageConfig != nil {
		orig := o.RecommendedOptions.Etcd.StorageConfig
		o.RecommendedOptions.Etcd.StorageConfig = *storageConfig
		o.RecommendedOptions.Etcd.StorageConfig.Codec = orig.Codec
		o.RecommendedOptions.Etcd.StorageConfig.EncodeVersioner = orig.EncodeVersioner
	}

	if err := fs.Parse(customFlags); err != nil {
		return result, err
	}
	if err := o.Complete(); err != nil {
		return result, fmt.Errorf("failed to set default options: %v", err)
	}
	if err := o.Validate(customFlags); err != nil {
		return result, fmt.Errorf("failed to validate options: %v", err)
	}

	t.Logf("Starting oauth-apiserver on port %d...", o.RecommendedOptions.SecureServing.BindPort)

	server, err := o.NewOAuthAPIServer()
	if err != nil {
		return result, fmt.Errorf("failed to create API server: %v", err)
	}
	errCh := make(chan error)
	go func(stopCh <-chan struct{}) {
		if err := server.GenericAPIServer.PrepareRun().Run(stopCh); err != nil {
			errCh <- err
		}
	}(stopCh)

	t.Logf("Waiting for /healthz to be ok...")

	client, err := kubernetes.NewForConfig(server.GenericAPIServer.LoopbackClientConfig)
	if err != nil {
		return result, fmt.Errorf("failed to create a client: %v", err)
	}
	err = wait.Poll(100*time.Millisecond, 30*time.Second, func() (bool, error) {
		select {
		case err := <-errCh:
			return false, err
		default:
		}

		result := client.CoreV1().RESTClient().Get().AbsPath("/healthz").Do(context.TODO())
		status := 0
		result.StatusCode(&status)
		if status == 200 {
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return result, fmt.Errorf("failed to wait for /healthz to return ok: %v", err)
	}

	// from here the caller must call tearDown
	result.ClientConfig = server.GenericAPIServer.LoopbackClientConfig
	result.TearDownFn = tearDown

	return result, nil
}

// StartTestServerOrDie calls StartTestServer t.Fatal if it does not succeed.
func StartTestServerOrDie(t Logger, instanceOptions *TestServerInstanceOptions, flags []string, storageConfig *storagebackend.Config) *TestServer {
	result, err := StartTestServer(t, instanceOptions, flags, storageConfig)
	if err == nil {
		return &result
	}

	t.Fatalf("failed to launch server: %v", err)
	return nil
}

func createLocalhostListenerOnFreePort() (net.Listener, int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}

	// get port
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		ln.Close()
		return nil, 0, fmt.Errorf("invalid listen address: %q", ln.Addr().String())
	}

	return ln, tcpAddr.Port, nil
}
