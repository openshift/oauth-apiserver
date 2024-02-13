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
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	oauthapiservercmd "github.com/openshift/oauth-apiserver/pkg/cmd/oauth-apiserver"
)

// TearDownFunc is to be called to tear down a test server.
type TearDownFunc func()

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

// StartTestServer starts a oauth-apiserver. A rest client config and a tear-down func,
// and location of the tmpdir are returned.
//
// Note: we return a tear-down func instead of a stop channel because the later will leak temporary
//
//	files that because Golang testing's call to os.Exit will not give a stop channel go routine
//	enough time to remove temporary files.
func StartTestServer(t Logger, customFlags []string, storageConfig *storagebackend.Config) (result TestServer, err error) {
	stopCh := make(chan struct{})
	tearDown := func() {
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

	serverConfig, err := o.NewOAuthAPIServerConfig()
	if err != nil {
		return result, fmt.Errorf("failed to create API server: %v", err)
	}
	completedServerConfig := serverConfig.Complete()
	oauthAPIServer, err := completedServerConfig.New(genericapiserver.NewEmptyDelegate())
	if err != nil {
		return result, err
	}
	preparedOAuthServer := oauthAPIServer.GenericAPIServer.PrepareRun()
	if err := completedServerConfig.WithOpenAPIAggregationController(preparedOAuthServer.GenericAPIServer); err != nil {
		return result, err
	}

	errCh := make(chan error)
	go func(stopCh <-chan struct{}) {
		if err := preparedOAuthServer.Run(stopCh); err != nil {
			errCh <- err
		}
	}(stopCh)

	t.Logf("Waiting for /healthz to be ok...")

	client, err := kubernetes.NewForConfig(preparedOAuthServer.GenericAPIServer.LoopbackClientConfig)
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
	result.ClientConfig = preparedOAuthServer.GenericAPIServer.LoopbackClientConfig
	result.TearDownFn = tearDown

	return result, nil
}

// StartTestServerOrDie calls StartTestServer t.Fatal if it does not succeed.
func StartTestServerOrDie(t Logger, flags []string, storageConfig *storagebackend.Config) *TestServer {
	result, err := StartTestServer(t, flags, storageConfig)
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
