package oauth_apiserver_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/pflag"
	oteltrace "go.opentelemetry.io/otel/trace"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	genericapiserveroptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/storage/etcd3"
	etcdtesting "k8s.io/apiserver/pkg/storage/etcd3/testing"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	auditbuffered "k8s.io/apiserver/plugin/pkg/audit/buffered"
	audittruncate "k8s.io/apiserver/plugin/pkg/audit/truncate"
	"k8s.io/component-base/featuregate"
	netutils "k8s.io/utils/net"

	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned"
	userclient "github.com/openshift/client-go/user/clientset/versioned"
	oauthapiserver "github.com/openshift/oauth-apiserver/pkg/cmd/oauth-apiserver"
	oauthapiservertesting "github.com/openshift/oauth-apiserver/pkg/cmd/oauth-apiserver/testing"
	tokenvalidationoptions "github.com/openshift/oauth-apiserver/pkg/tokenvalidation/options"
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
	if _, err := oauthClient.OauthV1().OAuthAccessTokens().List(context.TODO(), metav1.ListOptions{}); err != nil {
		t.Fatal(err)
	}

	userClient, err := userclient.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userClient.UserV1().Groups().List(context.TODO(), metav1.ListOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestAddFlags(t *testing.T) {
	// test data
	fs := pflag.NewFlagSet("addflagstest", pflag.PanicOnError)
	target := oauthapiserver.NewOAuthAPIServerOptions(nil)
	target.AddFlags(fs)
	args := []string{
		"--shutdown-delay-duration=7s",
		"--shutdown-send-retry-after=true",
	}

	// act
	fs.Parse(args)

	// validate
	expected := &oauthapiserver.OAuthAPIServerOptions{
		GenericServerRunOptions: &genericapiserveroptions.ServerRunOptions{
			MaxRequestsInFlight:         400,
			MaxMutatingRequestsInFlight: 200,
			RequestTimeout:              time.Minute,
			MinRequestTimeout:           1800,
			ShutdownDelayDuration:       time.Second * 7,
			JSONPatchMaxCopyBytes:       int64(3 * 1024 * 1024),
			MaxRequestBodyBytes:         int64(3 * 1024 * 1024),
			ShutdownSendRetryAfter:      true,
		},
		RecommendedOptions: &genericapiserveroptions.RecommendedOptions{
			Etcd: &genericapiserveroptions.EtcdOptions{
				StorageConfig: storagebackend.Config{
					Type: "",
					Transport: storagebackend.TransportConfig{
						TracerProvider: oteltrace.NewNoopTracerProvider(),
					},
					Prefix:                "openshift.io",
					CompactionInterval:    storagebackend.DefaultCompactInterval,
					CountMetricPollPeriod: time.Minute,
					DBMetricPollInterval:  storagebackend.DefaultDBMetricPollInterval,
					HealthcheckTimeout:    storagebackend.DefaultHealthcheckTimeout,
					ReadycheckTimeout:     storagebackend.DefaultReadinessTimeout,
					LeaseManagerConfig: etcd3.LeaseManagerConfig{
						ReuseDurationSeconds: 60,
						MaxObjectCount:       1000,
					},
				},
				DefaultStorageMediaType: "application/json",
				DeleteCollectionWorkers: 1,
				EnableGarbageCollection: true,
				EnableWatchCache:        true,
				DefaultWatchCacheSize:   100,
			},
			SecureServing: (&genericapiserveroptions.SecureServingOptions{
				BindAddress: netutils.ParseIPSloppy("0.0.0.0"),
				BindPort:    443,
				ServerCert: genericapiserveroptions.GeneratableKeyCert{
					CertDirectory: "apiserver.local.config/certificates",
					PairName:      "apiserver",
				},
				HTTP2MaxStreamsPerConnection: 1000,
			}).WithLoopback(),
			Authentication: &genericapiserveroptions.DelegatingAuthenticationOptions{
				CacheTTL: time.Second * 10,
				RequestHeader: genericapiserveroptions.RequestHeaderAuthenticationOptions{
					UsernameHeaders:     []string{"x-remote-user"},
					GroupHeaders:        []string{"x-remote-group"},
					ExtraHeaderPrefixes: []string{"x-remote-extra-"},
				},
				WebhookRetryBackoff: genericapiserveroptions.DefaultAuthWebhookRetryBackoff(),
				TokenRequestTimeout: time.Second * 10,
			},
			Authorization: &genericapiserveroptions.DelegatingAuthorizationOptions{
				AllowCacheTTL:       time.Second * 10,
				DenyCacheTTL:        time.Second * 10,
				AlwaysAllowPaths:    []string{"/healthz", "/readyz", "/livez"},
				AlwaysAllowGroups:   []string{"system:masters"},
				ClientTimeout:       time.Second * 10,
				WebhookRetryBackoff: genericapiserveroptions.DefaultAuthWebhookRetryBackoff(),
			},
			Audit: &genericapiserveroptions.AuditOptions{
				LogOptions: genericapiserveroptions.AuditLogOptions{
					Format: "json",
					BatchOptions: genericapiserveroptions.AuditBatchOptions{
						Mode: "blocking",
						BatchConfig: auditbuffered.BatchConfig{
							BufferSize:   10000,
							MaxBatchSize: 1,
						},
					},
					TruncateOptions: genericapiserveroptions.AuditTruncateOptions{
						TruncateConfig: audittruncate.Config{
							MaxBatchSize: 10485760,
							MaxEventSize: 102400,
						},
					},
					GroupVersionString: "audit.k8s.io/v1",
				},
				WebhookOptions: genericapiserveroptions.AuditWebhookOptions{
					InitialBackoff: time.Second * 10,
					BatchOptions: genericapiserveroptions.AuditBatchOptions{
						Mode: "batch",
						BatchConfig: auditbuffered.BatchConfig{
							BufferSize:     10000,
							MaxBatchSize:   400,
							MaxBatchWait:   time.Second * 30,
							ThrottleEnable: true,
							ThrottleQPS:    10,
							ThrottleBurst:  15,
							AsyncDelegate:  true,
						},
					},
					TruncateOptions: genericapiserveroptions.AuditTruncateOptions{
						TruncateConfig: audittruncate.Config{
							MaxBatchSize: 10485760,
							MaxEventSize: 102400,
						},
					},
					GroupVersionString: "audit.k8s.io/v1",
				},
			},
			Features: &genericapiserveroptions.FeatureOptions{
				EnableProfiling:           true,
				EnablePriorityAndFairness: true,
			},
			CoreAPI: &genericapiserveroptions.CoreAPIOptions{},
			Admission: &genericapiserveroptions.AdmissionOptions{
				RecommendedPluginOrder: target.RecommendedOptions.Admission.RecommendedPluginOrder,
				Plugins:                target.RecommendedOptions.Admission.Plugins,
			},
			EgressSelector: &genericapiserveroptions.EgressSelectorOptions{},
			Traces:         &genericapiserveroptions.TracingOptions{},
		},
		TokenValidationOptions: &tokenvalidationoptions.TokenValidationOptions{},
	}

	// setting the FeatureGate to nil since there is no value in comparing a FG instance
	target.RecommendedOptions.FeatureGate = nil
	// setting the ExtraAdmissionInitializers to nil since there is no value in comparing a codec instance
	target.RecommendedOptions.Etcd.StorageConfig.Codec = nil
	// setting the ExtraAdmissionInitializers to nil since functions can't be compared in go
	target.RecommendedOptions.ExtraAdmissionInitializers = nil
	// setting the Decorators to nil since functions can't be compared in go
	target.RecommendedOptions.Admission.Decorators = nil

	if !cmp.Equal(expected, target, cmpopts.IgnoreUnexported(admission.Plugins{}, *featuregate.NewFeatureGate())) {
		t.Errorf("unexpected run options,\ndiff:\n%s", cmp.Diff(expected, target, cmpopts.IgnoreUnexported(admission.Plugins{}, *featuregate.NewFeatureGate())))
	}
}

var fakeKubeConfigYAML = `
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
`

func TestOAuthAPIServerConfig(t *testing.T) {
	// test data
	fs := pflag.NewFlagSet("addflagstest", pflag.PanicOnError)
	o := oauthapiserver.NewOAuthAPIServerOptions(nil)
	o.AddFlags(fs)
	fakeKubeConfigPath := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(fakeKubeConfigPath, []byte(fakeKubeConfigYAML), 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--shutdown-delay-duration=7s",
		"--shutdown-send-retry-after=true",
		"--secure-port=0",
		"--kubeconfig", fakeKubeConfigPath,
		"--enable-priority-and-fairness=false",
	}

	// act
	fs.Parse(args)
	// the following skip loading delegated authNZ kubeconifg
	o.RecommendedOptions.Authorization.RemoteKubeConfigFileOptional = true
	o.RecommendedOptions.Authentication.RemoteKubeConfigFileOptional = true
	target, err := o.NewOAuthAPIServerConfig()
	if err != nil {
		t.Fatal(err)
	}

	// validate
	//
	// note: currently, we perform simple validation. In the future, we may consider
	// implementing more comprehensive validation for the entire configuration(apiserver.NewConfig()).
	// However, this could involve handling numerous exceptions (e.g., IgnoreUnexported)
	// when using cmp.Equal for deep equality checks.
	if target.GenericConfig.ShutdownDelayDuration != time.Second*7 {
		t.Fatalf("incorrect value of target.GenericConfig.ShutdownDelayDuration = %v, expected 7s", target.GenericConfig.ShutdownDelayDuration)
	}
	if !target.GenericConfig.ShutdownSendRetryAfter {
		t.Fatal("expected target.GenericConfig.ShutdownSendRetryAfter to be true")
	}
	if target.GenericConfig.FlowControl != nil {
		t.Fatal("PriorityAndFairness wasn't disabled")
	}
}
