package network

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	clientcert "k8s.io/client-go/util/cert"
)

var systemCertPool = x509.SystemCertPool

// TransportOption configures an outbound HTTP transport.
type TransportOption func(*transportConfig) error

type transportConfig struct {
	basePool                *x509.CertPool
	basePoolSet             bool
	staticCAs               [][]*x509.Certificate
	caContentProviders      []dynamiccertificates.CAContentProvider
	clientCertificates      []tls.Certificate
	proxyFunc               func(*http.Request) (*url.URL, error)
	explicitProxyConfigured bool
}

// WithCAContentProvider adds a CA content provider to the transport's trust
// pool. The transport registers for provider notifications and rebuilds itself
// when the provider reports a change.
func WithCAContentProvider(provider dynamiccertificates.CAContentProvider) TransportOption {
	return func(config *transportConfig) error {
		if provider == nil {
			return errors.New("CA content provider must not be nil")
		}
		config.caContentProviders = append(config.caContentProviders, provider)
		return nil
	}
}

// WithCAData adds certificates from PEM-encoded data to the transport's trust
// pool. Empty data is ignored. The name identifies the source in errors.
func WithCAData(name string, pemData []byte) TransportOption {
	return func(config *transportConfig) error {
		if len(pemData) == 0 {
			return nil
		}

		certificates, err := clientcert.ParseCertsPEM(pemData)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificates from %q: %w", name, err)
		}
		config.staticCAs = append(config.staticCAs, certificates)
		return nil
	}
}

// WithCAFile adds certificates from a PEM-encoded file to the transport's
// trust pool. An empty path is ignored. The file is read only during transport
// construction; use WithCAContentProvider for dynamically reloaded content.
func WithCAFile(name, path string) TransportOption {
	return func(config *transportConfig) error {
		if len(path) == 0 {
			return nil
		}

		certificates, err := clientcert.CertsFromFile(path)
		if err != nil {
			return fmt.Errorf("failed to load CA certificates from %q at %q: %w", name, path, err)
		}
		config.staticCAs = append(config.staticCAs, certificates)
		return nil
	}
}

// WithCertPool uses a snapshot of pool as the base trust pool instead of the
// system certificate pool. A nil pool retains the default system trust pool.
// At most one WithCertPool option may be supplied.
func WithCertPool(pool *x509.CertPool) TransportOption {
	return func(config *transportConfig) error {
		if config.basePoolSet {
			return errors.New("WithCertPool may only be specified once")
		}
		config.basePoolSet = true
		if pool != nil {
			config.basePool = pool.Clone()
		}
		return nil
	}
}

// WithClientCertificateFile configures a client certificate from a PEM-encoded
// certificate file and private key file. Both paths must be supplied together.
// The files are read only during transport construction. This option may be
// supplied multiple times; certificates retain option order.
func WithClientCertificateFile(certFile, keyFile string) TransportOption {
	return func(config *transportConfig) error {
		if (len(certFile) == 0) != (len(keyFile) == 0) {
			return errors.New("certFile and keyFile must be specified together")
		}
		if len(certFile) == 0 {
			return nil
		}

		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("failed to load client certificate from %q and key from %q: %w", certFile, keyFile, err)
		}
		config.clientCertificates = append(config.clientCertificates, certificate)
		return nil
	}
}

// WithProxyFunc explicitly configures proxy resolution. A nil function
// disables proxying. If this option is omitted, the transport uses the standard
// proxy environment variables. At most one proxy option may be supplied.
func WithProxyFunc(proxyFunc func(*http.Request) (*url.URL, error)) TransportOption {
	return func(config *transportConfig) error {
		if config.explicitProxyConfigured {
			return errors.New("WithProxyFunc may only be specified once")
		}
		config.explicitProxyConfigured = true
		config.proxyFunc = proxyFunc
		return nil
	}
}

// TransportBuilder constructs outbound HTTP transports.
type TransportBuilder interface {
	NewTransport(opts ...TransportOption) (http.RoundTripper, error)
}

// TransportBuilderFunc adapts a function to TransportBuilder.
type TransportBuilderFunc func(opts ...TransportOption) (http.RoundTripper, error)

// NewTransport implements TransportBuilder.
func (f TransportBuilderFunc) NewTransport(opts ...TransportOption) (http.RoundTripper, error) {
	return f(opts...)
}

// NewRoundTripper constructs an outbound HTTP round tripper. It uses the system trust
// pool and proxy environment variables by default. CA content provider changes
// cause the underlying transport to be rebuilt atomically.
//
// Callers own the lifecycle of supplied CA content providers and must register
// all transports before starting dynamic providers.
func NewRoundTripper(opts ...TransportOption) (http.RoundTripper, error) {
	config := &transportConfig{}
	for i, option := range opts {
		if option == nil {
			return nil, fmt.Errorf("transport option %d must not be nil", i)
		}
		if err := option(config); err != nil {
			return nil, fmt.Errorf("applying transport option %d: %w", i, err)
		}
	}

	roundTripper := &dynamicTransport{config: config}
	transport, err := config.newHTTPTransport()
	if err != nil {
		return nil, err
	}
	roundTripper.transport.Store(transport)

	for _, provider := range config.caContentProviders {
		provider.AddListener(roundTripper)
	}

	return roundTripper, nil
}

func (config *transportConfig) newHTTPTransport() (*http.Transport, error) {
	rootCAs, err := config.newCertPool()
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{RootCAs: rootCAs}
	if len(config.clientCertificates) > 0 {
		tlsConfig.Certificates = append([]tls.Certificate(nil), config.clientCertificates...)
	}

	transport := utilnet.SetTransportDefaults(&http.Transport{TLSClientConfig: tlsConfig})
	if config.explicitProxyConfigured {
		transport.Proxy = config.proxyFunc
	}
	return transport, nil
}

func (config *transportConfig) newCertPool() (*x509.CertPool, error) {
	var rootCAs *x509.CertPool
	if config.basePool != nil {
		rootCAs = config.basePool.Clone()
	} else {
		var err error
		rootCAs, err = systemCertPool()
		if err != nil {
			return nil, fmt.Errorf("loading system certificate pool: %w", err)
		}
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
	}

	for _, certificates := range config.staticCAs {
		for _, certificate := range certificates {
			rootCAs.AddCert(certificate)
		}
	}

	for _, provider := range config.caContentProviders {
		certificates, err := clientcert.ParseCertsPEM(provider.CurrentCABundleContent())
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA content from provider %q: %w", provider.Name(), err)
		}
		for _, certificate := range certificates {
			rootCAs.AddCert(certificate)
		}
	}

	return rootCAs, nil
}
