package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync/atomic"

	knet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/klog/v2"
)

// dynamicCARoundTripper rebuilds its transport when the component-proxy CA
// bundle changes. The root pool includes system roots, the static issuer CA,
// and the dynamic proxy CA so that the issuer and a TLS-intercepting proxy can
// use different certificate authorities.
type dynamicCARoundTripper struct {
	proxyCAContent *dynamiccertificates.DynamicFileCAContent
	issuerCA       []byte
	transport      atomic.Pointer[http.Transport]
}

var _ http.RoundTripper = &dynamicCARoundTripper{}
var _ dynamiccertificates.Listener = &dynamicCARoundTripper{}

// newDynamicCAHTTPClient returns an HTTP client that follows the standard
// proxy environment variables and hot-reloads the proxy trusted CA file.
func newDynamicCAHTTPClient(proxyCAContent *dynamiccertificates.DynamicFileCAContent, issuerCA []byte) (*http.Client, error) {
	roundTripper := &dynamicCARoundTripper{
		proxyCAContent: proxyCAContent,
		issuerCA:       issuerCA,
	}

	transport, err := roundTripper.buildTransport()
	if err != nil {
		return nil, err
	}
	roundTripper.transport.Store(transport)
	proxyCAContent.AddListener(roundTripper)

	return &http.Client{Transport: roundTripper}, nil
}

func (rt *dynamicCARoundTripper) buildTransport() (*http.Transport, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("loading system certificate pool: %w", err)
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}

	if len(rt.issuerCA) > 0 && !roots.AppendCertsFromPEM(rt.issuerCA) {
		return nil, fmt.Errorf("issuer certificate authority does not contain any valid PEM certificates")
	}

	if !roots.AppendCertsFromPEM(rt.proxyCAContent.CurrentCABundleContent()) {
		return nil, fmt.Errorf("proxy certificate authority does not contain any valid PEM certificates")
	}

	return knet.SetTransportDefaults(&http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}), nil
}

// Enqueue replaces the transport only after a complete CA update has been
// parsed successfully. The old transport remains available on invalid updates.
func (rt *dynamicCARoundTripper) Enqueue() {
	transport, err := rt.buildTransport()
	if err != nil {
		klog.Warningf("Failed to rebuild external OIDC transport after proxy CA change: %v", err)
		return
	}

	oldTransport := rt.transport.Swap(transport)
	if oldTransport != nil {
		oldTransport.CloseIdleConnections()
	}
	klog.V(2).Infof("Rebuilt external OIDC outbound transport with updated proxy CA bundle")
}

func (rt *dynamicCARoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.transport.Load().RoundTrip(req)
}
