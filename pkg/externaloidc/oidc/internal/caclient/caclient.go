// Package caclient builds *http.Client instances that pin trust to an
// optional static CA bundle, layer an optional dynamically reloaded trusted
// CA content provider on top, or both. It exists so the issuer, external
// claims source, and client-credentials HTTP clients share one
// implementation of that trust-building logic instead of each reimplementing
// it.
package caclient

import (
	"crypto/x509"
	"net/http"
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"github.com/openshift/library-go/pkg/network/httptransport"
)

// New builds an *http.Client that pins trust to certificateAuthority, if
// non-empty, and layers trustedCA, if non-nil, on top. certAuthorityName
// identifies certificateAuthority in parse-failure errors.
//
// A non-empty certificateAuthority excludes the system trust roots, because
// callers document the system verifier as the behavior for the empty case.
// trustedCA is always added on top of whatever base is already in effect —
// the system roots, or certificateAuthority when set — so that an HTTPS or
// TLS-intercepting proxy still verifies.
func New(certAuthorityName, certificateAuthority string, trustedCA dynamiccertificates.CAContentProvider, timeout time.Duration) (*http.Client, error) {
	rt, err := httptransport.NewRoundTripper(Options(certAuthorityName, certificateAuthority, trustedCA)...)
	if err != nil {
		return nil, err
	}

	return &http.Client{Transport: rt, Timeout: timeout}, nil
}

// Options returns the httptransport options implementing the trust-pinning
// behavior documented on New. It is exposed separately so a caller that
// needs to special-case "no CA configured at all" (for example, to defer to
// someone else's default client) can make that decision before paying for a
// round tripper it won't use.
func Options(certAuthorityName, certificateAuthority string, trustedCA dynamiccertificates.CAContentProvider) []httptransport.Option {
	var opts []httptransport.Option
	if len(certificateAuthority) > 0 {
		opts = append(opts,
			httptransport.WithCertPool(x509.NewCertPool()),
			httptransport.WithCAData(certAuthorityName, []byte(certificateAuthority)),
		)
	}
	if trustedCA != nil {
		opts = append(opts, httptransport.WithCAContentProvider(trustedCA))
	}
	return opts
}
