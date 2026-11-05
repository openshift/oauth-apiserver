// Package caclient builds the HTTP clients shared by the issuer, external
// claims source, and client-credentials code paths.
package caclient

import (
	"crypto/x509"
	"net/http"
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	"github.com/openshift/library-go/pkg/network/httptransport"
)

// New builds an *http.Client trusting certificateAuthority if set, otherwise
// the system roots, plus trustedCA if non-nil. certAuthorityName identifies
// certificateAuthority in parse errors.
func New(certAuthorityName, certificateAuthority string, trustedCA dynamiccertificates.CAContentProvider, timeout time.Duration) (*http.Client, error) {
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

	rt, err := httptransport.NewRoundTripper(opts...)
	if err != nil {
		return nil, err
	}

	return &http.Client{Transport: rt, Timeout: timeout}, nil
}
