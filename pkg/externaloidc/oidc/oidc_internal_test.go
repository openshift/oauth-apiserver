package oidc

import "testing"

// TestHTTPClientForIssuerReturnsNilWhenNoCAConfigured asserts that
// httpClientForIssuer defers to k8soidc's own default client, rather than
// building one via caclient, when neither CA is configured.
func TestHTTPClientForIssuerReturnsNilWhenNoCAConfigured(t *testing.T) {
	client, err := httpClientForIssuer("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client != nil {
		t.Errorf("expected a nil client, got %#v", client)
	}
}
