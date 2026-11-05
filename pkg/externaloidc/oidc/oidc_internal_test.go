package oidc

import "testing"

func TestHTTPClientForIssuerReturnsNilWhenNoCAConfigured(t *testing.T) {
	client, err := httpClientForIssuer("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client != nil {
		t.Errorf("expected a nil client, got %#v", client)
	}
}
