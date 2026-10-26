package oidc_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/oidc"
	"gopkg.in/go-jose/go-jose.v2"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/utils/ptr"
)

func newIssuerServer(keys jose.JSONWebKeySet, userInfoMap map[string]interface{}) *httptest.Server {
	var srvr *httptest.Server
	mux := http.NewServeMux()

	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out, err := json.Marshal(userInfoMap)
		if err != nil {
			panic(fmt.Sprintf("could not marshal userInfoMap data: %v", err))
		}

		w.Write(out)
	})

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out, err := newOpenIDConfig(srvr.URL)
		if err != nil {
			panic(fmt.Sprintf("generating openid-configuration: %v", err))
		}
		w.Write(out)
	})

	mux.HandleFunc("/.testing/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out, err := json.Marshal(keys)
		if err != nil {
			panic(fmt.Sprintf("could not marshal keys data: %v", err))
		}

		w.Write(out)
	})

	srvr = httptest.NewTLSServer(mux)
	return srvr
}

type simpleOpenIDConfig struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func newOpenIDConfig(iss string) ([]byte, error) {
	cfg := &simpleOpenIDConfig{
		Issuer:  iss,
		JWKSURI: fmt.Sprintf("%s/.testing/keys", iss),
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshalling openid-configuration: %w", err)
	}

	return out, nil
}

type oidcKeySet struct {
	*jose.JSONWebKeySet
}

func (oks *oidcKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("parsing signed token: %w", err)
	}

	if len(jws.Signatures) == 0 {
		return nil, errors.New("jwt contained no signatures")
	}

	keyID := jws.Signatures[0].Header.KeyID

	for _, key := range oks.Keys {
		if key.KeyID == keyID {
			return jws.Verify(key)
		}
	}

	return nil, fmt.Errorf("no keys matching signature keyID %q found", keyID)
}

func TestOIDCAuthenticator(t *testing.T) {
	type testcase struct {
		name        string
		configFunc  func(iss string, ca string) *authentication.JWTAuthenticator
		want        user.DefaultInfo
		tokenFunc   func(iss string, signer jose.Signer) string
		userInfoMap map[string]interface{}
	}

	testcases := []testcase{
		{
			name: "externally sourcing claims that return a string list can be mapped to a string and re-mapped to a string list during claim mapping",
			configFunc: func(iss string, ca string) *authentication.JWTAuthenticator {
				return &authentication.JWTAuthenticator{
					Issuer: &authentication.Issuer{
						URL:                  iss,
						CertificateAuthority: ca,
						Audiences: []string{
							"test-client",
						},
					},
					ClaimMappings: &authentication.ClaimMappings{
						Username: authentication.PrefixedClaimOrExpression{
							Expression: "claims.preferred_username",
						},
						Groups: authentication.PrefixedClaimOrExpression{
							Expression: "claims.groups.split(',')",
						},
					},
					ExternalClaimsSources: []authentication.ExternalClaimsSource{
						{
							URL: &authentication.SourceURL{
								Hostname:       ptr.To(strings.TrimPrefix(iss, "https://")),
								PathExpression: ptr.To("['userinfo']"),
							},
							TLS: &authentication.TLS{
								CertificateAuthority: ptr.To(ca),
							},
							Mappings: []authentication.SourcedClaimMapping{
								{
									Name:       ptr.To("groups"),
									Expression: ptr.To("response.body.groups.join(',')"),
								},
							},
						},
					},
				}
			},
			userInfoMap: map[string]interface{}{
				"groups": []string{"one", "two", "three"},
			},
			tokenFunc: func(iss string, signer jose.Signer) string {
				claims := map[string]interface{}{
					"iss":                iss,
					"aud":                "test-client",
					"exp":                time.Now().Add(24 * time.Hour).Unix(),
					"preferred_username": "testuser",
				}

				serialized, err := json.Marshal(claims)
				if err != nil {
					panic(fmt.Sprintf("error serializing claims: %v", err))
				}

				jws, err := signer.Sign(serialized)
				if err != nil {
					panic(fmt.Sprintf("error signing serialized claims: %v", err))
				}

				token, err := jws.CompactSerialize()
				if err != nil {
					panic(fmt.Sprintf("error creating token: %v", err))
				}

				return token
			},
			want: user.DefaultInfo{
				Name: "testuser",
				Groups: []string{
					"one",
					"two",
					"three",
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("generating RSA private key: %v", err)
			}

			pubKey, err := generateJWKFromKey(&privateKey.PublicKey)
			if err != nil {
				t.Fatalf("generating public key for JWKS: %v", err)
			}

			jwks := jose.JSONWebKeySet{
				Keys: []jose.JSONWebKey{
					*pubKey,
				},
			}

			srv := newIssuerServer(jwks, tc.userInfoMap)
			defer srv.Close()

			pemBlock := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: srv.Certificate().Raw,
			}
			pemBytes := pem.EncodeToMemory(pemBlock)

			authn, err := oidc.New(t.Context(), oidc.Options{
				JWTAuthenticator:           *tc.configFunc(srv.URL, string(pemBytes)),
				KeySet:                     &oidcKeySet{&jwks},
				IssuerCertificateAuthority: string(pemBytes),
			})
			if err != nil {
				t.Fatalf("creating authenticator: %v", err)
			}

			signer, err := generateSignerFromPrivateKey(privateKey)
			if err != nil {
				t.Fatalf("generating signer: %v", err)
			}

			resp, authenticated, err := authn.AuthenticateToken(t.Context(), tc.tokenFunc(srv.URL, *signer))
			if err != nil {
				t.Fatalf("authenticating token: %v", err)
			}

			if !authenticated {
				t.Fatalf("expected the token to be authenticated but it was not")
			}

			if resp.User == nil {
				t.Fatal("expected a user but got none.")
			}

			if resp.User.GetName() != tc.want.Name {
				t.Fatalf("expected user to have name %q but got %q", tc.want.Name, resp.User.GetName())
			}

			if !slices.Equal(resp.User.GetGroups(), tc.want.GetGroups()) {
				t.Fatalf("expected user to have groups %v but got %v", tc.want.GetGroups(), resp.User.GetGroups())
			}
		})
	}
}

func generateSignerFromPrivateKey(pk *rsa.PrivateKey) (*jose.Signer, error) {
	jwk, err := generateJWKFromKey(pk)
	if err != nil {
		return nil, fmt.Errorf("generating jwk from key: %w", err)
	}

	signingKey := jose.SigningKey{
		Key:       jwk,
		Algorithm: jose.RS256,
	}

	signer, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		return nil, fmt.Errorf("generating signer: %v", err)
	}

	return &signer, nil
}

func generateJWKFromKey[T *rsa.PrivateKey | *rsa.PublicKey](key T) (*jose.JSONWebKey, error) {
	out := &jose.JSONWebKey{
		Key:       key,
		Use:       "sig",
		Algorithm: string(jose.RS256),
	}

	thumbprint, err := out.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("generating public key thumbprint: %v", err)
	}

	out.KeyID = hex.EncodeToString(thumbprint)
	return out, nil
}
