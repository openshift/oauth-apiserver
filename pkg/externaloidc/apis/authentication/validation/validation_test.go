package validation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/utils/ptr"

	certutil "k8s.io/client-go/util/cert"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	externaloidccel "github.com/openshift/oauth-apiserver/pkg/externaloidc/cel"
)

// NOTE: These test cases were taken from
// https://github.com/kubernetes/kubernetes/blob/03779bbd00da25c7fcd03711ddfe466a3322e1d7/staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation_test.go#L46-L842
// and adjusted to fit our new configuration file API and validation pattern.

func TestValidateAuthenticationConfiguration(t *testing.T) {
	testCases := []struct {
		name string
		in   *authentication.AuthenticationConfiguration
		want string
	}{
		{
			name: "jwt authenticator is empty",
			in:   &authentication.AuthenticationConfiguration{},
			// NOTE: This differs from the upstream because this is an
			// opt-in feature from our end users and we do not allow them to
			// not specify any authentication configuration.
			// want: "",
			want: "jwt: Required value: jwt is required and must not be empty",
		},
		{
			name: "duplicate issuer across jwt authenticators",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[1].issuer.url: Duplicate value: "https://issuer-url"`,
		},
		{
			name: "duplicate discoveryURL across jwt authenticators",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:          "https://issuer-url",
							DiscoveryURL: "https://discovery-url/.well-known/openid-configuration",
							Audiences:    []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
					{
						Issuer: &authentication.Issuer{
							URL:          "https://different-issuer-url",
							DiscoveryURL: "https://discovery-url/.well-known/openid-configuration",
							Audiences:    []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[1].issuer.discoveryURL: Duplicate value: "https://discovery-url/.well-known/openid-configuration"`,
		},
		{
			name: "failed issuer validation",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "invalid-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "claim",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[0].issuer.url: Invalid value: "invalid-url": URL scheme must be https`,
		},
		{
			name: "failed claimValidationRule validation",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
							{
								Claim:         "foo",
								RequiredValue: "baz",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "claim",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: `jwt[0].claimValidationRules[1].claim: Duplicate value: "foo"`,
		},
		{
			name: "failed claimMapping validation",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: "jwt[0].claimMappings.username: Required value: claim or expression is required",
		},
		{
			name: "failed userValidationRule validation",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						UserValidationRules: []authentication.UserValidationRule{
							{Expression: "user.username == 'foo'"},
							{Expression: "user.username == 'foo'"},
						},
					},
				},
			},
			want: `jwt[0].userValidationRules[1].expression: Duplicate value: "user.username == 'foo'"`,
		},
		{
			name: "valid authentication configuration with disallowed issuer",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			// TODO: We currently do not match the upstream on being able to configure disallowed issuers.
			// We should eventually match this functionality to ensure that we never attempt to
			// configure an authenticator for something like the service account issuer (what the disallowed issuers seems to be mostly used for upstream).
			// want: `jwt[0].issuer.url: Invalid value: "https://issuer-url": URL must not overlap with disallowed issuers: [a b c https://issuer-url]`,
			want: "",
		},
		{
			name: "valid authentication configuration that uses unverified email",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: "claims.email",
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "claims.email": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that almost uses unverified email",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: "claims.email_",
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses unverified email join",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `['yay', string(claims.email), 'panda'].join(' ')`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "['yay', string(claims.email), 'panda'].join(' ')": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses unverified optional email",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `claims.?email`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "claims.?email": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses unverified optional map email key",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `{claims.?email: "panda"}`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "{claims.?email: \"panda\"}": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses unverified optional map email value",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `{"fancy": claims.?email}`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "{\"fancy\": claims.?email}": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses unverified email value in list iteration",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `["a"].map(i, i + claims.email)`,
							},
						},
					},
				},
			},
			want: `jwt[0].claimMappings.username.expression: Invalid value: "[\"a\"].map(i, i + claims.email)": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression`,
		},
		{
			name: "valid authentication configuration that uses verified email join via rule",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Expression: `string(claims.email_verified) == "panda"`,
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `['yay', string(claims.email), 'panda'].join(' ')`,
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses verified email join via extra",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `['yay', string(claims.email), 'panda'].join(' ')`,
							},
							Extra: []authentication.ExtraMapping{
								{Key: "panda.io/foo", ValueExpression: "claims.email_verified.upperAscii()"},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses verified email join via extra optional",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `['yay', string(claims.email), 'panda'].join(' ')`,
							},
							Extra: []authentication.ExtraMapping{
								{Key: "panda.io/foo", ValueExpression: "claims.?email_verified"},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses email and email_verified || true via username",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						// allow email claim when email_verified is true or absent
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `claims.?email_verified.orValue(true) ? claims.email : claims.sub`,
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses email and email_verified || false via username",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						// allow email claim only when email_verified is present and true
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `claims.?email_verified.orValue(false) ? claims.email : claims.sub`,
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses verified email via claim validation rule",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								// By explicitly comparing the value to true, we let type-checking see the result will be
								// a boolean, and to make sure a non-boolean email_verified claim will be caught at runtime.
								Expression: `claims.?email_verified.orValue(true) == true`,
							},
						},
						// allow email claim only when email_verified is present and true
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `{claims.?email: "panda"}`,
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "valid authentication configuration that uses verified email via claim validation rule incorrectly",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								// This expression was previously documented in the godoc for the JWT authenticator
								// and was incorrect. It was changed to the above expression in the previous test case.
								// Testing the old expression here to confirm it fails validation.
								Expression: `claims.?email_verified.orValue(true)`,
							},
						},
						// allow email claim only when email_verified is present and true
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Expression: `{claims.?email: "panda"}`,
							},
						},
					},
				},
			},
			want: `[jwt[0].claimValidationRules[0].expression: Invalid value: "claims.?email_verified.orValue(true)": must evaluate to bool, jwt[0].claimMappings.username.expression: Invalid value: "{claims.?email: \"panda\"}": claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression]`,
		},
		{
			name: "valid authentication configuration",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimValidationRules: []authentication.ClaimValidationRule{
							{
								Claim:         "foo",
								RequiredValue: "bar",
							},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
					},
				},
			},
			want: "",
		},

		// NOTE: From here on, these are test cases we have added for OpenShift-specific implementation

		{
			name: "valid authentication configuration with an external claims source",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "invalid authentication configuration with external claims sources, too many",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: func() []authentication.ExternalClaimsSource {
							out := []authentication.ExternalClaimsSource{}
							for i := range maxExternalClaimSources + 1 {
								out = append(out, authentication.ExternalClaimsSource{
									Authentication: &authentication.Authentication{
										Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
									},
									URL: &authentication.SourceURL{
										Hostname:       ptr.To("test.kubernetes.com"),
										PathExpression: ptr.To("['claims']"),
									},
									Mappings: []authentication.SourcedClaimMapping{
										{
											Name:       ptr.To(strings.Repeat("a", i+1)),
											Expression: ptr.To("response.groups.join(',')"),
										},
									},
								})
							}
							return out
						}(),
					},
				},
			},
			want: fmt.Sprintf("jwt[0].externalClaimsSources: Too many: %d: must have at most %d items", maxExternalClaimSources+1, maxExternalClaimSources),
		},
		{
			name: "valid authentication configuration with an external claims source, authentication not specified",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "invalid authentication configuration with an external claims source, authentication specified, authentication.type not specified",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].authentication.type: Required value: type is required and must be one of [ClientCredential RequestProvidedToken]",
		},
		{
			name: "invalid authentication configuration with an external claims source, authentication specified, authentication.type not valid option",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationType("NotARealAuthenticationType")),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].authentication.type: Invalid value: \"NotARealAuthenticationType\": type must be one of [ClientCredential RequestProvidedToken]",
		},
		{
			name: "valid authentication configuration with an external claims source, ClientCredential authentication",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential authentication, missing clientCredential",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].authentication.clientCredential: Required value: clientCredential is required when type is ClientCredential",
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential authentication, empty id",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].authentication.clientCredential.clientID: Required value: clientID is required and must not be an empty string",
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential authentication, empty secret",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "",
										TokenEndpoint: "https://login.example.com/oauth2/token",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].authentication.clientCredential.clientSecret: Required value: clientSecret is required and must not be an empty string",
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential authentication, empty tokenEndpoint",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].authentication.clientCredential.tokenEndpoint: Required value: tokenEndpoint is required and must not be an empty string",
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential authentication, non-https tokenEndpoint",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "http://login.example.com/oauth2/token",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.tokenEndpoint: Invalid value: "http://login.example.com/oauth2/token": tokenEndpoint must use the https scheme`,
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential authentication, tokenEndpoint with no host",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https:///oauth2/token",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.tokenEndpoint: Invalid value: "https:///oauth2/token": tokenEndpoint must have a host`,
		},
		{
			name: "invalid authentication configuration with an external claims source, RequestProvidedToken with clientCredential set (forbidden)",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].authentication.clientCredential: Forbidden: clientCredential must not be set when type is not ClientCredential",
		},
		{
			name: "valid authentication configuration with an external claims source, ClientCredential with certificateAuthority",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token",
										TLS: &authentication.TLS{
											CertificateAuthority: func() *string {
												caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
												if err != nil {
													t.Fatal(err)
												}
												caCert, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "test-ca"}, caPrivateKey)
												if err != nil {
													t.Fatal(err)
												}
												return ptr.To(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})))
											}(),
										},
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential with empty certificateAuthority",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token",
										TLS: &authentication.TLS{
											CertificateAuthority: ptr.To(""),
										},
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.tls.certificateAuthority: Invalid value: "": certificateAuthority must not be empty when set and must be a valid PEM-encoded certificate`,
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential with empty scope in scopes list",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token",
										Scopes:        []string{"https://graph.microsoft.com/.default", ""},
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.scopes[1]: Invalid value: "": scope must not be an empty string`,
		},
		{
			name: "valid authentication configuration with an external claims source, ClientCredential with scopes",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token",
										Scopes:        []string{"https://graph.microsoft.com/.default"},
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential with non-ASCII clientID",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "client-\x00-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.clientID: Invalid value: "client-\x00-id": clientID must only contain printable ASCII characters`,
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential with non-ASCII clientSecret",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "secret-\xff",
										TokenEndpoint: "https://login.example.com/oauth2/token",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.clientSecret: Invalid value: "<masked>": clientSecret must only contain printable ASCII characters`,
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential tokenEndpoint with query parameters",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token?foo=bar",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.tokenEndpoint: Invalid value: "https://login.example.com/oauth2/token?foo=bar": tokenEndpoint must not contain query parameters`,
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential tokenEndpoint with fragment",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com/oauth2/token#frag",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.tokenEndpoint: Invalid value: "https://login.example.com/oauth2/token#frag": tokenEndpoint must not contain a fragment`,
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential tokenEndpoint with user info",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://user:pass@login.example.com/oauth2/token",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.tokenEndpoint: Invalid value: "https://user:pass@login.example.com/oauth2/token": tokenEndpoint must not contain user information`,
		},
		{
			name: "invalid authentication configuration with an external claims source, ClientCredential tokenEndpoint with no path",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeClientCredential),
									ClientCredential: &authentication.ClientCredentialConfig{
										ClientID:      "my-client-id",
										ClientSecret:  "my-client-secret",
										TokenEndpoint: "https://login.example.com",
									},
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("api.example.com"),
									PathExpression: ptr.To("['v1', 'users']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: `jwt[0].externalClaimsSources[0].authentication.clientCredential.tokenEndpoint: Invalid value: "https://login.example.com": tokenEndpoint must have a path`,
		},
		{
			name: "invalid authentication configuration with an external claims source, tls specified, tls.certificateAuthority omitted",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								TLS: &authentication.TLS{},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].tls: Invalid value: {\"CertificateAuthority\":null}: at least one field must be set when tls is specified",
		},
		{
			name: "invalid authentication configuration with an external claims source, tls specified, tls.certificateAuthority empty string",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								TLS: &authentication.TLS{
									CertificateAuthority: ptr.To(""),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].tls.certificateAuthority: Invalid value: \"\": certificateAuthority must not be empty when set and must be a valid PEM-encoded certificate",
		},
		{
			name: "valid authentication configuration with an external claims source, tls specified, tls.certificateAuthority valid certificate",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								TLS: &authentication.TLS{
									CertificateAuthority: func() *string {
										caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
										if err != nil {
											t.Fatal(err)
										}
										caCert, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "test-ca"}, caPrivateKey)
										if err != nil {
											t.Fatal(err)
										}
										return ptr.To(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})))
									}(),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "",
		},
		{
			name: "invalid authentication configuration with an external claims source, no mappings",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings: Required value: mappings is required and must not be an empty list.",
		},
		{
			name: "invalid authentication configuration with an external claims source, too many mappings",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: func() []authentication.SourcedClaimMapping {
									out := []authentication.SourcedClaimMapping{}
									for i := range maxSourcedClaimMappings + 1 {
										out = append(out, authentication.SourcedClaimMapping{
											Name:       ptr.To(strings.Repeat("a", i+1)),
											Expression: ptr.To("'test'"),
										})
									}
									return out
								}(),
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings: Too many: 17: must have at most 16 items",
		},
		{
			name: "invalid authentication configuration with an external claims source, duplicate mapping names in single source",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("'true'"),
									},
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("'true'"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings[1].name: Duplicate value: \"groups\"",
		},
		{
			name: "invalid authentication configuration with an external claims source, duplicate mapping names across sources",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("'true'"),
									},
								},
							},
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['otherclaims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("'true'"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[1].mappings[0].name: Duplicate value: \"groups\"",
		},
		{
			name: "invalid authentication configuration with an external claims source, mapping with no name",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Expression: ptr.To("'true'"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings[0].name: Required value: name is required",
		},
		{
			name: "invalid authentication configuration with an external claims source, mapping with empty string name",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To(""),
										Expression: ptr.To("'true'"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings[0].name: Invalid value: \"\": name must not be an empty string (\"\")",
		},
		{
			name: "invalid authentication configuration with an external claims source, mapping with name not matching pattern",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("ABC789"),
										Expression: ptr.To("'true'"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings[0].name: Invalid value: \"ABC789\": name must consist of only lowercase alpha characters and underscores ('_').",
		},
		{
			name: "invalid authentication configuration with an external claims source, mapping with too long name",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To(strings.Repeat("a", maxSourceMappingNameLength+1)),
										Expression: ptr.To("'true'"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings[0].name: Too long: may not be more than 256 bytes",
		},
		{
			name: "invalid authentication configuration with an external claims source, mapping with no expression",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name: ptr.To("groups"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings[0].expression: Required value: expression is required",
		},
		{
			name: "invalid authentication configuration with an external claims source, mapping with empty string expression",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To(""),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings[0].expression: Invalid value: \"\": expression must not be an empty string",
		},
		{
			name: "invalid authentication configuration with an external claims source, mapping with invalid expression",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("notreal.claims.thing"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].mappings[0].expression: Invalid value: \"notreal.claims.thing\": error compiling expression: compilation failed: ERROR: <input>:1:1: undeclared reference to 'notreal' (in container '')\n | notreal.claims.thing\n | ^",
		},
		{
			name: "invalid authentication configuration with an external claims source, conditions specified with too many conditions",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups"),
									},
								},
								Conditions: func() []authentication.ExternalSourceCondition {
									out := []authentication.ExternalSourceCondition{}
									for i := range maxExternalSourceConditions + 1 {
										out = append(out, authentication.ExternalSourceCondition{
											Expression: ptr.To(fmt.Sprintf("!has(claims.%s)", strings.Repeat("a", i+1))),
										})
									}
									return out
								}(),
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].conditions: Too many: 17: must have at most 16 items",
		},
		{
			name: "invalid authentication configuration with an external claims source, condition specified, condition missing expression",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups"),
									},
								},
								Conditions: []authentication.ExternalSourceCondition{
									{},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].conditions[0].expression: Required value: expression is required",
		},
		{
			name: "invalid authentication configuration with an external claims source, condition specified, condition has empty string expression",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups"),
									},
								},
								Conditions: []authentication.ExternalSourceCondition{
									{
										Expression: ptr.To(""),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].conditions[0].expression: Invalid value: \"\": expression must not be an empty string",
		},
		{
			name: "invalid authentication configuration with an external claims source, condition specified, condition has invalid expression",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups"),
									},
								},
								Conditions: []authentication.ExternalSourceCondition{
									{
										Expression: ptr.To("response.something"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].conditions[0].expression: Invalid value: \"response.something\": error compiling expression: compilation failed: ERROR: <input>:1:1: undeclared reference to 'response' (in container '')\n | response.something\n | ^",
		},
		{
			name: "invalid authentication configuration with an external claims source, condition specified, conditions has duplicate expressions",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("['claims']"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups"),
									},
								},
								Conditions: []authentication.ExternalSourceCondition{
									{
										Expression: ptr.To("!has(claims.groups)"),
									},
									{
										Expression: ptr.To("!has(claims.groups)"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].conditions[1].expression: Duplicate value: \"!has(claims.groups)\"",
		},
		{
			name: "invalid authentication configuration with an external claims source, no source url",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].url: Required value: url is required",
		},
		{
			name: "invalid authentication configuration with an external claims source, source url, no hostname",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									PathExpression: ptr.To("[claims.path]"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].url.hostname: Required value: hostname is required",
		},
		{
			name: "invalid authentication configuration with an external claims source, source url, invalid hostname",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("ABC-.123.C0m"),
									PathExpression: ptr.To("[claims.path]"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].url.hostname: Invalid value: \"ABC-.123.C0m\": hostname must be a valid RFC1123 subdomain name (start/end with a lowercase alphanumeric character and only contain lowercase alphanumeric characters, '-', and '.'), optionally followed by a non-zero port.",
		},
		{
			name: "invalid authentication configuration with an external claims source, source url, hostname with port number to big",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.example.com:70000"),
									PathExpression: ptr.To("[claims.path]"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].url.hostname: Invalid value: \"test.example.com:70000\": port of the hostname must not be greater than 65535",
		},
		{
			name: "invalid authentication configuration with an external claims source, source url, hostname with port number set to 0",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.example.com:0"),
									PathExpression: ptr.To("[claims.path]"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].url.hostname: Invalid value: \"test.example.com:0\": hostname must be a valid RFC1123 subdomain name (start/end with a lowercase alphanumeric character and only contain lowercase alphanumeric characters, '-', and '.'), optionally followed by a non-zero port.",
		},
		{
			name: "invalid authentication configuration with an external claims source, source url, no pathExpression",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname: ptr.To("test.kubernetes.com"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].url.pathExpression: Required value: pathExpression is required",
		},
		{
			name: "invalid authentication configuration with an external claims source, source url, empty pathExpression",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To(""),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].url.pathExpression: Invalid value: \"\": pathExpression must not be an empty string",
		},
		{
			name: "invalid authentication configuration with an external claims source, source url, invalid pathExpression",
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{
					{
						Issuer: &authentication.Issuer{
							URL:       "https://issuer-url",
							Audiences: []string{"audience"},
						},
						ClaimMappings: &authentication.ClaimMappings{
							Username: authentication.PrefixedClaimOrExpression{
								Claim:  "sub",
								Prefix: ptr.To("prefix"),
							},
						},
						ExternalClaimsSources: []authentication.ExternalClaimsSource{
							{
								Authentication: &authentication.Authentication{
									Type: ptr.To(authentication.AuthenticationTypeRequestProvidedToken),
								},
								URL: &authentication.SourceURL{
									Hostname:       ptr.To("test.kubernetes.com"),
									PathExpression: ptr.To("[response.thing]"),
								},
								Mappings: []authentication.SourcedClaimMapping{
									{
										Name:       ptr.To("groups"),
										Expression: ptr.To("response.groups.join(',')"),
									},
								},
							},
						},
					},
				},
			},
			want: "jwt[0].externalClaimsSources[0].url.pathExpression: Invalid value: \"[response.thing]\": error compiling expression: compilation failed: ERROR: <input>:1:2: undeclared reference to 'response' (in container '')\n | [response.thing]\n | .^",
		},
	}

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{name: "trustedCAFilePath unset", path: "", want: ""},
		{name: "trustedCAFilePath valid absolute path", path: "/etc/ca/ca.crt", want: ""},
		{name: "trustedCAFilePath relative path", path: "etc/ca/ca.crt", want: `trustedCAFilePath: Invalid value: "etc/ca/ca.crt": must be a clean valid absolute filepath`},
		{name: "trustedCAFilePath with parent traversal", path: "/etc/../ca.crt", want: `trustedCAFilePath: Invalid value: "/etc/../ca.crt": must be a clean valid absolute filepath`},
		{name: "trustedCAFilePath with empty element", path: "/etc//ca.crt", want: `trustedCAFilePath: Invalid value: "/etc//ca.crt": must be a clean valid absolute filepath`},
	} {
		testCases = append(testCases, struct {
			name string
			in   *authentication.AuthenticationConfiguration
			want string
		}{
			name: tc.name,
			in: &authentication.AuthenticationConfiguration{
				JWT: []authentication.JWTAuthenticator{{
					Issuer: &authentication.Issuer{
						URL:       "https://issuer-url",
						Audiences: []string{"audience"},
					},
					ClaimMappings: &authentication.ClaimMappings{
						Username: authentication.PrefixedClaimOrExpression{
							Claim:  "sub",
							Prefix: new("prefix"),
						},
					},
				}},
				TrustedCAFilePath: tc.path,
			},
			want: tc.want,
		})
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateAuthenticationConfiguration(externaloidccel.NewCompiler(), tt.in).ToAggregate()
			if d := cmp.Diff(tt.want, errString(got)); d != "" {
				t.Fatalf("AuthenticationConfiguration validation mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func errString(errs errors.Aggregate) string {
	if errs != nil {
		return errs.Error()
	}
	return ""
}
