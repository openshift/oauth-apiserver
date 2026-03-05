/*
* NOTE: This file was copied from https://github.com/kubernetes/kubernetes
* based on commit https://github.com/kubernetes/kubernetes/commit/b69fd9d42c4d03b8fe5b37433d59f85483835d30
*
* This is so that we can make modifications as necessary to support additional functionality
* in our external OIDC webhook implementation that is not supported by the Kubernetes
* API server, like sourcing claims from external sources.
*
* Modifications to this file will be tracked as separate commits that follow our
* standard patch commit structure of UPSTREAM: <carry>: {message}.
 */
/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apiserver

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthenticationConfiguration provides versioned configuration for authentication.
type AuthenticationConfiguration struct {
	metav1.TypeMeta

	JWT []JWTAuthenticator
}

// JWTAuthenticator provides the configuration for a single JWT authenticator.
type JWTAuthenticator struct {
	Issuer               Issuer
	ClaimValidationRules []ClaimValidationRule
	ClaimMappings        ClaimMappings
	UserValidationRules  []UserValidationRule

	// externalClaimSources is an optional field that can be used to configure
	// sources, external to the token provided in a request, in which claims
	// should be fetched from and made available to the claim mapping process
	// that is used to build the identity of a token holder.
	// For example, fetching additional user metadata from an OIDC provider's UserInfo endpoint.
	// externalClaimSources must not exceed 5 entries.
	// +optional
	ExternalClaimsSources []ExternalClaimsSource
}

// Issuer provides the configuration for an external provider's specific settings.
type Issuer struct {
	// url points to the issuer URL in a format https://url or https://url/path.
	// This must match the "iss" claim in the presented JWT, and the issuer returned from discovery.
	// Same value as the --oidc-issuer-url flag.
	// Discovery information is fetched from "{url}/.well-known/openid-configuration" unless overridden by discoveryURL.
	// Required to be unique across all JWT authenticators.
	// Note that egress selection configuration is not used for this network connection.
	// +required
	URL string
	// discoveryURL, if specified, overrides the URL used to fetch discovery
	// information instead of using "{url}/.well-known/openid-configuration".
	// The exact value specified is used, so "/.well-known/openid-configuration"
	// must be included in discoveryURL if needed.
	//
	// The "issuer" field in the fetched discovery information must match the "issuer.url" field
	// in the AuthenticationConfiguration and will be used to validate the "iss" claim in the presented JWT.
	// This is for scenarios where the well-known and jwks endpoints are hosted at a different
	// location than the issuer (such as locally in the cluster).
	//
	// Example:
	// A discovery url that is exposed using kubernetes service 'oidc' in namespace 'oidc-namespace'
	// and discovery information is available at '/.well-known/openid-configuration'.
	// discoveryURL: "https://oidc.oidc-namespace/.well-known/openid-configuration"
	// certificateAuthority is used to verify the TLS connection and the hostname on the leaf certificate
	// must be set to 'oidc.oidc-namespace'.
	//
	// curl https://oidc.oidc-namespace/.well-known/openid-configuration (.discoveryURL field)
	// {
	//     issuer: "https://oidc.example.com" (.url field)
	// }
	//
	// discoveryURL must be different from url.
	// Required to be unique across all JWT authenticators.
	// Note that egress selection configuration is not used for this network connection.
	// +optional
	DiscoveryURL         string
	CertificateAuthority string
	Audiences            []string
	AudienceMatchPolicy  AudienceMatchPolicyType
}

// AudienceMatchPolicyType is a set of valid values for Issuer.AudienceMatchPolicy
type AudienceMatchPolicyType string

// Valid types for AudienceMatchPolicyType
const (
	AudienceMatchPolicyMatchAny AudienceMatchPolicyType = "MatchAny"
)

// ClaimValidationRule provides the configuration for a single claim validation rule.
type ClaimValidationRule struct {
	Claim         string
	RequiredValue string

	Expression string
	Message    string
}

// ClaimMappings provides the configuration for claim mapping
type ClaimMappings struct {
	Username PrefixedClaimOrExpression
	Groups   PrefixedClaimOrExpression
	UID      ClaimOrExpression
	Extra    []ExtraMapping
}

// PrefixedClaimOrExpression provides the configuration for a single prefixed claim or expression.
type PrefixedClaimOrExpression struct {
	Claim  string
	Prefix *string

	Expression string
}

// ClaimOrExpression provides the configuration for a single claim or expression.
type ClaimOrExpression struct {
	Claim      string
	Expression string
}

// ExtraMapping provides the configuration for a single extra mapping.
type ExtraMapping struct {
	Key             string
	ValueExpression string
}

// UserValidationRule provides the configuration for a single user validation rule.
type UserValidationRule struct {
	Expression string
	Message    string
}

// ExternalClaimsSource provides the configuration for a single external claim source.
type ExternalClaimsSource struct {
	// authentication is a required field that configures how the apiserver authenticates with an external claims source.
	// +required
	Authentication *Authentication
	// tls is an optional field that configures the http client TLS
	// settings when fetching external claims from this source.
	// +optional
	TLS *TLS
	// url is a required configuration of the URL
	// for which the external claims are located.
	// +required
	URL *SourceURL
	// mappings is a required list of the claim
	// and response handling expression pairs
	// that produces the claims from the external source.
	// mappings must have at least 1 entry and must not exceed 16 entries.
	// +required
	Mappings []SourcedClaimMapping
	// conditions is an optional list of conditions in
	// which claims should attempt to be fetched from this
	// external source.
	// When omitted, claims are always attempted to be fetched
	// from this external source.
	// When specified, all conditions must evaluate to 'true'
	// before claims are attempted to be fetched from this external source.
	// When specified, conditions must have at least 1 entry and must not
	// exceed 16 entries.
	// +optional
	Conditions []ExternalSourceCondition
}

// TLS configures the TLS options that the apiserver uses as a client
// when making a request to the external claim source.
type TLS struct {
	// certificateAuthority is a required field that configures the certificate authority
	// used to validate TLS connections with the external claims source.
	// Must not be empty and must be a valid PEM-encoded certificate.
	// +required
	CertificateAuthority *string
}

// Authentication configures how the apiserver should attempt to authenticate
// with an external claims source.
type Authentication struct {
	// type is a required field that sets the type of
	// authentication method used by the authenticator
	// when fetching external claims.
	//
	// Allowed values are 'RequestProvidedToken'.
	//
	// When set to 'RequestProvidedToken', the authenticator will
	// use the token provided to the kube-apiserver as part of the
	// request to authenticate with the external claims source.
	// +required
	Type *AuthenticationType
}

// AuthenticationType is the type of authentication that should be used
// when fetching claims from an external source.
type AuthenticationType string

const (
	// AuthenticationTypeRequestProvidedToken is an AuthenticationType
	// that represents that the token being evaluated for authentication
	// should be used for authenticating with the external claims source.
	// This is useful for scenarios where a token has multiple audiences
	// and scopes so that it can be used to access both the cluster and
	// the UserInfo endpoint that contains additional information about the
	// user not present in the token.
	AuthenticationTypeRequestProvidedToken AuthenticationType = "RequestProvidedToken"
)

// SourceURL configures the options used to build the URL that is queried for external claims.
type SourceURL struct {
	// hostname is a required hostname for which the external claims are located.
	// It must be a valid DNS subdomain name as per RFC1123.
	// This means that it must start and end with an alphanumeric character,
	// must only consist of alphanumeric characters, '-', and '.'.
	// hostname must not be an empty string ("") and must not exceed 253 characters in length.
	// +required
	Hostname *string
	// pathExpression is a required CEL expression that returns a list
	// of string values used to construct the URL path.
	// Claims from the token used for the request to the kube-apiserver
	// are made available via the `claims` variable.
	// expression must not be an empty string ("").
	// +required
	PathExpression *string
}

// SourceClaimMapping configures the mapping behavior for a single external claim
// from the response the apiserver received from the external claim source.
type SourcedClaimMapping struct {
	// name is a required name of the claim that
	// will be produced and made available during
	// the claim-to-identity mapping process.
	// name must consist of only alphanumeric characters, '-', '.', and '_'.
	// name must not be an empty string ("") and must not exceed 256 characters in length.
	// +required
	Name *string

	// expression is a required CEL expression that
	// will produce a value to be assigned to the claim.
	// The full response body from the request to the
	// external claim source is provided via the
	// `response` variable.
	// expression must not be an empty string ("").
	// +required
	Expression *string
}

// ExternalSourceCondition configures a singular condition
// that must return true before the external source is queried
// to retrieve external claims.
type ExternalSourceCondition struct {
	// expression is a required CEL expression that
	// is used to determine whether or not an external
	// source should be used to fetch external claims.
	// The expression must return a boolean value,
	// where true means that the source should be consulted
	// and false means that it should not.
	// Claims from the token used for the request to the kube-apiserver
	// are made available via the `claims` variable.
	// expression must not be an empty string ("").
	// +required
	Expression *string
}
