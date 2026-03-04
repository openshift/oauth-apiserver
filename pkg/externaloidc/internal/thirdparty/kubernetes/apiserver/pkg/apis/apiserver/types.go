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
