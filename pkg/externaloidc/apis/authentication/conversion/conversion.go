package conversion

import (
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"k8s.io/apiserver/pkg/apis/apiserver"
)

// ConvertAuthenticationConfigurationToApiserverAuthenticationConfiguration converts an authentication.AuthenticationConfiguration to its apiserver.AuthenticationConfiguration equivalent.
// This is useful for re-using existing kube-apiserver package logic for token authentication.
func ConvertAuthenticationConfigurationToApiserverAuthenticationConfiguration(in *authentication.AuthenticationConfiguration) *apiserver.AuthenticationConfiguration {
	out := &apiserver.AuthenticationConfiguration{}

	if in == nil {
		return out
	}

	apiserverJWTs := []apiserver.JWTAuthenticator{}

	for _, authenticator := range in.JWT {
		apiserverJWTs = append(apiserverJWTs, ConvertAuthenticatorToApiserverJWTAuthenticator(authenticator))
	}

	out.JWT = apiserverJWTs

	return out
}

// ConvertAuthenticatorToApiserverJWTAuthenticator converts an authentication.Authenticator to its apiserver.JWTAuthenticator equivalent.
// This is useful for re-using existing kube-apiserver package logic for token authentication.
func ConvertAuthenticatorToApiserverJWTAuthenticator(in authentication.Authenticator) apiserver.JWTAuthenticator {
	out := apiserver.JWTAuthenticator{}
	out.Issuer = ConvertIssuerToApiserverIssuer(in.Issuer)
	out.ClaimMappings = ConvertClaimMappingsToApiserverClaimMappings(in.ClaimMappings)
	out.ClaimValidationRules = ConvertClaimValidationRulesToApiserverClaimValidationRules(in.ClaimValidationRules)
	out.UserValidationRules = ConvertUserValidationRulesToApiserverUserValidationRules(in.UserValidationRules)

	return out
}

// ConvertIssuerToApiserverIssuer converts an *authentication.Issuer to its apiserver.Issuer equivalent.
func ConvertIssuerToApiserverIssuer(issuer *authentication.Issuer) apiserver.Issuer {
	if issuer == nil {
		return apiserver.Issuer{}
	}

	out := apiserver.Issuer{
		URL:                  issuer.URL,
		CertificateAuthority: issuer.CertificateAuthority,
		Audiences:            issuer.Audiences,
		AudienceMatchPolicy:  apiserver.AudienceMatchPolicyType(issuer.AudienceMatchPolicy),
	}

	if issuer.DiscoveryURL != nil {
		out.DiscoveryURL = *issuer.DiscoveryURL
	}

	return out
}

// ConvertClaimMappingsToApiserverClaimMappings converts an *authentication.ClaimMappings to its apiserver.ClaimMappings equivalent.
func ConvertClaimMappingsToApiserverClaimMappings(claimMappings *authentication.ClaimMappings) apiserver.ClaimMappings {
	out := apiserver.ClaimMappings{}

	if claimMappings == nil {
		return out
	}

	out.Username = ConvertPrefixedClaimOrExpressionToApiserverPrefixedClaimOrExpression(claimMappings.Username)
	out.Groups = ConvertPrefixedClaimOrExpressionToApiserverPrefixedClaimOrExpression(claimMappings.Groups)
	out.UID = ConvertClaimOrExpressionToApiserverClaimOrExpression(claimMappings.UID)
	out.Extra = ConvertExtraMappingsToApiserverExtraMappings(claimMappings.Extra)

	return out
}

// ConvertPrefixedClaimOrExpressionToApiserverPrefixedClaimOrExpression converts an authentication.PrefixedClaimOrExpression to its apiserver.PrefixedClaimOrExpression equivalent.
func ConvertPrefixedClaimOrExpressionToApiserverPrefixedClaimOrExpression(prefixedClaimOrExpression authentication.PrefixedClaimOrExpression) apiserver.PrefixedClaimOrExpression {
	return apiserver.PrefixedClaimOrExpression{
		Claim:      prefixedClaimOrExpression.Claim,
		Expression: prefixedClaimOrExpression.Expression,
		Prefix:     prefixedClaimOrExpression.Prefix,
	}
}

// ConvertClaimOrExpressionToApiserverClaimOrExpression converts an authentication.ClaimOrExpression to its apiserver.ClaimOrExpression equivalent.
func ConvertClaimOrExpressionToApiserverClaimOrExpression(claimOrExpression authentication.ClaimOrExpression) apiserver.ClaimOrExpression {
	return apiserver.ClaimOrExpression{
		Claim:      claimOrExpression.Claim,
		Expression: claimOrExpression.Expression,
	}
}

// ConvertExtraMappingsToApiserverExtraMappings converts an []authentication.ExtraMapping to its []apiserver.ExtraMapping equivalent.
func ConvertExtraMappingsToApiserverExtraMappings(extraMappings []authentication.ExtraMapping) []apiserver.ExtraMapping {
	out := []apiserver.ExtraMapping{}

	for _, extraMapping := range extraMappings {
		out = append(out, apiserver.ExtraMapping{
			Key:             extraMapping.Key,
			ValueExpression: extraMapping.ValueExpression,
		})
	}

	return out
}

// ConvertClaimValidationRulesToApiserverClaimValidationRules converts an []authentication.ClaimValidationRule to its []apiserver.ClaimValidationRule equivalent.
func ConvertClaimValidationRulesToApiserverClaimValidationRules(claimValidationRules []authentication.ClaimValidationRule) []apiserver.ClaimValidationRule {
	out := []apiserver.ClaimValidationRule{}

	for _, rule := range claimValidationRules {
		out = append(out, apiserver.ClaimValidationRule{
			Claim:         rule.Claim,
			RequiredValue: rule.RequiredValue,
			Expression:    rule.Expression,
			Message:       rule.Message,
		})
	}

	return out
}

// ConvertUserValidationRulesToApiserverUserValidationRules converts an []authentication.UserValidationRules to its []apiserver.UserValidationRules equivalent.
func ConvertUserValidationRulesToApiserverUserValidationRules(userValidationRules []authentication.UserValidationRule) []apiserver.UserValidationRule {
	out := []apiserver.UserValidationRule{}

	for _, rule := range userValidationRules {
		out = append(out, apiserver.UserValidationRule{
			Expression: rule.Expression,
			Message:    rule.Message,
		})
	}

	return out
}
