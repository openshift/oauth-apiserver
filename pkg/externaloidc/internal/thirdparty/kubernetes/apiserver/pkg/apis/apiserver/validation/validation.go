/*
* NOTE: This file was copied from https://github.com/kubernetes/kubernetes
* based on commit https://github.com/kubernetes/kubernetes/commit/a1478c77301cb7fe17e5369eae9aeaa943b10155
*
* This is so that we can make modifications as necessary to support additional functionality
* in our external OIDC webhook implementation that is not supported by the Kubernetes
* API server, like sourcing claims from external sources.
*
* Modifications to this file will be tracked as separate commits that follow our
* standard patch commit structure of UPSTREAM: <carry>: {message}.
 */
/*
Copyright 2023 The Kubernetes Authors.

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

package validation

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/operators"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	api "github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver"
	authenticationcel "github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/thirdparty/kubernetes/apiserver/pkg/authentication/cel"
	"k8s.io/apimachinery/pkg/util/sets"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/cel"
	"k8s.io/client-go/util/cert"
)

// ValidateAuthenticationConfiguration validates a given AuthenticationConfiguration.
func ValidateAuthenticationConfiguration(compiler authenticationcel.Compiler, c *api.AuthenticationConfiguration, disallowedIssuers []string) field.ErrorList {
	root := field.NewPath("jwt")
	var allErrs field.ErrorList

	// We allow 0 authenticators in the authentication configuration.
	// This allows us to support scenarios where the API server is initially set up without
	// any authenticators and then authenticators are added later via dynamic config.

	if len(c.JWT) > 64 {
		allErrs = append(allErrs, field.TooMany(root, len(c.JWT), 64))
		return allErrs
	}

	seenIssuers := sets.New[string]()
	seenDiscoveryURLs := sets.New[string]()
	for i, a := range c.JWT {
		fldPath := root.Index(i)
		_, errs := validateJWTAuthenticator(compiler, a, fldPath, sets.New(disallowedIssuers...))
		allErrs = append(allErrs, errs...)

		if seenIssuers.Has(a.Issuer.URL) {
			allErrs = append(allErrs, field.Duplicate(fldPath.Child("issuer").Child("url"), a.Issuer.URL))
		}
		seenIssuers.Insert(a.Issuer.URL)

		if len(a.Issuer.DiscoveryURL) > 0 {
			if seenDiscoveryURLs.Has(a.Issuer.DiscoveryURL) {
				allErrs = append(allErrs, field.Duplicate(fldPath.Child("issuer").Child("discoveryURL"), a.Issuer.DiscoveryURL))
			}
			seenDiscoveryURLs.Insert(a.Issuer.DiscoveryURL)
		}
	}

	return allErrs
}

// CompileAndValidateJWTAuthenticator validates a given JWTAuthenticator and returns a CELMapper with the compiled
// CEL expressions for claim mappings and validation rules.
// This is exported for use in oidc package.
func CompileAndValidateJWTAuthenticator(compiler authenticationcel.Compiler, authenticator api.JWTAuthenticator, disallowedIssuers []string) (authenticationcel.CELMapper, field.ErrorList) {
	return validateJWTAuthenticator(compiler, authenticator, nil, sets.New(disallowedIssuers...))
}

func validateJWTAuthenticator(compiler authenticationcel.Compiler, authenticator api.JWTAuthenticator, fldPath *field.Path, disallowedIssuers sets.Set[string]) (authenticationcel.CELMapper, field.ErrorList) {
	var allErrs field.ErrorList

	state := &validationState{}

	allErrs = append(allErrs, validateIssuer(authenticator.Issuer, disallowedIssuers, fldPath.Child("issuer"))...)
	allErrs = append(allErrs, validateClaimValidationRules(compiler, state, authenticator.ClaimValidationRules, fldPath.Child("claimValidationRules"))...)
	allErrs = append(allErrs, validateClaimMappings(compiler, state, authenticator.ClaimMappings, fldPath.Child("claimMappings"))...)
	allErrs = append(allErrs, validateUserValidationRules(compiler, state, authenticator.UserValidationRules, fldPath.Child("userValidationRules"))...)
	allErrs = append(allErrs, validateExternalClaimsSources(compiler, authenticator.ExternalClaimsSources, fldPath.Child("externalClaimsSources"))...)

	return state.mapper, allErrs
}

type validationState struct {
	mapper                 authenticationcel.CELMapper
	usesEmailClaim         bool
	usesEmailVerifiedClaim bool
}

func validateIssuer(issuer api.Issuer, disallowedIssuers sets.Set[string], fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	allErrs = append(allErrs, validateIssuerURL(issuer.URL, disallowedIssuers, fldPath.Child("url"))...)
	allErrs = append(allErrs, validateIssuerDiscoveryURL(issuer.URL, issuer.DiscoveryURL, fldPath.Child("discoveryURL"))...)
	allErrs = append(allErrs, validateAudiences(issuer.Audiences, issuer.AudienceMatchPolicy, fldPath.Child("audiences"), fldPath.Child("audienceMatchPolicy"))...)
	allErrs = append(allErrs, validateCertificateAuthority(issuer.CertificateAuthority, fldPath.Child("certificateAuthority"))...)

	return allErrs
}

func validateIssuerURL(issuerURL string, disallowedIssuers sets.Set[string], fldPath *field.Path) field.ErrorList {
	if len(issuerURL) == 0 {
		return field.ErrorList{field.Required(fldPath, "")}
	}

	return validateURL(issuerURL, disallowedIssuers, fldPath)
}

func validateIssuerDiscoveryURL(issuerURL, issuerDiscoveryURL string, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if len(issuerDiscoveryURL) == 0 {
		return nil
	}

	if len(issuerURL) > 0 && strings.TrimRight(issuerURL, "/") == strings.TrimRight(issuerDiscoveryURL, "/") {
		allErrs = append(allErrs, field.Invalid(fldPath, issuerDiscoveryURL, "discoveryURL must be different from URL"))
	}

	// issuerDiscoveryURL is not an issuer URL and does not need to validated against any set of disallowed issuers
	allErrs = append(allErrs, validateURL(issuerDiscoveryURL, nil, fldPath)...)
	return allErrs
}

func validateURL(issuerURL string, disallowedIssuers sets.Set[string], fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if disallowedIssuers.Has(issuerURL) {
		allErrs = append(allErrs, field.Invalid(fldPath, issuerURL, fmt.Sprintf("URL must not overlap with disallowed issuers: %s", sets.List(disallowedIssuers))))
	}

	u, err := url.Parse(issuerURL)
	if err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, issuerURL, err.Error()))
		return allErrs
	}
	if u.Scheme != "https" {
		allErrs = append(allErrs, field.Invalid(fldPath, issuerURL, "URL scheme must be https"))
	}
	if u.User != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, issuerURL, "URL must not contain a username or password"))
	}
	if len(u.RawQuery) > 0 {
		allErrs = append(allErrs, field.Invalid(fldPath, issuerURL, "URL must not contain a query"))
	}
	if len(u.Fragment) > 0 {
		allErrs = append(allErrs, field.Invalid(fldPath, issuerURL, "URL must not contain a fragment"))
	}

	return allErrs
}

// Copied from https://github.com/kubernetes/kubernetes/blob/7ea5b88209020a07cc96717c6e8cb622feebdd4a/staging/src/k8s.io/apiserver/pkg/apis/apiserver/validation/validation_encryption.go#L37
const (
	atLeastOneRequiredErrFmt = "at least one %s is required"
)

func validateAudiences(audiences []string, audienceMatchPolicy api.AudienceMatchPolicyType, fldPath, audienceMatchPolicyFldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if len(audiences) == 0 {
		allErrs = append(allErrs, field.Required(fldPath, fmt.Sprintf(atLeastOneRequiredErrFmt, fldPath)))
		return allErrs
	}

	seenAudiences := sets.NewString()
	for i, audience := range audiences {
		fldPath := fldPath.Index(i)
		if len(audience) == 0 {
			allErrs = append(allErrs, field.Required(fldPath, ""))
		}
		if seenAudiences.Has(audience) {
			allErrs = append(allErrs, field.Duplicate(fldPath, audience))
		}
		seenAudiences.Insert(audience)
	}

	if len(audiences) > 1 && audienceMatchPolicy != api.AudienceMatchPolicyMatchAny {
		allErrs = append(allErrs, field.Invalid(audienceMatchPolicyFldPath, audienceMatchPolicy, "audienceMatchPolicy must be MatchAny for multiple audiences"))
	}
	if len(audiences) == 1 && (len(audienceMatchPolicy) > 0 && audienceMatchPolicy != api.AudienceMatchPolicyMatchAny) {
		allErrs = append(allErrs, field.Invalid(audienceMatchPolicyFldPath, audienceMatchPolicy, "audienceMatchPolicy must be empty or MatchAny for single audience"))
	}

	return allErrs
}

func validateCertificateAuthority(certificateAuthority string, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	if len(certificateAuthority) == 0 {
		return allErrs
	}
	_, err := cert.NewPoolFromBytes([]byte(certificateAuthority))
	if err != nil {
		allErrs = append(allErrs, field.Invalid(fldPath, "<omitted>", err.Error()))
	}

	return allErrs
}

func validateClaimValidationRules(compiler authenticationcel.Compiler, state *validationState, rules []api.ClaimValidationRule, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	seenClaims := sets.NewString()
	seenExpressions := sets.NewString()
	var compilationResults []authenticationcel.CompilationResult

	for i, rule := range rules {
		fldPath := fldPath.Index(i)

		switch {
		case len(rule.Claim) > 0 && len(rule.Expression) > 0:
			allErrs = append(allErrs, field.Invalid(fldPath, rule.Claim, "claim and expression can't both be set"))
		case len(rule.Claim) == 0 && len(rule.Expression) == 0:
			allErrs = append(allErrs, field.Required(fldPath, "claim or expression is required"))
		case len(rule.Claim) > 0:
			if len(rule.Message) > 0 {
				allErrs = append(allErrs, field.Invalid(fldPath.Child("message"), rule.Message, "may not be specified when claim is set"))
			}
			if seenClaims.Has(rule.Claim) {
				allErrs = append(allErrs, field.Duplicate(fldPath.Child("claim"), rule.Claim))
			}
			seenClaims.Insert(rule.Claim)
		case len(rule.Expression) > 0:
			if len(rule.RequiredValue) > 0 {
				allErrs = append(allErrs, field.Invalid(fldPath.Child("requiredValue"), rule.RequiredValue, "may not be specified when expression is set"))
			}
			if seenExpressions.Has(rule.Expression) {
				allErrs = append(allErrs, field.Duplicate(fldPath.Child("expression"), rule.Expression))
				continue
			}
			seenExpressions.Insert(rule.Expression)

			compilationResult, err := compileClaimsCELExpression(compiler, &authenticationcel.ClaimValidationCondition{
				Expression: rule.Expression,
				Message:    rule.Message,
			}, fldPath.Child("expression"))
			if err != nil {
				allErrs = append(allErrs, err)
				continue
			}
			if compilationResult != nil {
				compilationResults = append(compilationResults, *compilationResult)
			}
		}
	}

	if len(compilationResults) > 0 {
		state.mapper.ClaimValidationRules = authenticationcel.NewClaimsMapper(compilationResults)
		state.usesEmailVerifiedClaim = state.usesEmailVerifiedClaim || anyUsesEmailVerifiedClaim(compilationResults)
	}

	return allErrs
}

func validateClaimMappings(compiler authenticationcel.Compiler, state *validationState, m api.ClaimMappings, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	compilationResult, err := validatePrefixClaimOrExpression(compiler, m.Username, fldPath.Child("username"), true)
	if err != nil {
		allErrs = append(allErrs, err...)
	} else if compilationResult != nil {
		state.usesEmailClaim = state.usesEmailClaim || usesEmailClaim(compilationResult.AST)
		state.usesEmailVerifiedClaim = state.usesEmailVerifiedClaim || usesEmailVerifiedClaim(compilationResult.AST)
		state.mapper.Username = authenticationcel.NewClaimsMapper([]authenticationcel.CompilationResult{*compilationResult})
	}

	compilationResult, err = validatePrefixClaimOrExpression(compiler, m.Groups, fldPath.Child("groups"), false)
	if err != nil {
		allErrs = append(allErrs, err...)
	} else if compilationResult != nil {
		state.mapper.Groups = authenticationcel.NewClaimsMapper([]authenticationcel.CompilationResult{*compilationResult})
	}

	switch {
	case len(m.UID.Claim) > 0 && len(m.UID.Expression) > 0:
		allErrs = append(allErrs, field.Invalid(fldPath.Child("uid"), "", "claim and expression can't both be set"))
	case len(m.UID.Expression) > 0:
		compilationResult, err := compileClaimsCELExpression(compiler, &authenticationcel.ClaimMappingExpression{
			Expression: m.UID.Expression,
		}, fldPath.Child("uid").Child("expression"))

		if err != nil {
			allErrs = append(allErrs, err)
		} else if compilationResult != nil {
			state.mapper.UID = authenticationcel.NewClaimsMapper([]authenticationcel.CompilationResult{*compilationResult})
		}
	}

	var extraCompilationResults []authenticationcel.CompilationResult
	seenExtraKeys := sets.NewString()

	for i, mapping := range m.Extra {
		fldPath := fldPath.Child("extra").Index(i)
		// Key should be namespaced to the authenticator or authenticator/authorizer pair making use of them.
		// For instance: "example.org/foo" instead of "foo".
		// xref: https://github.com/kubernetes/kubernetes/blob/3825e206cb162a7ad7431a5bdf6a065ae8422cf7/staging/src/k8s.io/apiserver/pkg/authentication/user/user.go#L31-L41
		// IsDomainPrefixedPath checks for non-empty key and that the key is prefixed with a domain name.
		allErrs = append(allErrs, utilvalidation.IsDomainPrefixedPath(fldPath.Child("key"), mapping.Key)...)
		if mapping.Key != strings.ToLower(mapping.Key) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("key"), mapping.Key, "must be lowercase"))
		}

		if isKubernetesDomainPrefix(mapping.Key) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("key"), mapping.Key, "k8s.io, kubernetes.io and their subdomains are reserved for Kubernetes use"))
		}

		if seenExtraKeys.Has(mapping.Key) {
			allErrs = append(allErrs, field.Duplicate(fldPath.Child("key"), mapping.Key))
			continue
		}
		seenExtraKeys.Insert(mapping.Key)

		if len(mapping.ValueExpression) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("valueExpression"), ""))
			continue
		}

		compilationResult, err := compileClaimsCELExpression(compiler, &authenticationcel.ExtraMappingExpression{
			Key:        mapping.Key,
			Expression: mapping.ValueExpression,
		}, fldPath.Child("valueExpression"))
		if err != nil {
			allErrs = append(allErrs, err)
			continue
		}

		if compilationResult != nil {
			extraCompilationResults = append(extraCompilationResults, *compilationResult)
		}
	}

	if len(extraCompilationResults) > 0 {
		state.mapper.Extra = authenticationcel.NewClaimsMapper(extraCompilationResults)
		state.usesEmailVerifiedClaim = state.usesEmailVerifiedClaim || anyUsesEmailVerifiedClaim(extraCompilationResults)
	}

	if state.usesEmailClaim && !state.usesEmailVerifiedClaim {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("username", "expression"), m.Username.Expression,
			"claims.email_verified must be used in claimMappings.username.expression or claimMappings.extra[*].valueExpression or claimValidationRules[*].expression when claims.email is used in claimMappings.username.expression"))
	}

	return allErrs
}

func isKubernetesDomainPrefix(key string) bool {
	domainPrefix := getDomainPrefix(key)
	if domainPrefix == "kubernetes.io" || strings.HasSuffix(domainPrefix, ".kubernetes.io") {
		return true
	}
	if domainPrefix == "k8s.io" || strings.HasSuffix(domainPrefix, ".k8s.io") {
		return true
	}
	return false
}

func getDomainPrefix(key string) string {
	if parts := strings.SplitN(key, "/", 2); len(parts) == 2 {
		return parts[0]
	}
	return ""
}

func usesEmailClaim(ast *celgo.Ast) bool {
	return hasSelectExp(ast.Expr(), "claims", "email")
}

func anyUsesEmailVerifiedClaim(results []authenticationcel.CompilationResult) bool {
	for _, result := range results {
		if usesEmailVerifiedClaim(result.AST) {
			return true
		}
	}
	return false
}

func usesEmailVerifiedClaim(ast *celgo.Ast) bool {
	return hasSelectExp(ast.Expr(), "claims", "email_verified")
}

func hasSelectExp(exp *exprpb.Expr, operand, field string) bool {
	if exp == nil {
		return false
	}
	switch e := exp.ExprKind.(type) {
	case *exprpb.Expr_ConstExpr,
		*exprpb.Expr_IdentExpr:
		return false
	case *exprpb.Expr_SelectExpr:
		s := e.SelectExpr
		if s == nil {
			return false
		}
		if isIdentOperand(s.Operand, operand) && s.Field == field {
			return true
		}
		return hasSelectExp(s.Operand, operand, field)
	case *exprpb.Expr_CallExpr:
		c := e.CallExpr
		if c == nil {
			return false
		}
		if c.Target == nil && c.Function == operators.OptSelect && len(c.Args) == 2 &&
			isIdentOperand(c.Args[0], operand) && isConstField(c.Args[1], field) {
			return true
		}
		for _, arg := range c.Args {
			if hasSelectExp(arg, operand, field) {
				return true
			}
		}
		return hasSelectExp(c.Target, operand, field)
	case *exprpb.Expr_ListExpr:
		l := e.ListExpr
		if l == nil {
			return false
		}
		for _, element := range l.Elements {
			if hasSelectExp(element, operand, field) {
				return true
			}
		}
		return false
	case *exprpb.Expr_StructExpr:
		s := e.StructExpr
		if s == nil {
			return false
		}
		for _, entry := range s.Entries {
			if hasSelectExp(entry.GetMapKey(), operand, field) {
				return true
			}
			if hasSelectExp(entry.Value, operand, field) {
				return true
			}
		}
		return false
	case *exprpb.Expr_ComprehensionExpr:
		c := e.ComprehensionExpr
		if c == nil {
			return false
		}
		return hasSelectExp(c.IterRange, operand, field) ||
			hasSelectExp(c.AccuInit, operand, field) ||
			hasSelectExp(c.LoopCondition, operand, field) ||
			hasSelectExp(c.LoopStep, operand, field) ||
			hasSelectExp(c.Result, operand, field)
	default:
		return false
	}
}

func isIdentOperand(exp *exprpb.Expr, operand string) bool {
	if len(operand) == 0 {
		return false // sanity check against default values
	}
	id := exp.GetIdentExpr() // does not panic even if exp is nil
	return id != nil && id.Name == operand
}

func isConstField(exp *exprpb.Expr, field string) bool {
	if len(field) == 0 {
		return false // sanity check against default values
	}
	c := exp.GetConstExpr()                        // does not panic even if exp is nil
	return c != nil && c.GetStringValue() == field // does not panic even if c is not a string
}

func validatePrefixClaimOrExpression(compiler authenticationcel.Compiler, mapping api.PrefixedClaimOrExpression, fldPath *field.Path, claimOrExpressionRequired bool) (*authenticationcel.CompilationResult, field.ErrorList) {
	var allErrs field.ErrorList

	var compilationResult *authenticationcel.CompilationResult
	switch {
	case len(mapping.Expression) > 0 && len(mapping.Claim) > 0:
		allErrs = append(allErrs, field.Invalid(fldPath, "", "claim and expression can't both be set"))
	case len(mapping.Expression) == 0 && len(mapping.Claim) == 0 && claimOrExpressionRequired:
		allErrs = append(allErrs, field.Required(fldPath, "claim or expression is required"))
	case len(mapping.Expression) > 0:
		var err *field.Error

		if mapping.Prefix != nil {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("prefix"), *mapping.Prefix, "may not be specified when expression is set"))
		}
		compilationResult, err = compileClaimsCELExpression(compiler, &authenticationcel.ClaimMappingExpression{
			Expression: mapping.Expression,
		}, fldPath.Child("expression"))
		if err != nil {
			allErrs = append(allErrs, err)
		}

	case len(mapping.Claim) > 0:
		if mapping.Prefix == nil {
			allErrs = append(allErrs, field.Required(fldPath.Child("prefix"), "prefix is required when claim is set. It can be set to an empty string to disable prefixing"))
		}
	}

	return compilationResult, allErrs
}

func validateUserValidationRules(compiler authenticationcel.Compiler, state *validationState, rules []api.UserValidationRule, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	var compilationResults []authenticationcel.CompilationResult

	seenExpressions := sets.NewString()
	for i, rule := range rules {
		fldPath := fldPath.Index(i)

		if len(rule.Expression) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("expression"), ""))
			continue
		}

		if seenExpressions.Has(rule.Expression) {
			allErrs = append(allErrs, field.Duplicate(fldPath.Child("expression"), rule.Expression))
			continue
		}
		seenExpressions.Insert(rule.Expression)

		compilationResult, err := compileUserCELExpression(compiler, &authenticationcel.UserValidationCondition{
			Expression: rule.Expression,
			Message:    rule.Message,
		}, fldPath.Child("expression"))
		if err != nil {
			allErrs = append(allErrs, err)
			continue
		}

		if compilationResult != nil {
			compilationResults = append(compilationResults, *compilationResult)
		}
	}

	if len(compilationResults) > 0 {
		state.mapper.UserValidationRules = authenticationcel.NewUserMapper(compilationResults)
	}

	return allErrs
}

func compileClaimsCELExpression(compiler authenticationcel.Compiler, expression authenticationcel.ExpressionAccessor, fldPath *field.Path) (*authenticationcel.CompilationResult, *field.Error) {
	compilationResult, err := compiler.CompileClaimsExpression(expression)
	if err != nil {
		return nil, convertCELErrorToValidationError(fldPath, expression.GetExpression(), err)
	}
	return &compilationResult, nil
}

func compileUserCELExpression(compiler authenticationcel.Compiler, expression authenticationcel.ExpressionAccessor, fldPath *field.Path) (*authenticationcel.CompilationResult, *field.Error) {
	compilationResult, err := compiler.CompileUserExpression(expression)
	if err != nil {
		return nil, convertCELErrorToValidationError(fldPath, expression.GetExpression(), err)
	}
	return &compilationResult, nil
}

func convertCELErrorToValidationError(fldPath *field.Path, expression string, err error) *field.Error {
	var celErr *cel.Error
	if errors.As(err, &celErr) {
		switch celErr.Type {
		case cel.ErrorTypeRequired:
			return field.Required(fldPath, celErr.Detail)
		case cel.ErrorTypeInvalid:
			return field.Invalid(fldPath, expression, celErr.Detail)
		default:
			return field.InternalError(fldPath, celErr)
		}
	}
	return field.InternalError(fldPath, fmt.Errorf("error is not cel error: %w", err))
}

const maxExternalClaimSources = 5

func validateExternalClaimsSources(compiler authenticationcel.Compiler, externalClaimsSources []api.ExternalClaimsSource, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	seenExternalClaimNames := sets.New[string]()

	if len(externalClaimsSources) > maxExternalClaimSources {
		allErrs = append(allErrs, field.TooMany(fldPath, len(externalClaimsSources), maxExternalClaimSources))
	}

	for i, source := range externalClaimsSources {
		allErrs = append(allErrs, validateExternalClaimsSource(compiler, source, seenExternalClaimNames, fldPath.Index(i))...)
	}

	return allErrs
}

func validateExternalClaimsSource(compiler authenticationcel.Compiler, source api.ExternalClaimsSource, seenExternalClaimNames sets.Set[string], path *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateExternalClaimsSourceAuthentication(source.Authentication, path.Child("authentication"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceTLS(compiler, source.TLS, path.Child("tls"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceMappings(compiler, source.Mappings, seenExternalClaimNames, path.Child("mappings"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceConditions(compiler, source.Conditions, path.Child("conditions"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceURL(compiler, source.URL, path.Child("url"))...)

	return allErrs
}

func validateExternalClaimsSourceURL(compiler authenticationcel.Compiler, sourceURL *api.SourceURL, path *field.Path) field.ErrorList {
	if sourceURL == nil {
		return field.ErrorList{field.Required(path, "url is required")}
	}

	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateExternalClaimsSourceURLHostname(sourceURL.Hostname, path.Child("hostname"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceURLPathExpression(compiler, sourceURL.PathExpression, path.Child("pathExpression"))...)

	return allErrs
}

const (
	dns1123LabelFmt     string = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"
	dns1123SubdomainFmt string = dns1123LabelFmt + "(\\." + dns1123LabelFmt + ")*"
	optionalPortFmt     string = "(:(\\d{1,5}))?"
)

var rfc1123HostnameWithPortRegex = regexp.MustCompile("^" + dns1123SubdomainFmt + optionalPortFmt + "$")

func validateExternalClaimsSourceURLHostname(hostname *string, path *field.Path) field.ErrorList {
	if hostname == nil {
		return field.ErrorList{field.Required(path, "hostname is required")}
	}

	if len(*hostname) < 1 {
		return field.ErrorList{field.Invalid(path, *hostname, "hostname must not be an empty string")}
	}

	if !rfc1123HostnameWithPortRegex.MatchString(*hostname) {
		return field.ErrorList{field.Invalid(path, *hostname, "hostname must be a valid RFC1123 subdomain name (start/end with a lowercase alphanumeric character and only contain lowercase alphanumeric characters, '-', and '.'), optionally followed by a port.")}
	}

	return nil
}

func validateExternalClaimsSourceURLPathExpression(compiler authenticationcel.Compiler, pathExpression *string, path *field.Path) field.ErrorList {
	if pathExpression == nil {
		return field.ErrorList{field.Required(path, "pathExpression is required")}
	}

	if len(*pathExpression) < 1 {
		return field.ErrorList{field.Invalid(path, *pathExpression, "pathExpression must not be an empty string")}
	}

	_, err := compiler.CompileClaimsExpression(&authenticationcel.ExternalSourceURLExpression{
		PathExpression: *pathExpression,
	})
	if err != nil {
		return field.ErrorList{field.Invalid(path.Child("pathExpression"), *pathExpression, fmt.Sprintf("error compiling expression: %v", err))}
	}

	return nil
}

const maxExternalSourceConditions = 16

func validateExternalClaimsSourceConditions(compiler authenticationcel.Compiler, externalSourceConditions []api.ExternalSourceCondition, path *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(externalSourceConditions) > maxExternalSourceConditions {
		allErrs = append(allErrs, field.TooMany(path, len(externalSourceConditions), maxExternalSourceConditions))
	}

	seenConditions := sets.New[string]()

	for i, condition := range externalSourceConditions {
		allErrs = append(allErrs, validateExternalSourceCondition(compiler, condition, seenConditions, path.Index(i))...)
	}

	return allErrs
}

func validateExternalSourceCondition(compiler authenticationcel.Compiler, condition api.ExternalSourceCondition, seenConditions sets.Set[string], path *field.Path) field.ErrorList {
	if condition.Expression == nil {
		return field.ErrorList{field.Required(path.Child("expression"), "expression is required")}
	}

	if len(*condition.Expression) < 1 {
		return field.ErrorList{field.Invalid(path.Child("expression"), *condition.Expression, "expression must not be an empty string")}
	}

	if seenConditions.Has(*condition.Expression) {
		return field.ErrorList{field.Duplicate(path.Child("expression"), *condition.Expression)}
	}

	seenConditions.Insert(*condition.Expression)

	_, err := compiler.CompileClaimsExpression(&authenticationcel.ExternalSourceMappingExpression{
		Expression: *condition.Expression,
	})
	if err != nil {
		return field.ErrorList{field.Invalid(path.Child("expression"), *condition.Expression, fmt.Sprintf("error compiling expression: %v", err))}
	}

	return nil
}

const maxSourcedClaimMappings = 16

func validateExternalClaimsSourceMappings(compiler authenticationcel.Compiler, sourcedClaimMappings []api.SourcedClaimMapping, seenExternalClaimNames sets.Set[string], path *field.Path) field.ErrorList {
	if len(sourcedClaimMappings) == 0 {
		return field.ErrorList{field.Required(path, "mappings is required and must not be an empty list.")}
	}

	allErrs := field.ErrorList{}

	if len(sourcedClaimMappings) > maxSourcedClaimMappings {
		allErrs = append(allErrs, field.TooMany(path, len(sourcedClaimMappings), maxSourcedClaimMappings))
	}

	for i, mapping := range sourcedClaimMappings {
		allErrs = append(allErrs, validateExternalClaimsSourceMapping(compiler, mapping, seenExternalClaimNames, path.Index(i))...)
	}

	return allErrs
}

func validateExternalClaimsSourceMapping(compiler authenticationcel.Compiler, sourcedClaimMapping api.SourcedClaimMapping, seenExternalClaimNames sets.Set[string], path *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateExternalClaimsSourceMappingName(sourcedClaimMapping.Name, seenExternalClaimNames, path.Child("name"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceMappingExpression(compiler, sourcedClaimMapping.Expression, path.Child("expression"))...)

	return allErrs
}

func validateExternalClaimsSourceMappingExpression(compiler authenticationcel.Compiler, expression *string, path *field.Path) field.ErrorList {
	if expression == nil {
		return field.ErrorList{field.Required(path, "expression is required")}
	}

	if len(*expression) < 1 {
		return field.ErrorList{field.Invalid(path, *expression, "expression must not be an empty string")}
	}

	_, err := compiler.CompileExternalSourceExpression(&authenticationcel.ExternalSourceMappingExpression{
		Expression: *expression,
	})
	if err != nil {
		return field.ErrorList{field.Invalid(path, expression, fmt.Sprintf("error compiling expression: %v", err))}
	}

	return nil
}

var nameRegex = regexp.MustCompile("^([a-z_])+$")

const maxSourceMappingNameLength = 256

func validateExternalClaimsSourceMappingName(name *string, seenExternalClaimNames sets.Set[string], path *field.Path) field.ErrorList {
	if name == nil {
		return field.ErrorList{field.Required(path, "name is required")}
	}

	if len(*name) < 1 {
		return field.ErrorList{field.Invalid(path, *name, "name must not be an empty string (\"\")")}
	}

	if !nameRegex.MatchString(*name) {
		return field.ErrorList{field.Invalid(path, name, "name must consist of only lowercase alpha characters and underscores ('_').")}
	}

	if len(*name) > maxSourceMappingNameLength {
		return field.ErrorList{field.TooLong(path, name, maxSourceMappingNameLength)}
	}

	if seenExternalClaimNames.Has(*name) {
		return field.ErrorList{field.Duplicate(path, *name)}
	}

	seenExternalClaimNames.Insert(*name)

	return nil
}

func validateExternalClaimsSourceTLS(compiler authenticationcel.Compiler, tls *api.TLS, path *field.Path) field.ErrorList {
	if tls == nil {
		return nil
	}

	if tls.CertificateAuthority == nil {
		return field.ErrorList{field.Required(path.Child("certificateAuthority"), "certificateAuthority is required")}
	}

	if len(*tls.CertificateAuthority) < 1 {
		return field.ErrorList{field.Invalid(path.Child("certificateAuthority"), *tls.CertificateAuthority, "certificateAuthority must not be empty and must be a valid PEM-encoded certificate")}
	}

	return validateCertificateAuthority(*tls.CertificateAuthority, path.Child("certificateAuthority"))
}

func validateExternalClaimsSourceAuthentication(authentication *api.Authentication, path *field.Path) field.ErrorList {
	if authentication == nil {
		return field.ErrorList{field.Required(path, "authentication is required")}
	}

	allowedTypes := sets.New(api.AuthenticationTypeRequestProvidedToken)
	if authentication.Type == nil {
		return field.ErrorList{field.Required(path.Child("type"), fmt.Sprintf("type is required and must be one of %v", sets.List(allowedTypes)))}
	}

	if !allowedTypes.Has(*authentication.Type) {
		return field.ErrorList{field.Invalid(path.Child("type"), authentication.Type, fmt.Sprintf("type must be one of %v", sets.List(allowedTypes)))}
	}

	return nil
}
