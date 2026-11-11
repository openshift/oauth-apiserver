package validation

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication/conversion"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/cel"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/oidc"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
)

// ValidateAuthenticationConfiguration validates an instance of an *authentication.AuthenticationConfiguration,
// returning any errors it encounters on a field-basis.
func ValidateAuthenticationConfiguration(compiler oidc.Compiler, c *authentication.AuthenticationConfiguration) field.ErrorList {
	errors := field.ErrorList{}

	root := field.NewPath("jwt")

	// Unlike the kube-apiserver, we require that there be at least one authenticator defined.
	if len(c.JWT) == 0 {
		errors = append(errors, field.Required(root, "jwt is required and must not be empty"))
	}

	// defer to kube-apiserver validation
	errors = append(errors,
		validation.ValidateAuthenticationConfiguration(
			compiler,
			conversion.ConvertAuthenticationConfigurationToApiserverAuthenticationConfiguration(c),
			nil,
		)...)

	// Now validate our custom fields
	for i, jwt := range c.JWT {
		errors = append(errors, validateExternalClaimsSources(compiler, jwt.ExternalClaimsSources, root.Index(i).Child("externalClaimsSources"))...)
	}

	// Make sure the trustedCA path is a valid, clean, absolute path.
	if p := c.TrustedCAFilePath; len(p) > 0 {
		switch {
		case !filepath.IsAbs(p):
			errors = append(errors, field.Invalid(field.NewPath("trustedCAFilePath"), p, "must be an absolute filepath"))
		case filepath.Clean(p) != p:
			errors = append(errors, field.Invalid(field.NewPath("trustedCAFilePath"), p, `must not contain duplicate slashes, "." or ".." as path elements`))
		}
	}

	return errors
}

// External claim sources are limited to a maximum of 5 entries to
// limit the number of calls to external sources that can be made
// during the authentication process, reducing the risk
// of authentication failure due to slow responses from external sources.
const maxExternalClaimSources = 5

func validateExternalClaimsSources(compiler oidc.Compiler, externalClaimsSources []authentication.ExternalClaimsSource, fldPath *field.Path) field.ErrorList {
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

func validateExternalClaimsSource(compiler oidc.Compiler, source authentication.ExternalClaimsSource, seenExternalClaimNames sets.Set[string], path *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateExternalClaimsSourceAuthentication(source.Authentication, path.Child("authentication"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceTLS(source.TLS, path.Child("tls"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceMappings(compiler, source.Mappings, seenExternalClaimNames, path.Child("mappings"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceConditions(compiler, source.Conditions, path.Child("conditions"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceURL(compiler, source.URL, path.Child("url"))...)

	return allErrs
}

func validateExternalClaimsSourceURL(compiler oidc.Compiler, sourceURL *authentication.SourceURL, path *field.Path) field.ErrorList {
	if sourceURL == nil {
		return field.ErrorList{field.Required(path, "url is required")}
	}

	allErrs := field.ErrorList{}

	allErrs = append(allErrs, ValidateExternalClaimsSourceURLHostname(sourceURL.Hostname, path.Child("hostname"))...)
	allErrs = append(allErrs, ValidateExternalClaimsSourceURLPathExpression(compiler, sourceURL.PathExpression, path.Child("pathExpression"))...)

	return allErrs
}

const (
	dns1123LabelFmt     string = "[a-z0-9]([-a-z0-9]*[a-z0-9])?"
	dns1123SubdomainFmt string = dns1123LabelFmt + "(\\." + dns1123LabelFmt + ")*"
	optionalPortFmt     string = "(:([1-9]\\d{0,4}))?"
)

var rfc1123HostnameWithPortRegex = regexp.MustCompile("^" + dns1123SubdomainFmt + optionalPortFmt + "$")

// ValidateExternalClaimsSourceURLHostname validates a hostname for an external claims source URL,
// returning any errors assoicated with the hostname field value provided.
func ValidateExternalClaimsSourceURLHostname(hostname *string, path *field.Path) field.ErrorList {
	if hostname == nil {
		return field.ErrorList{field.Required(path, "hostname is required")}
	}

	if len(*hostname) < 1 {
		return field.ErrorList{field.Invalid(path, *hostname, "hostname must not be an empty string")}
	}

	if !rfc1123HostnameWithPortRegex.MatchString(*hostname) {
		return field.ErrorList{field.Invalid(path, *hostname, "hostname must be a valid RFC1123 subdomain name (start/end with a lowercase alphanumeric character and only contain lowercase alphanumeric characters, '-', and '.'), optionally followed by a non-zero port.")}
	}

	u, err := url.Parse(fmt.Sprintf("https://%s", *hostname))
	if err != nil {
		return field.ErrorList{field.Invalid(path, *hostname, fmt.Sprintf("could not parse url with provided hostname: %v", err))}
	}

	if len(u.Port()) > 0 {
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return field.ErrorList{field.Invalid(path, *hostname, fmt.Sprintf("could not parse port of the provided hostname: %v", err))}
		}

		if port > 65535 {
			return field.ErrorList{field.Invalid(path, *hostname, "port of the hostname must not be greater than 65535")}
		}
	}

	return nil
}

// ValidateExternalClaimsSourceURLPathExpression validates a path expression for an external claims source URL,
// returning any errors assoicated with the pathExpression field value provided.
func ValidateExternalClaimsSourceURLPathExpression(compiler oidc.Compiler, pathExpression *string, path *field.Path) field.ErrorList {
	if pathExpression == nil {
		return field.ErrorList{field.Required(path, "pathExpression is required")}
	}

	if len(*pathExpression) < 1 {
		return field.ErrorList{field.Invalid(path, *pathExpression, "pathExpression must not be an empty string")}
	}

	_, err := compiler.CompileClaimsExpression(&cel.ExternalSourceURLExpression{
		PathExpression: *pathExpression,
	})
	if err != nil {
		return field.ErrorList{field.Invalid(path, *pathExpression, fmt.Sprintf("error compiling expression: %v", err))}
	}

	return nil
}

// External sourcing conditions are limited to 16 conditions per
// external source as a mitigation for spending excessive time evaluating
// conditions in which to consult an external source.
const maxExternalSourceConditions = 16

func validateExternalClaimsSourceConditions(compiler oidc.Compiler, externalSourceConditions []authentication.ExternalSourceCondition, path *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if len(externalSourceConditions) > maxExternalSourceConditions {
		allErrs = append(allErrs, field.TooMany(path, len(externalSourceConditions), maxExternalSourceConditions))
	}

	seenConditions := sets.New[string]()

	for i, condition := range externalSourceConditions {
		allErrs = append(allErrs, ValidateExternalSourceCondition(compiler, condition, seenConditions, path.Index(i))...)
	}

	return allErrs
}

// ValidateExternalSourceCondition validates an authentication.ExternalSourceCondition for an external claims source,
// returning any errors assoicated with the condition provided.
func ValidateExternalSourceCondition(compiler oidc.Compiler, condition authentication.ExternalSourceCondition, seenConditions sets.Set[string], path *field.Path) field.ErrorList {
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

	_, err := compiler.CompileClaimsExpression(&cel.ExternalSourceConditionExpression{
		Expression: *condition.Expression,
	})
	if err != nil {
		return field.ErrorList{field.Invalid(path.Child("expression"), *condition.Expression, fmt.Sprintf("error compiling expression: %v", err))}
	}

	return nil
}

// Externally sourced claims are limited to 16 per external source
// as a mitigation for spending excessive time evaluating CEL expressions.
const maxSourcedClaimMappings = 16

func validateExternalClaimsSourceMappings(compiler oidc.Compiler, sourcedClaimMappings []authentication.SourcedClaimMapping, seenExternalClaimNames sets.Set[string], path *field.Path) field.ErrorList {
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

func validateExternalClaimsSourceMapping(compiler oidc.Compiler, sourcedClaimMapping authentication.SourcedClaimMapping, seenExternalClaimNames sets.Set[string], path *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, ValidateExternalClaimsSourceMappingName(sourcedClaimMapping.Name, seenExternalClaimNames, path.Child("name"))...)
	allErrs = append(allErrs, ValidateExternalClaimsSourceMappingExpression(compiler, sourcedClaimMapping.Expression, path.Child("expression"))...)

	return allErrs
}

// ValidateExternalClaimsSourceMappingExpression validates the CEL expression
// used to extract values from the response from an external claims source.
// It returns any errors associated with the expression field.
func ValidateExternalClaimsSourceMappingExpression(compiler oidc.Compiler, expression *string, path *field.Path) field.ErrorList {
	if expression == nil {
		return field.ErrorList{field.Required(path, "expression is required")}
	}

	if len(*expression) < 1 {
		return field.ErrorList{field.Invalid(path, *expression, "expression must not be an empty string")}
	}

	_, err := compiler.CompileExternalSourceExpression(&cel.ExternalSourceMappingExpression{
		Expression: *expression,
	})
	if err != nil {
		return field.ErrorList{field.Invalid(path, *expression, fmt.Sprintf("error compiling expression: %v", err))}
	}

	return nil
}

var nameRegex = regexp.MustCompile("^([a-z_])+$")

// Externally sourced claim names should not exceed 256 characters to
// remain closely in line with general best practices of token claim names.
// Token claims don't have an actually enforced limit, but because tokens
// are included in request headers, it is common practice for claims to have
// very short names. In practice, 256 characters should be sufficiently
// long enough for any reasonably named claim name.
const maxSourceMappingNameLength = 256

// ValidateExternalClaimsSourceMappingName validates the claim name that will be populated
// by an external claims source mappings entry.
// It returns any errors associated with the name field.
func ValidateExternalClaimsSourceMappingName(name *string, seenExternalClaimNames sets.Set[string], path *field.Path) field.ErrorList {
	if name == nil {
		return field.ErrorList{field.Required(path, "name is required")}
	}

	if len(*name) < 1 {
		return field.ErrorList{field.Invalid(path, *name, "name must not be an empty string (\"\")")}
	}

	if !nameRegex.MatchString(*name) {
		return field.ErrorList{field.Invalid(path, *name, "name must consist of only lowercase alpha characters and underscores ('_').")}
	}

	if len(*name) > maxSourceMappingNameLength {
		return field.ErrorList{field.TooLong(path, *name, maxSourceMappingNameLength)}
	}

	if seenExternalClaimNames.Has(*name) {
		return field.ErrorList{field.Duplicate(path, *name)}
	}

	seenExternalClaimNames.Insert(*name)

	return nil
}

func validateExternalClaimsSourceTLS(tls *authentication.TLS, path *field.Path) field.ErrorList {
	if tls == nil {
		return nil
	}

	if tls.IsZero() {
		return field.ErrorList{field.Invalid(path, tls, "at least one field must be set when tls is specified")}
	}

	if tls.CertificateAuthority != nil {
		if len(*tls.CertificateAuthority) < 1 {
			return field.ErrorList{field.Invalid(path.Child("certificateAuthority"), *tls.CertificateAuthority, "certificateAuthority must not be empty when set and must be a valid PEM-encoded certificate")}
		}

		return validation.ValidateCertificateAuthority(*tls.CertificateAuthority, path.Child("certificateAuthority"))
	}

	return nil
}

func validateExternalClaimsSourceAuthentication(authn *authentication.Authentication, path *field.Path) field.ErrorList {
	if authn == nil {
		return nil
	}

	allowedTypes := sets.New(authentication.AuthenticationTypeRequestProvidedToken, authentication.AuthenticationTypeClientCredential)
	if authn.Type == nil {
		return field.ErrorList{field.Required(path.Child("type"), fmt.Sprintf("type is required and must be one of %v", sets.List(allowedTypes)))}
	}

	if !allowedTypes.Has(*authn.Type) {
		return field.ErrorList{field.Invalid(path.Child("type"), *authn.Type, fmt.Sprintf("type must be one of %v", sets.List(allowedTypes)))}
	}

	allErrs := field.ErrorList{}

	switch *authn.Type {
	case authentication.AuthenticationTypeClientCredential:
		allErrs = append(allErrs, validateClientCredentialConfig(authn.ClientCredential, path.Child("clientCredential"))...)
	default:
		// clientCredential must not be set for non-ClientCredential types
		if authn.ClientCredential != nil {
			allErrs = append(allErrs, field.Forbidden(path.Child("clientCredential"), "clientCredential must not be set when type is not ClientCredential"))
		}
	}

	return allErrs
}

func validateClientCredentialConfig(cfg *authentication.ClientCredentialConfig, path *field.Path) field.ErrorList {
	if cfg == nil {
		return field.ErrorList{field.Required(path, "clientCredential is required when type is ClientCredential")}
	}

	allErrs := field.ErrorList{}

	allErrs = append(allErrs, ValidateClientCredentialConfigClientID(cfg.ClientID, path.Child("clientID"))...)
	allErrs = append(allErrs, ValidateClientCredentialConfigClientSecret(cfg.ClientSecret, path.Child("clientSecret"))...)
	allErrs = append(allErrs, ValidateTokenEndpoint(cfg.TokenEndpoint, path.Child("tokenEndpoint"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceTLS(cfg.TLS, path.Child("tls"))...)

	for i, scope := range cfg.Scopes {
		allErrs = append(allErrs, ValidateClientCredentialConfigScope(scope, path.Child("scopes").Index(i))...)
	}

	return allErrs
}

// As documented in https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.4 OAuth2 scope-tokens
// must only consist of printable ascii characters, not including spaces, double quotes, and backslashes.
// Because our API structure uses a list type for specifying the scopes, we do not allow space delimiting
// as a signal of a distinct scope.
// Scope-tokens are documented as 1*NQCHAR, where NQCHAR is equivalent to ( %x21 / %x23-5B / %x5D-7E ).
// %x21 converted to ASCII is the exclamation point character ('!').
// %x23 converted to ASCII is the hash character ('#').
// 5B converted to ASCII is the left bracket character ('[').
// %x5D converted to ASCII is the right bracket character (']').
// 7E converted to ASCII is the tilde character ('~').
//
// The regular expression below ensures that only strings that start, contain, and end with
// characters within these ASCII ranges are considered valid for a scope entry.
var scopeRegex = regexp.MustCompile(`^[!#-[\]-~]+$`)

func ValidateClientCredentialConfigScope(scope string, path *field.Path) field.ErrorList {
	if len(scope) == 0 {
		return field.ErrorList{field.Invalid(path, scope, "scope must not be an empty string")}
	}

	if !scopeRegex.MatchString(scope) {
		return field.ErrorList{field.Invalid(path, scope, "scope must only contain printable ascii characters, not including spaces, double quotes and backslashes")}
	}

	return nil
}

// printableASCIIRegexp matches strings that consist entirely of printable ASCII
// characters (0x20-0x7E) as defined by RFC 6749 Appendix A (VSCHAR = %x20-7E).
var printableASCIIRegexp = regexp.MustCompile(`^[[:print:]]+$`)

func ValidateClientCredentialConfigClientID(clientID string, path *field.Path) field.ErrorList {
	if len(clientID) == 0 {
		return field.ErrorList{field.Required(path, "clientID is required and must not be an empty string")}
	}

	if !printableASCIIRegexp.MatchString(clientID) {
		return field.ErrorList{field.Invalid(path, clientID, "clientID must only contain printable ASCII characters")}
	}

	return nil
}

func ValidateClientCredentialConfigClientSecret(clientSecret string, path *field.Path) field.ErrorList {
	if len(clientSecret) == 0 {
		return field.ErrorList{field.Required(path, "clientSecret is required and must not be an empty string")}
	}

	if !printableASCIIRegexp.MatchString(clientSecret) {
		return field.ErrorList{field.Invalid(path, "<masked>", "clientSecret must only contain printable ASCII characters")}
	}

	return nil
}

func ValidateTokenEndpoint(tokenEndpoint string, path *field.Path) field.ErrorList {
	if len(tokenEndpoint) == 0 {
		return field.ErrorList{field.Required(path, "tokenEndpoint is required and must not be an empty string")}
	}

	u, err := url.Parse(tokenEndpoint)
	if err != nil {
		return field.ErrorList{field.Invalid(path, tokenEndpoint, fmt.Sprintf("tokenEndpoint must be a valid URL: %v", err))}
	}

	allErrs := field.ErrorList{}

	if u.Scheme != "https" {
		allErrs = append(allErrs, field.Invalid(path, tokenEndpoint, "tokenEndpoint must use the https scheme"))
	}

	if u.Host == "" {
		allErrs = append(allErrs, field.Invalid(path, tokenEndpoint, "tokenEndpoint must have a host"))
	}

	if u.Path == "" {
		allErrs = append(allErrs, field.Invalid(path, tokenEndpoint, "tokenEndpoint must have a path"))
	}

	if u.RawQuery != "" {
		allErrs = append(allErrs, field.Invalid(path, tokenEndpoint, "tokenEndpoint must not contain query parameters"))
	}

	if u.Fragment != "" {
		allErrs = append(allErrs, field.Invalid(path, tokenEndpoint, "tokenEndpoint must not contain a fragment"))
	}

	if u.User != nil {
		allErrs = append(allErrs, field.Invalid(path, tokenEndpoint, "tokenEndpoint must not contain user information"))
	}

	return allErrs
}
