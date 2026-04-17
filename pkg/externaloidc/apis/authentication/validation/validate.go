package validation

import (
	"fmt"
	"regexp"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication/conversion"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/cel"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/oidc"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
)

func ValidateAuthenticationConfiguration(compiler oidc.Compiler, c *authentication.AuthenticationConfiguration) field.ErrorList {
	errors := field.ErrorList{}

	root := field.NewPath("jwt")

	// Unlike the kube-apiserver, we require that there be at least one authenticator defined.
	if len(c.JWT) == 0 {
		errors = append(errors, field.Required(root, "jwt is required and must not be empty"))
	}

	// defer to kube-apiserver validation before validating our custom fields
	errors = append(errors, validation.ValidateAuthenticationConfiguration(compiler, conversion.ConvertAuthenticationConfigurationToApiserverAuthenticationConfiguration(c), nil)...)

	// Now validate our custom fields
	for i, jwt := range c.JWT {
		errors = append(errors, validateExternalClaimsSources(compiler, jwt.ExternalClaimsSources, root.Index(i).Child("externalClaimsSources"))...)
	}

	return errors
}

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
	allErrs = append(allErrs, validateExternalClaimsSourceTLS(compiler, source.TLS, path.Child("tls"))...)
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

func validateExternalClaimsSourceURLPathExpression(compiler oidc.Compiler, pathExpression *string, path *field.Path) field.ErrorList {
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

const maxExternalSourceConditions = 16

func validateExternalClaimsSourceConditions(compiler oidc.Compiler, externalSourceConditions []authentication.ExternalSourceCondition, path *field.Path) field.ErrorList {
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

func validateExternalSourceCondition(compiler oidc.Compiler, condition authentication.ExternalSourceCondition, seenConditions sets.Set[string], path *field.Path) field.ErrorList {
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

	allErrs = append(allErrs, validateExternalClaimsSourceMappingName(sourcedClaimMapping.Name, seenExternalClaimNames, path.Child("name"))...)
	allErrs = append(allErrs, validateExternalClaimsSourceMappingExpression(compiler, sourcedClaimMapping.Expression, path.Child("expression"))...)

	return allErrs
}

func validateExternalClaimsSourceMappingExpression(compiler oidc.Compiler, expression *string, path *field.Path) field.ErrorList {
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

const maxSourceMappingNameLength = 256

func validateExternalClaimsSourceMappingName(name *string, seenExternalClaimNames sets.Set[string], path *field.Path) field.ErrorList {
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

func validateExternalClaimsSourceTLS(compiler oidc.Compiler, tls *authentication.TLS, path *field.Path) field.ErrorList {
	if tls == nil {
		return nil
	}

	if tls.CertificateAuthority == nil {
		return field.ErrorList{field.Required(path.Child("certificateAuthority"), "certificateAuthority is required")}
	}

	if len(*tls.CertificateAuthority) < 1 {
		return field.ErrorList{field.Invalid(path.Child("certificateAuthority"), *tls.CertificateAuthority, "certificateAuthority must not be empty and must be a valid PEM-encoded certificate")}
	}

	return validation.ValidateCertificateAuthority(*tls.CertificateAuthority, path.Child("certificateAuthority"))
}

func validateExternalClaimsSourceAuthentication(authn *authentication.Authentication, path *field.Path) field.ErrorList {
	if authn == nil {
		return nil
	}

	allowedTypes := sets.New(authentication.AuthenticationTypeRequestProvidedToken)
	if authn.Type == nil {
		return field.ErrorList{field.Required(path.Child("type"), fmt.Sprintf("type is required and must be one of %v", sets.List(allowedTypes)))}
	}

	if !allowedTypes.Has(*authn.Type) {
		return field.ErrorList{field.Invalid(path.Child("type"), *authn.Type, fmt.Sprintf("type must be one of %v", sets.List(allowedTypes)))}
	}

	return nil
}
