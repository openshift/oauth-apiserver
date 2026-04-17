package externalclaims

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	externaloidccel "github.com/openshift/oauth-apiserver/pkg/externaloidc/cel"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/klog/v2"

	k8soidc "k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

var _ k8soidc.ClaimsExpander = (*externalClaimsResolver)(nil)

type Compiler interface {
	CompileClaimsExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error)
	CompileExternalSourceExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error)
}

func NewClaimsResolver(compiler Compiler, externalClaimSource ...authentication.ExternalClaimsSource) (*externalClaimsResolver, error) {
	externalSources := []externalClaimsSource{}
	for _, source := range externalClaimSource {
		httpClient, err := httpClientForTLSConfig(source.TLS)
		if err != nil {
			return nil, fmt.Errorf("building http client for external source: %w", err)
		}

		externalSourceCELMapper, err := buildExternalSourceCELMapper(compiler, source.URL, source.Mappings, source.Conditions)
		if err != nil {
			return nil, fmt.Errorf("building external source CEL mapper: %w", err)
		}

		accessTokenGetter := buildAccessTokenGetter(source.Authentication)

		externalSources = append(externalSources, externalClaimsSource{
			accessTokenGetter: accessTokenGetter,
			httpClient:        httpClient,
			mapper:            externalSourceCELMapper,
		})
	}

	return &externalClaimsResolver{
		sources: externalSources,
	}, nil
}

func buildAccessTokenGetter(auth *authentication.Authentication) accessTokenGetter {
	if auth == nil || auth.Type == nil {
		return nil
	}

	switch *auth.Type {
	case authentication.AuthenticationTypeRequestProvidedToken:
		return &RequestProvidedAccessTokenGetter{}
	default:
		return nil
	}
}

func httpClientForTLSConfig(tlsCfg *authentication.TLS) (*http.Client, error) {
	client := &http.Client{
		Timeout: externalSourceRequestTimeout,
	}

	if tlsCfg == nil || tlsCfg.CertificateAuthority == nil || len(*tlsCfg.CertificateAuthority) == 0 {
		return client, nil
	}

	caCertPool := x509.NewCertPool()

	if ok := caCertPool.AppendCertsFromPEM([]byte(*tlsCfg.CertificateAuthority)); !ok {
		return nil, fmt.Errorf("certificate authority does not contain any valid PEM certificates")
	}

	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caCertPool,
			MinVersion: tls.VersionTLS12,
		},
	}

	return client, nil
}

func buildExternalSourceCELMapper(compiler Compiler, sourceURL *authentication.SourceURL, sourceMappings []authentication.SourcedClaimMapping, sourceConditions []authentication.ExternalSourceCondition) (*externaloidccel.ExternalSourceCELMapper, error) {
	urlMapper, err := buildURLMapperFromSourceURL(compiler, sourceURL)
	if err != nil {
		return nil, fmt.Errorf("building external claims url mapper: %w", err)
	}

	externalClaimsMapper, err := buildExternalClaimsMapperFromSourcedClaimMappings(compiler, sourceMappings...)
	if err != nil {
		return nil, fmt.Errorf("building external claims response mapper: %w", err)
	}

	conditionsMapper, err := buildExternalSourceConditionMapperFromConditions(compiler, sourceConditions)
	if err != nil {
		return nil, fmt.Errorf("building external claims conditions mapper: %w", err)
	}

	return &externaloidccel.ExternalSourceCELMapper{
		URL:        urlMapper,
		Sources:    externalClaimsMapper,
		Conditions: conditionsMapper,
	}, nil
}

func buildExternalSourceConditionMapperFromConditions(compiler Compiler, sourceConditions []authentication.ExternalSourceCondition) (authenticationcel.ClaimsMapper, error) {
	compilationResults := []authenticationcel.CompilationResult{}
	for _, condition := range sourceConditions {
		if condition.Expression == nil {
			// This should never happen because configuration validation prevents this, but if it does skip building this condition.
			continue
		}

		accessor := externaloidccel.ExternalSourceConditionExpression{
			Expression: *condition.Expression,
		}
		compiled, err := compiler.CompileClaimsExpression(&accessor)
		if err != nil {
			return nil, fmt.Errorf("compiling condition %q: %w", *condition.Expression, err)
		}

		compilationResults = append(compilationResults, compiled)
	}

	return authenticationcel.NewClaimsMapper(compilationResults), nil
}

func buildURLMapperFromSourceURL(compiler Compiler, sourceURL *authentication.SourceURL) (authenticationcel.ClaimsMapper, error) {
	if sourceURL == nil {
		return nil, errors.New("sourceURL is nil")
	}

	if sourceURL.Hostname == nil {
		return nil, errors.New("sourceURL.hostname is nil")
	}

	if sourceURL.PathExpression == nil {
		return nil, errors.New("sourceURL.pathExpression is nil")
	}

	pathExpressionAccessor := &externaloidccel.ExternalSourceURLExpression{
		Hostname:       *sourceURL.Hostname,
		PathExpression: *sourceURL.PathExpression,
	}
	compiledPathExpression, err := compiler.CompileClaimsExpression(pathExpressionAccessor)
	if err != nil {
		return nil, fmt.Errorf("compiling path expression: %w", err)
	}

	return authenticationcel.NewClaimsMapper([]authenticationcel.CompilationResult{compiledPathExpression}), nil
}

func buildExternalClaimsMapperFromSourcedClaimMappings(compiler Compiler, sourcedClaimMappings ...authentication.SourcedClaimMapping) (externaloidccel.ExternalClaimsMapper, error) {
	compilationResults := []authenticationcel.CompilationResult{}
	for _, sourcedClaimMapping := range sourcedClaimMappings {
		if sourcedClaimMapping.Name == nil || sourcedClaimMapping.Expression == nil {
			// This should never happen because configuration validation prevents this, but if it does skip building this mapping.
			continue
		}
		expressionAccessor := &externaloidccel.ExternalSourceMappingExpression{
			Claim:      *sourcedClaimMapping.Name,
			Expression: *sourcedClaimMapping.Expression,
		}
		compiledExpression, err := compiler.CompileExternalSourceExpression(expressionAccessor)
		if err != nil {
			return nil, fmt.Errorf("compiling sourced claim mapping for claim %q: %w", *sourcedClaimMapping.Name, err)
		}

		compilationResults = append(compilationResults, compiledExpression)
	}

	return externaloidccel.NewExternalClaimsMapper(compilationResults), nil
}

type accessTokenGetter interface {
	GetAccessToken(context.Context) (string, error)
}

type externalClaimsSource struct {
	accessTokenGetter accessTokenGetter
	mapper            *externaloidccel.ExternalSourceCELMapper
	httpClient        *http.Client
}

type externalClaimsResolver struct {
	sources []externalClaimsSource
}

// TODO: Is 500 milliseconds reasonable? Prove this out through testing and update as necessary.
// Using 500 milliseconds means that we can make 10 requests to external sources before we
// end up hitting 5 seconds, which is half the default Kubernetes API server timeout (10s) for
// requests made to a webhook authenticator.
// 10 requests to external sources is a significant amount of buffer room for something
// that we expect to be used sparingly and leaves at least 5 seconds for the rest
// of the claim mapping logic to execute, which should be plenty of time.
const externalSourceRequestTimeout = 500 * time.Millisecond

// ExpandClaims attempts to expand the claims made available to the claim mappings that are
// used to construct a cluster identity by fetching additional claims from
// sources external to the JWT.
// If it is unable to successfully expand claims for an external source, those claims
// will not be present, and no error will be returned. Errors are logged.
// Errors are not returned by this method because partial evaluation of external
// claim sources is preferred over failing so that authentication is not
// entirely dependent upon the availability of the external sources (although
// authentication may be in a degraded state if external sources are unavailable).
// This method only has an error return value to satisfy the k8soidc.ClaimsExpander interface.
func (ecr *externalClaimsResolver) ExpandClaims(ctx context.Context, c k8soidc.ClaimsMap) error {
	for _, source := range ecr.sources {
		// Before anything, first evaluate whether or not the sourcing conditions are met
		shouldSource, err := evaluateConditionsWithClaims(ctx, c, source.mapper.Conditions)
		if err != nil {
			klog.Errorf("external claims resolver: could not evaluate conditions for external source: %v", err)
			continue
		}
		if !shouldSource {
			continue
		}

		var accessToken string
		if source.accessTokenGetter != nil {
			token, err := source.accessTokenGetter.GetAccessToken(ctx)
			if err != nil {
				klog.Errorf("external claims resolver: getting access token for external source: %v", err)
			}

			accessToken = token
		}

		url, err := getURLWithClaims(ctx, c, source.mapper.URL)
		if err != nil {
			klog.Errorf("external claims resolver: could not resolve URL for external source: %v", err)
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			klog.Errorf("external claims resolver: building external claims request: %v", err)
			continue
		}

		if accessToken != "" {
			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		}

		resp, err := source.httpClient.Do(req)
		if err != nil {
			klog.Errorf("external claims resolver: performing external claims request: %v", err)
			continue
		}

		if resp == nil {
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			klog.Errorf("external claims resolver: received a %d status code when fetching external claims", resp.StatusCode)
			continue
		}

		externalClaims, err := getClaimsFromResponse(ctx, resp, source.mapper.Sources)
		resp.Body.Close()
		if err != nil {
			klog.Errorf("external claims resolver: getting claims from response: %v", err)
			continue
		}

		maps.Copy(c, externalClaims)
	}

	return nil
}

func evaluateConditionsWithClaims(ctx context.Context, c k8soidc.ClaimsMap, claimsMapper authenticationcel.ClaimsMapper) (bool, error) {
	evalResults, err := claimsMapper.EvalClaimMappings(ctx, k8soidc.NewClaimsValue(c))
	if err != nil {
		return false, fmt.Errorf("evaluating sourcing conditions: %w", err)
	}

	for _, result := range evalResults {
		if result.EvalResult.Type() != cel.BoolType {
			return false, fmt.Errorf("evaluating sourcing conditions: %w", fmt.Errorf("sourcing conditions must return a boolean, but got %v", result.EvalResult.Type()))
		}

		satisfied, ok := result.EvalResult.Value().(bool)
		if !ok {
			return false, fmt.Errorf("could not convert type %T to bool", result.EvalResult.Value())
		}

		// If any condition is not satisfied, the external source should not be consulted.
		if !satisfied {
			return false, nil
		}
	}

	// if we made it here, no conditions evaluated to false
	return true, nil
}

func getURLWithClaims(ctx context.Context, c k8soidc.ClaimsMap, urlMapper authenticationcel.ClaimsMapper) (string, error) {
	evaluationResults, err := urlMapper.EvalClaimMapping(ctx, k8soidc.NewClaimsValue(c))
	if err != nil {
		return "", fmt.Errorf("oidc: error evaluating path expression: %w", err)
	}

	if evaluationResults.EvalResult.Type().TypeName() != cel.ListType(cel.DynType).TypeName() {
		return "", fmt.Errorf("oidc: error evaluating path expression: %w", fmt.Errorf("path expression must return a list, but got %v", evaluationResults.EvalResult.Type()))
	}

	path := ""
	pathVals, err := k8soidc.ConvertCELValueToStringList(evaluationResults.EvalResult)
	if err != nil {
		return "", fmt.Errorf("converting result to string list: %w", err)
	}
	for _, val := range pathVals {
		path, err = url.JoinPath(path, url.PathEscape(val))
		if err != nil {
			return "", fmt.Errorf("oidc: error building url path: %w", err)
		}
	}

	urlExpressionAccessor, ok := evaluationResults.ExpressionAccessor.(*externaloidccel.ExternalSourceURLExpression)
	if !ok {
		return "", fmt.Errorf("oidc: error getting url hostname: invalid type conversion, expected ExternalSourceURLExpression")
	}

	urlStr := fmt.Sprintf("https://%s/%s", urlExpressionAccessor.Hostname, path)

	return urlStr, nil
}

func getClaimsFromResponse(ctx context.Context, resp *http.Response, sourcedClaimsMapper externaloidccel.ExternalClaimsMapper) (k8soidc.ClaimsMap, error) {
	responseBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	input := map[string]any{}
	err = json.Unmarshal(responseBodyBytes, &input)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response body: %w", err)
	}

	evalResults, err := sourcedClaimsMapper.EvalExternalClaims(ctx, types.NewStringInterfaceMap(types.DefaultTypeAdapter, input))
	if err != nil {
		return nil, fmt.Errorf("evaluating external source mappings: %w", err)
	}

	externalClaims := k8soidc.ClaimsMap{}
	for _, result := range evalResults {
		sourceMappingExpressionAccessor, ok := result.ExpressionAccessor.(*externaloidccel.ExternalSourceMappingExpression)
		if !ok {
			return nil, fmt.Errorf("invalid type conversion, expected ExternalSourceMappingExpression")
		}

		if result.EvalResult.Type() != cel.StringType {
			return nil, fmt.Errorf("error evaluating external claim mapping %q: %w", sourceMappingExpressionAccessor.Claim, errors.New("expected a string return type"))
		}

		externalClaims[sourceMappingExpressionAccessor.Claim] = json.RawMessage(fmt.Sprintf("%q", result.EvalResult.Value().(string)))
	}

	return externalClaims, nil
}
