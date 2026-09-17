package resolver

import (
	"context"
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

	"github.com/openshift/library-go/pkg/network/httptransport"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
	externaloidccel "github.com/openshift/oauth-apiserver/pkg/externaloidc/cel"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/klog/v2"

	k8soidc "k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

var _ k8soidc.ClaimsExpander = (*externalClaimsResolver)(nil)

type Compiler interface {
	CompileClaimsExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error)
	CompileExternalSourceExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error)
}

func New(compiler Compiler, accessTokenGetter AccessTokenGetter, source authentication.ExternalClaimsSource, proxyCAContentProvider ...dynamiccertificates.CAContentProvider) (*externalClaimsResolver, error) {
	httpClient, err := httpClientForTLSConfig(source.TLS, proxyCAContentProvider...)
	if err != nil {
		return nil, fmt.Errorf("building http client for external source: %w", err)
	}

	externalSourceCELMapper, err := buildExternalSourceCELMapper(compiler, source.URL, source.Mappings, source.Conditions)
	if err != nil {
		return nil, fmt.Errorf("building external source CEL mapper: %w", err)
	}

	return &externalClaimsResolver{
		source: externalClaimsSource{
			accessTokenGetter: accessTokenGetter,
			httpClient:        httpClient,
			mapper:            externalSourceCELMapper,
		},
	}, nil
}

// TODO: Is 500 milliseconds reasonable? Prove this out through testing and update as necessary.
// Using 500 milliseconds means that we can make 10 requests to external sources before we
// end up hitting 5 seconds, which is half the default Kubernetes API server timeout (10s) for
// requests made to a webhook authenticator.
// 10 requests to external sources is a significant amount of buffer room for something
// that we expect to be used sparingly and leaves at least 5 seconds for the rest
// of the claim mapping logic to execute, which should be plenty of time.
const externalSourceRequestTimeout = 500 * time.Millisecond

func httpClientForTLSConfig(tlsCfg *authentication.TLS, proxyCAContentProvider ...dynamiccertificates.CAContentProvider) (*http.Client, error) {
	client := &http.Client{
		Timeout: externalSourceRequestTimeout,
	}

	var opts []httptransport.Option
	if tlsCfg != nil && tlsCfg.CertificateAuthority != nil && len(*tlsCfg.CertificateAuthority) > 0 {
		opts = append(opts, httptransport.WithCAData("external claims source CA", []byte(*tlsCfg.CertificateAuthority)))
	}
	for _, provider := range proxyCAContentProvider {
		if provider != nil {
			opts = append(opts, httptransport.WithCAContentProvider(provider))
		}
	}

	transport, err := httptransport.NewRoundTripper(opts...)
	if err != nil {
		return nil, err
	}

	client.Transport = transport
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

	return externaloidccel.NewExternalClaimsMapper(compilationResults...), nil
}

type AccessTokenGetter interface {
	GetAccessToken(context.Context) (string, error)
}

type externalClaimsSource struct {
	accessTokenGetter AccessTokenGetter
	mapper            *externaloidccel.ExternalSourceCELMapper
	httpClient        *http.Client
}

type externalClaimsResolver struct {
	source externalClaimsSource
}

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
	// Before anything, first evaluate whether or not the sourcing conditions are met
	shouldSource, err := evaluateConditionsWithClaims(ctx, c, ecr.source.mapper.Conditions)
	if err != nil {
		klog.Errorf("external claims resolver: could not evaluate conditions for external source: %v", err)
		return nil
	}
	if !shouldSource {
		return nil
	}

	accessToken, err := ecr.source.accessTokenGetter.GetAccessToken(ctx)
	if err != nil {
		klog.Errorf("external claims resolver: could not get access token for external source: %v", err)
		return nil
	}

	url, err := getURLWithClaims(ctx, c, ecr.source.mapper.URL)
	if err != nil {
		klog.Errorf("external claims resolver: could not resolve URL for external source: %v", err)
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		klog.Errorf("external claims resolver: building external claims request: %v", err)
		return nil
	}

	if accessToken != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	}

	resp, err := ecr.source.httpClient.Do(req)
	if err != nil {
		klog.Errorf("external claims resolver: performing external claims request: %v", err)
		return nil
	}

	if resp == nil {
		return nil
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		klog.Errorf("external claims resolver: received a %d status code when fetching external claims", resp.StatusCode)
		return nil
	}

	externalClaims, err := getClaimsFromResponse(ctx, resp, ecr.source.mapper.Sources)
	if err != nil {
		klog.Errorf("external claims resolver: getting claims from response: %v", err)
		return nil
	}

	// NOTE: Performing a copy intentionally overwrites existing claim
	// information in the token. While there are some tradeoffs associated
	// with this, the general expectation is that end-users will use this functionality
	// with the intention of fetching claims that are not present in the tokens they
	// issue.
	// There may be valid use cases where admins want to intentionally override
	// claims within a token, so we make this known to admins that write the
	// configuration and let them make the decision for how they handle this.
	// Admins can use the sourcing conditions configuration option as a guard
	// against accidentally doing this.
	maps.Copy(c, externalClaims)

	return nil
}

func UnknownCELValueTypesToStringListHandler() k8soidc.UnknownCELValueTypesToStringListFunc {
	return func(val any) ([]string, bool, error) {
		switch val := val.(type) {
		case []string:
			return val, true, nil
		default:
			return nil, false, nil
		}
	}
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
	pathVals, err := k8soidc.ConvertCELValueToStringList(evaluationResults.EvalResult, UnknownCELValueTypesToStringListHandler())
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
	// TODO: Because we have not gone through comprehensive testing here, we do not
	// realistically know what a reasonable response size limit for us to expect from
	// external sources are.
	// As part of performance testing, we should keep an eye on memory usage
	// impacts of common and uncommon scenarios based on the known
	// feedback we have.
	// Once we have a data-backed foundation for what a reasonable maximum response size
	// for our use case, we can move this to an io.LimitReader.
	responseBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	var respBodyInput any
	err = json.Unmarshal(responseBodyBytes, &respBodyInput)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response body: %w", err)
	}

	input := map[string]any{
		"body": respBodyInput,
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
