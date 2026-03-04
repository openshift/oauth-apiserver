package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/thirdparty/kubernetes/apiserver/pkg/apis/apiserver"
	authenticationcel "github.com/openshift/oauth-apiserver/pkg/externaloidc/internal/thirdparty/kubernetes/apiserver/pkg/authentication/cel"
	"k8s.io/klog/v2"
)

type ExternalClaimsCompatibleCompiler interface {
	CompileExternalSourceExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error)
}

func NewExternalClaimsResolver(compiler authenticationcel.Compiler, externalClaimSource ...apiserver.ExternalClaimsSource) (*externalClaimsResolver, error) {
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

		externalSources = append(externalSources, externalClaimsSource{
			clientAuthentication: clientAuthenticationForAuthentication(source.Authentication),
			httpClient:           httpClient,
			mapper:               externalSourceCELMapper,
		})
	}

	return &externalClaimsResolver{
		sources: externalSources,
	}, nil
}

func httpClientForTLSConfig(tlsCfg *apiserver.TLS) (*http.Client, error) {
	client := &http.Client{
		Timeout: externalSourceRequestTimeout,
	}

	if tlsCfg == nil || tlsCfg.CertificateAuthority == nil || len(*tlsCfg.CertificateAuthority) == 0 {
		return client, nil
	}

	caCertPool := x509.NewCertPool()

	block, _ := pem.Decode([]byte(*tlsCfg.CertificateAuthority))

	if block == nil {
		return nil, errors.New("ca certificate has no block")
	}

	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, errors.New("ca certificate is not a CERTIFICATE type")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	if cert == nil {
		return nil, errors.New("parsed ca certificate is nil")
	}

	caCertPool.AddCert(cert)

	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}

	return client, nil
}

func buildExternalSourceCELMapper(compiler authenticationcel.Compiler, sourceURL *apiserver.SourceURL, sourceMappings []apiserver.SourcedClaimMapping, sourceConditions []apiserver.ExternalSourceCondition) (*authenticationcel.ExternalSourceCELMapper, error) {
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

	return &authenticationcel.ExternalSourceCELMapper{
		URL:        urlMapper,
		Sources:    externalClaimsMapper,
		Conditions: conditionsMapper,
	}, nil
}

func buildExternalSourceConditionMapperFromConditions(compiler authenticationcel.Compiler, sourceConditions []apiserver.ExternalSourceCondition) (authenticationcel.ClaimsMapper, error) {
	compilationResults := []authenticationcel.CompilationResult{}
	for _, condition := range sourceConditions {
		if condition.Expression == nil {
			// This should never happen because configuration validation prevents this, but if it does skip building this condition.
			continue
		}

		accessor := authenticationcel.ExternalSourceConditionExpression{
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

func buildURLMapperFromSourceURL(compiler authenticationcel.Compiler, sourceURL *apiserver.SourceURL) (authenticationcel.ClaimsMapper, error) {
	if sourceURL == nil {
		return nil, errors.New("sourceURL is nil")
	}

	if sourceURL.Hostname == nil {
		return nil, errors.New("sourceURL.hostname is nil")
	}

	if sourceURL.PathExpression == nil {
		return nil, errors.New("sourceURL.pathExpression is nil")
	}

	pathExpressionAccessor := &authenticationcel.ExternalSourceURLExpression{
		Hostname:       *sourceURL.Hostname,
		PathExpression: *sourceURL.PathExpression,
	}
	compiledPathExpression, err := compiler.CompileClaimsExpression(pathExpressionAccessor)
	if err != nil {
		return nil, fmt.Errorf("compiling path expression: %w", err)
	}

	return authenticationcel.NewClaimsMapper([]authenticationcel.CompilationResult{compiledPathExpression}), nil
}

func buildExternalClaimsMapperFromSourcedClaimMappings(compiler authenticationcel.Compiler, sourcedClaimMappings ...apiserver.SourcedClaimMapping) (authenticationcel.ExternalClaimsMapper, error) {
	compilationResults := []authenticationcel.CompilationResult{}
	for _, sourcedClaimMapping := range sourcedClaimMappings {
		if sourcedClaimMapping.Name == nil || sourcedClaimMapping.Expression == nil {
			// This should never happen because configuration validation prevents this, but if it does skip building this mapping.
			continue
		}
		expressionAccessor := &authenticationcel.ExternalSourceMappingExpression{
			Claim:      *sourcedClaimMapping.Name,
			Expression: *sourcedClaimMapping.Expression,
		}
		compiledExpression, err := compiler.CompileExternalSourceExpression(expressionAccessor)
		if err != nil {
			return nil, fmt.Errorf("compiling sourced claim mapping for claim %q: %w", *sourcedClaimMapping.Name, err)
		}

		compilationResults = append(compilationResults, compiledExpression)
	}

	return authenticationcel.NewExternalClaimsMapper(compilationResults), nil
}

func clientAuthenticationForAuthentication(authn *apiserver.Authentication) clientAuthentication {
	if authn == nil || authn.Type == nil {
		return clientAuthentication{}
	}

	switch *authn.Type {
	case apiserver.AuthenticationTypeRequestProvidedToken:
		return clientAuthentication{
			Type: apiserver.AuthenticationTypeRequestProvidedToken,
		}
	}

	return clientAuthentication{}
}

type clientAuthentication struct {
	Type             apiserver.AuthenticationType
	clientCredential clientCredential
	accessToken      string
}

type clientCredential struct {
	id            string
	secret        string
	tokenEndpoint string
}

type externalClaimsSource struct {
	clientAuthentication clientAuthentication
	mapper               *authenticationcel.ExternalSourceCELMapper
	httpClient           *http.Client
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

// expand attempts to expand the claims made available to the claim mappings that are
// used to construct a cluster identity by fetching additional claims from
// sources external to the JWT.
// If it is unable to successfully expand claims for an external source, those claims
// will not be present, and no error will be returned. Errors are logged.
// Errors are not returned by this method because partial evaluation of external
// claim sources is preferred over failing so that authentication is not
// entirely dependent upon the availability of the external sources (although
// authentication may be in a degraded state if external sources are unavailable).
func (ecr *externalClaimsResolver) expand(ctx context.Context, token string, c claims) {
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
		if source.clientAuthentication.Type == apiserver.AuthenticationTypeRequestProvidedToken {
			accessToken = token
		}

		url, err := getURLWithClaims(ctx, c, source.mapper.URL)
		if err != nil {
			klog.Errorf("external claims resolver: could not resolve URL for external source: %v", err)
			continue
		}

		req, err := http.NewRequest(http.MethodGet, url, nil)
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
			responseBody, _ := io.ReadAll(resp.Body)
			klog.Errorf("external claims resolver: received a %d status code when fetching external claims: response body: %s ", resp.StatusCode, string(responseBody))
			continue
		}
		externalClaims, err := getClaimsFromResponse(ctx, resp, source.mapper.Sources)
		if err != nil {
			klog.Errorf("external claims resolver: getting claims from response: %v", err)
			continue
		}

		maps.Copy(c, externalClaims)
	}
}

func evaluateConditionsWithClaims(ctx context.Context, c claims, claimsMapper authenticationcel.ClaimsMapper) (bool, error) {
	evalResults, err := claimsMapper.EvalClaimMappings(ctx, newClaimsValue(c))
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

func getURLWithClaims(ctx context.Context, c claims, urlMapper authenticationcel.ClaimsMapper) (string, error) {
	evaluationResults, err := urlMapper.EvalClaimMapping(ctx, newClaimsValue(c))
	if err != nil {
		return "", fmt.Errorf("oidc: error evaluating path expression: %w", err)
	}

	if evaluationResults.EvalResult.Type().TypeName() != cel.ListType(cel.DynType).TypeName() {
		return "", fmt.Errorf("oidc: error evaluating path expression: %w", fmt.Errorf("path expression must return a list, but got %v", evaluationResults.EvalResult.Type()))
	}

	pathSegmentsVal := evaluationResults.EvalResult.Value()

	refVals, ok := pathSegmentsVal.([]ref.Val)
	if !ok {
		return "", fmt.Errorf("could not convert output type %T to list of values", pathSegmentsVal)
	}

	path := ""
	for _, val := range refVals {
		str, ok := val.Value().(string)
		if !ok {
			return "", fmt.Errorf("could not convert list element type %T to string", val.Value())
		}

		path, err = url.JoinPath(path, url.PathEscape(str))
		if err != nil {
			return "", fmt.Errorf("oidc: error building url path: %w", err)
		}
	}

	urlExpressionAccessor, ok := evaluationResults.ExpressionAccessor.(*authenticationcel.ExternalSourceURLExpression)
	if !ok {
		return "", fmt.Errorf("oidc: error getting url hostname: invalid type conversion, expected ExternalSourceURLExpression")
	}

	urlStr := fmt.Sprintf("https://%s/%s", urlExpressionAccessor.Hostname, path)

	return urlStr, nil
}

func getClaimsFromResponse(ctx context.Context, resp *http.Response, sourcedClaimsMapper authenticationcel.ExternalClaimsMapper) (claims, error) {
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

	externalClaims := claims{}
	for _, result := range evalResults {
		sourceMappingExpressionAccessor, ok := result.ExpressionAccessor.(*authenticationcel.ExternalSourceMappingExpression)
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
