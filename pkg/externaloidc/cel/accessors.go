package cel

import (
	"context"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/traits"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

type ExternalClaimsMapper interface {
	// EvalExternalClaim evaluates the given external claim and returns an EvaluationResult.
	// This is used for external claim source validation that contains a single external claim.
	EvalExternalClaim(context.Context, traits.Mapper) (authenticationcel.EvaluationResult, error)

	// EvalExternalClaims evaluates the given external claims and returns a list of EvaluationResult.
	// This is used for external claim source validation that contains multiple external claims.
	EvalExternalClaims(context.Context, traits.Mapper) ([]authenticationcel.EvaluationResult, error)
}

var _ authenticationcel.ExpressionAccessor = &ExternalSourceMappingExpression{}

type ExternalSourceMappingExpression struct {
	Claim      string
	Expression string
}

// GetExpression returns the CEL expression.
func (v *ExternalSourceMappingExpression) GetExpression() string {
	return v.Expression
}

// ReturnTypes returns the CEL expression return types.
func (v *ExternalSourceMappingExpression) ReturnTypes() []*celgo.Type {
	// return types is only used for validation. The response variable that's available
	// to the external source expressions is a map[string]interface{}, so we can't
	// really know what the return type is during compilation. Strict type checking
	// is done during evaluation to ensure that it is a string.
	return []*celgo.Type{celgo.AnyType}
}

var _ authenticationcel.ExpressionAccessor = &ExternalSourceURLExpression{}

type ExternalSourceURLExpression struct {
	Hostname       string
	PathExpression string
}

// GetExpression returns the CEL expression.
func (v *ExternalSourceURLExpression) GetExpression() string {
	return v.PathExpression
}

// ReturnTypes returns the CEL expression return types.
func (v *ExternalSourceURLExpression) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.AnyType}
}

var _ authenticationcel.ExpressionAccessor = &ExternalSourceConditionExpression{}

type ExternalSourceConditionExpression struct {
	Expression string
}

// GetExpression returns the CEL expression.
func (v *ExternalSourceConditionExpression) GetExpression() string {
	return v.Expression
}

// ReturnTypes returns the CEL expression return types.
func (v *ExternalSourceConditionExpression) ReturnTypes() []*celgo.Type {
	return []*celgo.Type{celgo.BoolType}
}
