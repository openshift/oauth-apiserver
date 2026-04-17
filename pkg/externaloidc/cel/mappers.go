package cel

import (
	"context"
	"fmt"

	"github.com/google/cel-go/common/types/traits"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

// ExternalSourceCELMapper is a struct that holds the compiled expressions
// used when externally sourcing claims.
type ExternalSourceCELMapper struct {
	URL        authenticationcel.ClaimsMapper
	Conditions authenticationcel.ClaimsMapper
	Sources    ExternalClaimsMapper
}

// TODO: exported and extended form of mapper
func NewExternalClaimsMapper(compilationResults []authenticationcel.CompilationResult) ExternalClaimsMapper {
	return &externalClaimsMapper{
		ExportedMapper: authenticationcel.NewExportedMapper(compilationResults),
	}
}

type externalClaimsMapper struct {
	*authenticationcel.ExportedMapper
}

// EvalExternalClaim evaluates the given external claim and returns an EvaluationResult.
// This is used for external claim source validation that contains a single external claim.
func (ecm *externalClaimsMapper) EvalExternalClaim(ctx context.Context, input traits.Mapper) (authenticationcel.EvaluationResult, error) {
	results, err := ecm.ExportedMapper.Eval(ctx, authenticationcel.NewVarNameActivation(responseVarName, input))
	if err != nil {
		return authenticationcel.EvaluationResult{}, err
	}
	if len(results) != 1 {
		return authenticationcel.EvaluationResult{}, fmt.Errorf("expected 1 evaluation result, got %d", len(results))
	}
	return results[0], nil
}

// EvalExternalClaims evaluates the given external claims and returns a list of EvaluationResult.
// This is used for external claim source validation that contains multiple external claims.
func (ecm *externalClaimsMapper) EvalExternalClaims(ctx context.Context, input traits.Mapper) ([]authenticationcel.EvaluationResult, error) {
	return ecm.ExportedMapper.Eval(ctx, authenticationcel.NewVarNameActivation(responseVarName, input))
}
