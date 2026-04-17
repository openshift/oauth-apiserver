package cel

import (
	"context"

	"github.com/google/cel-go/common/types/traits"
)

type ExportedMapper struct {
	*mapper
}

func NewExportedMapper(compilationResults []CompilationResult) *ExportedMapper {
	return &ExportedMapper{
		mapper: &mapper{
			compilationResults: compilationResults,
		},
	}
}

func (em *ExportedMapper) Eval(ctx context.Context, input VarNameActivation) ([]EvaluationResult, error) {
	return em.mapper.eval(ctx, input.varNameActivation)
}

type VarNameActivation struct {
	*varNameActivation
}

func NewVarNameActivation(name string, value traits.Mapper) VarNameActivation {
	return VarNameActivation{
		varNameActivation: &varNameActivation{
			name: name,
			value: value,
		},
	}
}
