package cel

import (
	"github.com/google/cel-go/cel"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

const (
	responseVarName = "response"
)

type compiler struct {
	*authenticationcel.ExtendableCompiler
}

func (c *compiler) CompileExternalSourceExpression(expressionAccessor authenticationcel.ExpressionAccessor) (authenticationcel.CompilationResult, error) {
	return c.Compile(expressionAccessor, responseVarName)
}

func NewCompiler() *compiler {
	responseType := apiservercel.NewMapType(apiservercel.StringType, apiservercel.DynType, -1)

	extendableCompiler := authenticationcel.NewExtendableCompiler(
		environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()),
		authenticationcel.NewEnvironmentSet(
			responseVarName,
			[]cel.EnvOption{cel.Variable(responseVarName, responseType.CelType())},
			[]*apiservercel.DeclType{responseType},
		),
	)

	return &compiler{
		extendableCompiler,
	}
}
