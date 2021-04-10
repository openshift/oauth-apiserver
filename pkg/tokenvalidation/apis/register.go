package apis

import (
	"k8s.io/apimachinery/pkg/runtime"

	kauthenticationv1 "k8s.io/api/authentication/v1"
)

var (
	localSchemeBuilder = runtime.NewSchemeBuilder(
		kauthenticationv1.AddToScheme,
	)
	Install = localSchemeBuilder.AddToScheme
)

func init() {
	localSchemeBuilder.Register(kauthenticationv1.AddToScheme)
}
