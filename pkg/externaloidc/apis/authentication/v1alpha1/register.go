package v1alpha1

import (
	k8sauthenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
)

var (
	localSchemeBuilder = runtime.NewSchemeBuilder(
		authentication.Install,
		k8sauthenticationv1.AddToScheme,
	)
	Install = localSchemeBuilder.AddToScheme
)
