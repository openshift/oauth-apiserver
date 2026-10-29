package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"

	authenticationv1alpha1 "github.com/openshift/api/authentication/v1alpha1"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
)

var (
	localSchemeBuilder = runtime.NewSchemeBuilder(
		authentication.Install,
		authenticationv1alpha1.Install,
	)
	Install = localSchemeBuilder.AddToScheme
)
