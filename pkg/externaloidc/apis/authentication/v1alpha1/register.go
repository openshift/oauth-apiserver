package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
)

var (
	localSchemeBuilder = runtime.NewSchemeBuilder(authentication.Install)
	Install            = localSchemeBuilder.AddToScheme
)
