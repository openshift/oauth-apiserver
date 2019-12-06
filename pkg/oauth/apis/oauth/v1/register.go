package v1

import (
	"k8s.io/apimachinery/pkg/runtime"

	oauthv1 "github.com/openshift/api/oauth/v1"
	"github.com/openshift/oauth-apiserver/pkg/oauth/apis/oauth"
)

var (
	localSchemeBuilder = runtime.NewSchemeBuilder(
		oauth.Install,
		oauthv1.Install,

		addFieldSelectorKeyConversions,
		RegisterDefaults,
	)
	Install = localSchemeBuilder.AddToScheme
)
