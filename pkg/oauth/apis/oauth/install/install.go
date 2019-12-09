package install

import (
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	oauthv1 "github.com/openshift/api/oauth/v1"
	oauthapiv1 "github.com/openshift/oauth-apiserver/pkg/oauth/apis/oauth/v1"
)

// Install registers the API group and adds types to a scheme
func Install(scheme *runtime.Scheme) {
	utilruntime.Must(oauthapiv1.Install(scheme))
	utilruntime.Must(scheme.SetVersionPriority(oauthv1.GroupVersion))
}
