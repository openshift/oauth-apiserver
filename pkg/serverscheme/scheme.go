package serverscheme

import (
	oauthinstall "github.com/openshift/oauth-apiserver/pkg/oauth/apis/oauth/install"
	userinstall "github.com/openshift/oauth-apiserver/pkg/user/apis/user/install"
	"k8s.io/apimachinery/pkg/runtime"
)

var Scheme = runtime.NewScheme()

func init() {
	oauthinstall.Install(Scheme)
	userinstall.Install(Scheme)
}
