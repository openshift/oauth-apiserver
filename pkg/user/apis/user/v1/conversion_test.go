package v1

import (
	"testing"

	v1 "github.com/openshift/api/user/v1"
	"github.com/openshift/oauth-apiserver/pkg/apitesting"
	userapi "github.com/openshift/oauth-apiserver/pkg/user/apis/user"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestFieldSelectorConversions(t *testing.T) {
	apitesting.FieldKeyCheck{
		SchemeBuilder: []func(*runtime.Scheme) error{Install},
		Kind:          v1.GroupVersion.WithKind("Identity"),
		// Ensure previously supported labels have conversions. DO NOT REMOVE THINGS FROM THIS LIST
		AllowedExternalFieldKeys: []string{"providerName", "providerUserName", "user.name", "user.uid"},
		FieldKeyEvaluatorFn:      userapi.IdentityFieldSelector,
	}.Check(t)
}
