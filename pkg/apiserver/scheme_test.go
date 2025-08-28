package apiserver

import (
	"testing"

	"github.com/openshift/oauth-apiserver/pkg/serverscheme"
	"k8s.io/apimachinery/pkg/api/apitesting/roundtrip"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/randfill"

	oauthapi "github.com/openshift/oauth-apiserver/pkg/oauth/apis/oauth"
)

var fuzzerFuncs = func(codecs serializer.CodecFactory) []interface{} {
	return []interface{}{
		func(j *oauthapi.OAuthAuthorizeToken, c randfill.Continue) {
			c.FillNoCustom(j)
			if len(j.CodeChallenge) > 0 && len(j.CodeChallengeMethod) == 0 {
				j.CodeChallengeMethod = "plain"
			}
		},
		func(j *oauthapi.OAuthClientAuthorization, c randfill.Continue) {
			c.FillNoCustom(j)
			if len(j.Scopes) == 0 {
				j.Scopes = append(j.Scopes, "user:full")
			}
		},
	}
}

func TestRoundTripTypes(t *testing.T) {
	roundtrip.RoundTripTestForScheme(t, serverscheme.Scheme, fuzzerFuncs)
}
