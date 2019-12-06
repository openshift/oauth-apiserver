package apiserver

import (
	"testing"

	"github.com/openshift/oauth-apiserver/pkg/serverscheme"
	"k8s.io/apimachinery/pkg/api/apitesting/roundtrip"
)

func TestRoundTripTypes(t *testing.T) {
	roundtrip.RoundTripTestForScheme(t, serverscheme.Scheme)
}
