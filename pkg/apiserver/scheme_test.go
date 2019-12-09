package apiserver

import (
	"testing"

	"github.com/openshift/oauth-apiserver/pkg/serverscheme"
	"k8s.io/apimachinery/pkg/api/apitesting/roundtrip"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var fuzzerFuncs = func(codecs serializer.CodecFactory) []interface{} {
	return []interface{}{}
}

func TestRoundTripTypes(t *testing.T) {
	roundtrip.RoundTripTestForScheme(t, serverscheme.Scheme, fuzzerFuncs)
}
