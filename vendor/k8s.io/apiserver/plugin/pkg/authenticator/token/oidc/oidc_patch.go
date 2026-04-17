package oidc

import (
	"context"

	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// ClaimsMap is an exported version of the claims type
type ClaimsMap claims

// ClaimsExpander is used to expand the set of
// claims made available during the claim-to-identity mapping process.
type ClaimsExpander interface {
	ExpandClaims(context.Context, ClaimsMap) error
}

type tokenContextKey string

const RequestProvidedTokenContextKey tokenContextKey = "authentication.openshift.io/request-provided-token"

func NewClaimsValue(c ClaimsMap) traits.Mapper {
	return newClaimsValue(claims(c))
}

func ConvertCELValueToStringList(val ref.Val) ([]string, error) {
	return convertCELValueToStringList(val)
}
