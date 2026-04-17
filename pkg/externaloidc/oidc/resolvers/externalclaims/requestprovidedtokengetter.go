package externalclaims

import (
	"context"
	"errors"
	"fmt"

	k8soidc "k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

type RequestProvidedAccessTokenGetter struct{}

func (rpatg *RequestProvidedAccessTokenGetter) GetAccessToken(ctx context.Context) (string, error) {
	val := ctx.Value(k8soidc.RequestProvidedTokenContextKey)
	if val == nil {
		return "", errors.New("getting access token: no access token present in the request context")
	}

	strVal, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("getting access token: expected access token in the request context to be of type string but got %T", val)
	}

	return strVal, nil
}
