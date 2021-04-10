package etcd

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	kauthenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/klog/v2"
)

var _ rest.Storage = &REST{}
var _ rest.Creater = &REST{}

var badAuthenticatorAuds = apierrors.NewInternalError(errors.New("error validating audiences"))

type REST struct {
	tokenAuthenticator authenticator.Request
	apiAudiences       []string
}

func NewREST(tokenAuthenticator authenticator.Request, apiAudiences []string) *REST {
	return &REST{
		tokenAuthenticator: tokenAuthenticator,
		apiAudiences:       apiAudiences,
	}
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) New() runtime.Object {
	return &kauthenticationv1.TokenReview{}
}

func (r *REST) GroupVersionKind(containingGV schema.GroupVersion) schema.GroupVersionKind {
	return kauthenticationv1.SchemeGroupVersion.WithKind("TokenReview")
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	tokenReview, ok := obj.(*kauthenticationv1.TokenReview)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a TokenReview: %#v", obj))
	}
	namespace := genericapirequest.NamespaceValue(ctx)
	if len(namespace) != 0 {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("namespace is not allowed on this type: %v", namespace))
	}

	if len(tokenReview.Spec.Token) == 0 {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("token is required for TokenReview in authentication"))
	}

	if createValidation != nil {
		if err := createValidation(ctx, obj.DeepCopyObject()); err != nil {
			return nil, err
		}
	}

	if r.tokenAuthenticator == nil {
		return tokenReview, nil
	}

	// create a header that contains nothing but the token
	fakeReq := &http.Request{Header: http.Header{}}
	fakeReq.Header.Add("Authorization", "Bearer "+tokenReview.Spec.Token)

	auds := tokenReview.Spec.Audiences
	if len(auds) == 0 {
		auds = r.apiAudiences
	}
	if len(auds) > 0 {
		fakeReq = fakeReq.WithContext(authenticator.WithAudiences(fakeReq.Context(), auds))
	}

	resp, ok, err := r.tokenAuthenticator.AuthenticateRequest(fakeReq)
	tokenReview.Status.Authenticated = ok
	if err != nil {
		tokenReview.Status.Error = err.Error()
	}

	if len(auds) > 0 && resp != nil && len(authenticator.Audiences(auds).Intersect(resp.Audiences)) == 0 {
		klog.Errorf("error validating audience. want=%q got=%q", auds, resp.Audiences)
		return nil, badAuthenticatorAuds
	}

	if resp != nil && resp.User != nil {
		tokenReview.Status.User = kauthenticationv1.UserInfo{
			Username: resp.User.GetName(),
			UID:      resp.User.GetUID(),
			Groups:   resp.User.GetGroups(),
			Extra:    map[string]kauthenticationv1.ExtraValue{},
		}
		for k, v := range resp.User.GetExtra() {
			tokenReview.Status.User.Extra[k] = kauthenticationv1.ExtraValue(v)
		}
		tokenReview.Status.Audiences = resp.Audiences
	}

	return tokenReview, nil
}
