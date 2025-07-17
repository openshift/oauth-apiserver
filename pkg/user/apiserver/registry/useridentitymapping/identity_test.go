package useridentitymapping

import (
	"context"

	kerrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	userv1 "github.com/openshift/api/user/v1"
	userv1client "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
)

type Action struct {
	Name   string
	Object interface{}
}

type IdentityRegistry struct {
	userv1client.IdentityInterface

	GetErr        map[string]error
	GetIdentities map[string]*userv1.Identity

	CreateErr      error
	CreateIdentity *userv1.Identity

	UpdateErr      error
	UpdateIdentity *userv1.Identity

	ListErr      error
	ListIdentity *userv1.IdentityList

	Actions *[]Action
}

func (r *IdentityRegistry) Get(_ context.Context, name string, options metav1.GetOptions) (*userv1.Identity, error) {
	*r.Actions = append(*r.Actions, Action{"GetIdentity", name})
	if identity, ok := r.GetIdentities[name]; ok {
		return identity, nil
	}
	if err, ok := r.GetErr[name]; ok {
		return nil, err
	}
	return nil, kerrs.NewNotFound(userv1.Resource("identity"), name)
}

func (r *IdentityRegistry) Create(_ context.Context, u *userv1.Identity, _ metav1.CreateOptions) (*userv1.Identity, error) {
	*r.Actions = append(*r.Actions, Action{"CreateIdentity", u})
	if r.CreateIdentity == nil && r.CreateErr == nil {
		return u, nil
	}
	return r.CreateIdentity, r.CreateErr
}

func (r *IdentityRegistry) Update(_ context.Context, u *userv1.Identity, _ metav1.UpdateOptions) (*userv1.Identity, error) {
	*r.Actions = append(*r.Actions, Action{"UpdateIdentity", u})
	if r.UpdateIdentity == nil && r.UpdateErr == nil {
		return u, nil
	}
	return r.UpdateIdentity, r.UpdateErr
}

func (r *IdentityRegistry) List(_ context.Context, options metav1.ListOptions) (*userv1.IdentityList, error) {
	*r.Actions = append(*r.Actions, Action{"ListIdentities", options})
	if r.ListIdentity == nil && r.ListErr == nil {
		return &userv1.IdentityList{}, nil
	}
	return r.ListIdentity, r.ListErr
}
