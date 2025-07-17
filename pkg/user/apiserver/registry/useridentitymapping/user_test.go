package useridentitymapping

import (
	"context"

	kerrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	userv1 "github.com/openshift/api/user/v1"
	userv1client "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
)

type UserRegistry struct {
	// included to fill out the interface for testing
	userv1client.UserInterface

	GetErr   map[string]error
	GetUsers map[string]*userv1.User

	CreateErr  error
	CreateUser *userv1.User

	UpdateErr  map[string]error
	UpdateUser *userv1.User

	ListErr   error
	ListUsers *userv1.UserList

	Actions *[]Action
}

func (r *UserRegistry) Get(_ context.Context, name string, options metav1.GetOptions) (*userv1.User, error) {
	*r.Actions = append(*r.Actions, Action{"GetUser", name})
	if user, ok := r.GetUsers[name]; ok {
		return user, nil
	}
	if err, ok := r.GetErr[name]; ok {
		return nil, err
	}
	return nil, kerrs.NewNotFound(userv1.Resource("user"), name)
}

func (r *UserRegistry) Create(_ context.Context, u *userv1.User, _ metav1.CreateOptions) (*userv1.User, error) {
	*r.Actions = append(*r.Actions, Action{"CreateUser", u})
	if r.CreateUser == nil && r.CreateErr == nil {
		return u, nil
	}
	return r.CreateUser, r.CreateErr
}

func (r *UserRegistry) Update(_ context.Context, u *userv1.User, _ metav1.UpdateOptions) (*userv1.User, error) {
	*r.Actions = append(*r.Actions, Action{"UpdateUser", u})
	err, _ := r.UpdateErr[u.Name]
	if r.UpdateUser == nil && err == nil {
		return u, nil
	}
	return r.UpdateUser, err
}

func (r *UserRegistry) List(_ context.Context, options metav1.ListOptions) (*userv1.UserList, error) {
	*r.Actions = append(*r.Actions, Action{"ListUsers", options})
	if r.ListUsers == nil && r.ListErr == nil {
		return &userv1.UserList{}, nil
	}
	return r.ListUsers, r.ListErr
}
