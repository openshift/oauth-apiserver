package oauthclientauthorization

import (
	"context"
	"testing"

	oauth "github.com/openshift/api/oauth/v1"
	oauthapi "github.com/openshift/oauth-apiserver/pkg/oauth/apis/oauth"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// these are constants copied from the apiserver-library-go repo to avoid a transitive on kube for a string const
const (
	UserIndicator   = "user:"
	UserInfo        = UserIndicator + "info"
	UserAccessCheck = UserIndicator + "check-access"

	// UserListScopedProjects gives explicit permission to see the projects that this token can see.
	UserListScopedProjects = UserIndicator + "list-scoped-projects"

	// UserListAllProjects gives explicit permission to see the projects a user can see.  This is often used to prime secondary ACL systems
	// unrelated to openshift and to display projects for selection in a secondary UI.
	UserListAllProjects = UserIndicator + "list-projects"

	// UserFull includes all permissions of the user
	UserFull = UserIndicator + "full"
)

// TestValidateScopeUpdate asserts that a live client lookup only occurs when new scopes are added during an update
func TestValidateScopeUpdate(t *testing.T) {
	for _, test := range []struct {
		name           string
		expectedCalled bool
		obj            []string
		old            []string
	}{
		{
			name:           "both equal",
			expectedCalled: false,
			obj:            []string{UserAccessCheck},
			old:            []string{UserAccessCheck},
		},
		{
			name:           "new scopes from empty",
			expectedCalled: true,
			obj:            []string{UserFull},
			old:            []string{},
		},
		{
			name:           "new scopes from non-empty",
			expectedCalled: true,
			obj:            []string{UserFull},
			old:            []string{UserInfo},
		},
		{
			name:           "deleted scopes",
			expectedCalled: false,
			obj:            []string{UserFull},
			old:            []string{UserFull, UserInfo},
		},
		{
			name:           "deleted and added scopes",
			expectedCalled: true,
			obj:            []string{UserFull, UserAccessCheck},
			old:            []string{UserFull, UserInfo},
		},
	} {
		clientGetter := &wasCalledClientGetter{}
		s := strategy{clientGetter: clientGetter}
		if errs := s.ValidateUpdate(nil, validClientWithScopes(test.obj), validClientWithScopes(test.old)); len(errs) > 0 {
			t.Errorf("%s: unexpected update error: %s", test.name, errs)
			continue
		}
		if test.expectedCalled != clientGetter.called {
			t.Errorf("%s: expected call behavior %v does not match %v", test.name, test.expectedCalled, clientGetter.called)
		}
	}
}

func TestValidateScopeUpdateFailures(t *testing.T) {
	for _, test := range []struct {
		name           string
		expectedCalled bool
		obj            []string
		old            []string
	}{
		{
			name:           "both empty",
			expectedCalled: false,
			obj:            []string{},
			old:            []string{},
		},
		{
			name:           "deleted scopes to empty",
			expectedCalled: true,
			obj:            []string{},
			old:            []string{UserFull},
		},
	} {
		clientGetter := &wasCalledClientGetter{}
		s := strategy{clientGetter: clientGetter}
		if errs := s.ValidateUpdate(nil, validClientWithScopes(test.obj), validClientWithScopes(test.old)); len(errs) == 0 {
			t.Errorf("%s: expected error: %s", test.name, errs)
			continue
		}
		if test.expectedCalled != clientGetter.called {
			t.Errorf("%s: expected call behavior %v does not match %v", test.name, test.expectedCalled, clientGetter.called)
		}
	}
}

type wasCalledClientGetter struct {
	called bool
}

func (g *wasCalledClientGetter) Get(_ context.Context, _ string, _ metav1.GetOptions) (*oauth.OAuthClient, error) {
	g.called = true
	return &oauth.OAuthClient{}, nil
}

func validClientWithScopes(scopes []string) *oauthapi.OAuthClientAuthorization {
	return &oauthapi.OAuthClientAuthorization{
		ObjectMeta: metav1.ObjectMeta{Name: "un:cn", ResourceVersion: "0"},
		ClientName: "cn",
		UserName:   "un",
		UserUID:    "uid",
		Scopes:     scopes,
	}
}
