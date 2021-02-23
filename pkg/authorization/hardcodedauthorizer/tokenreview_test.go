package hardcodedauthorizer

import (
	"context"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestAuthorizer(t *testing.T) {
	tests := []struct {
		name       string
		authorizer authorizer.Authorizer

		shouldPass      []authorizer.Attributes
		shouldNoOpinion []authorizer.Attributes
	}{
		{
			name:       "tokens",
			authorizer: NewHardCodedTokenReviewAuthorizer(),
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{
					User: &user.DefaultInfo{Name: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
					Verb: "create", APIGroup: "oauth.openshift.io", Resource: "tokenreviews", Subresource: "", ResourceRequest: true},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// wrong user
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "other"},
					Verb: "create", APIGroup: "oauth.openshift.io", Resource: "tokenreviews", Subresource: "", ResourceRequest: true},

				// wrong verb
				authorizer.AttributesRecord{
					User: &user.DefaultInfo{Name: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
					Verb: "update", APIGroup: "oauth.openshift.io", Resource: "tokenreviews", Subresource: "", ResourceRequest: true},
				// wrong group
				authorizer.AttributesRecord{
					User: &user.DefaultInfo{Name: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
					Verb: "get", APIGroup: "k8s.io", Resource: "tokenreviews", Subresource: "", ResourceRequest: true},
				// wrong resource
				authorizer.AttributesRecord{
					User: &user.DefaultInfo{Name: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
					Verb: "get", APIGroup: "oauth.openshift.io", Resource: "other-resource", Subresource: "", ResourceRequest: true},
				// wrong subresource
				authorizer.AttributesRecord{
					User: &user.DefaultInfo{Name: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"},
					Verb: "get", APIGroup: "oauth.openshift.io", Resource: "tokenreviews", Subresource: "foo", ResourceRequest: true},

				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:serviceaccount:openshift-oauth-apiserver:openshift-authenticator"}, Verb: "get", Path: "/api"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, attr := range tt.shouldPass {
				if decision, _, _ := tt.authorizer.Authorize(context.Background(), attr); decision != authorizer.DecisionAllow {
					t.Errorf("incorrectly restricted %v", attr)
				}
			}

			for _, attr := range tt.shouldNoOpinion {
				if decision, _, _ := tt.authorizer.Authorize(context.Background(), attr); decision != authorizer.DecisionNoOpinion {
					t.Errorf("incorrectly opinionated %v", attr)
				}
			}
		})
	}
}
