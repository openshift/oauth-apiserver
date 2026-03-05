package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/openshift/oauth-apiserver/pkg/externaloidc/handlers"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

var _ authenticator.Token = &mockTokenAuthenticator{}

type mockTokenAuthenticator struct {
	delegate func(context.Context, string) (*authenticator.Response, bool, error)
}

func (mta *mockTokenAuthenticator) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return mta.delegate(ctx, token)
}

func TestAuthenticateHandler(t *testing.T) {
	type testcase struct {
		name                      string
		tokenAuthenticator        authenticator.Token
		expectedStatusCode        int
		expectedTokenReviewStatus *authenticationv1.TokenReviewStatus
		requestBody               []byte
	}

	testcases := []testcase{
		{
			name:               "bad request body, returns 500",
			expectedStatusCode: http.StatusInternalServerError,
			requestBody:        []byte("not a token review"),
		},
		{
			name:               "good request body, not successfully authenticated, returns 401 with token review status saying unauthenticated",
			expectedStatusCode: http.StatusUnauthorized,
			requestBody:        validTokenReviewToBytes(t),
			tokenAuthenticator: &mockTokenAuthenticator{
				delegate: func(ctx context.Context, s string) (*authenticator.Response, bool, error) {
					return &authenticator.Response{}, false, nil
				},
			},
			expectedTokenReviewStatus: &authenticationv1.TokenReviewStatus{
				Authenticated: false,
			},
		},
		{
			name:               "good request body, not successfully authenticated due to an error, returns 401 with token review status with error",
			expectedStatusCode: http.StatusUnauthorized,
			requestBody:        validTokenReviewToBytes(t),
			tokenAuthenticator: &mockTokenAuthenticator{
				delegate: func(ctx context.Context, s string) (*authenticator.Response, bool, error) {
					return &authenticator.Response{}, false, errors.New("boom")
				},
			},
			expectedTokenReviewStatus: &authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "boom",
			},
		},
		{
			name:               "good request body, authenticated with an error, returns 401 with token review status with error",
			expectedStatusCode: http.StatusUnauthorized,
			requestBody:        validTokenReviewToBytes(t),
			tokenAuthenticator: &mockTokenAuthenticator{
				delegate: func(ctx context.Context, s string) (*authenticator.Response, bool, error) {
					return &authenticator.Response{}, true, errors.New("boom")
				},
			},
			expectedTokenReviewStatus: &authenticationv1.TokenReviewStatus{
				Authenticated: false,
				Error:         "boom",
			},
		},
		{
			name:               "good request body, authenticated with no error and nil response , returns 401",
			expectedStatusCode: http.StatusUnauthorized,
			requestBody:        validTokenReviewToBytes(t),
			tokenAuthenticator: &mockTokenAuthenticator{
				delegate: func(ctx context.Context, s string) (*authenticator.Response, bool, error) {
					return nil, true, nil
				},
			},
		},
		{
			name:               "good request body, authenticated with no error non-nil response but nil user, returns 401",
			expectedStatusCode: http.StatusUnauthorized,
			requestBody:        validTokenReviewToBytes(t),
			tokenAuthenticator: &mockTokenAuthenticator{
				delegate: func(ctx context.Context, s string) (*authenticator.Response, bool, error) {
					return &authenticator.Response{User: nil}, true, nil
				},
			},
		},
		{
			name:               "good request body, authenticated, returns 200 and user identity",
			expectedStatusCode: http.StatusOK,
			requestBody:        validTokenReviewToBytes(t),
			tokenAuthenticator: &mockTokenAuthenticator{
				delegate: func(ctx context.Context, s string) (*authenticator.Response, bool, error) {
					return &authenticator.Response{
						User: &mockUserInfo{
							Username: "test",
							Groups:   []string{"one", "two"},
							Extra: map[string][]string{
								"test/role": {"admin"},
							},
							UID: "uid",
						},
					}, true, nil
				},
			},
			expectedTokenReviewStatus: &authenticationv1.TokenReviewStatus{
				Authenticated: true,
				User: authenticationv1.UserInfo{
					Username: "test",
					Groups:   []string{"one", "two"},
					Extra: map[string]authenticationv1.ExtraValue{
						"test/role": {"admin"},
					},
					UID: "uid",
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/authenticate", bytes.NewReader(tc.requestBody))
			respRec := httptest.NewRecorder()

			handlers.NewAuthenticate(tc.tokenAuthenticator).ServeHTTP(respRec, req)

			if respRec.Code != tc.expectedStatusCode {
				t.Fatalf("expected status code %d but got %d", tc.expectedStatusCode, respRec.Code)
			}

			if tc.expectedTokenReviewStatus != nil {
				actualTokenReview := &authenticationv1.TokenReview{}
				err := json.Unmarshal(respRec.Body.Bytes(), actualTokenReview)
				if err != nil {
					t.Fatalf("unmarshalling handler response to an authenticationv1.TokenReview: %v", err)
				}

				if tc.expectedTokenReviewStatus.Authenticated != actualTokenReview.Status.Authenticated {
					t.Errorf("expected authenticated status %v does not match actual authenticated status %v", tc.expectedTokenReviewStatus.Authenticated, actualTokenReview.Status.Authenticated)
				}

				if tc.expectedTokenReviewStatus.Error != actualTokenReview.Status.Error {
					t.Errorf("expected error status %v does not match actual error status %v", tc.expectedTokenReviewStatus.Error, actualTokenReview.Status.Error)
				}

				if tc.expectedTokenReviewStatus.User.Username != actualTokenReview.Status.User.Username {
					t.Errorf("expected user username %q does not match actual user username %q", tc.expectedTokenReviewStatus.User.Username, actualTokenReview.Status.User.Username)
				}

				if tc.expectedTokenReviewStatus.User.UID != actualTokenReview.Status.User.UID {
					t.Errorf("expected user uid %q does not match actual user uid %q", tc.expectedTokenReviewStatus.User.UID, actualTokenReview.Status.User.UID)
				}

				if !slices.Equal(tc.expectedTokenReviewStatus.User.Groups, actualTokenReview.Status.User.Groups) {
					t.Errorf("expected user groups %v does not match actual user groups %v", tc.expectedTokenReviewStatus.User.Groups, actualTokenReview.Status.User.Groups)
				}

				if !maps.EqualFunc(tc.expectedTokenReviewStatus.User.Extra, actualTokenReview.Status.User.Extra, func(v1, v2 authenticationv1.ExtraValue) bool {
					return slices.Equal([]string(v1), []string(v2))
				}) {
					t.Errorf("expected user extras %v does not match actual user extras %v", tc.expectedTokenReviewStatus.User.Extra, actualTokenReview.Status.User.Extra)
				}
			}
		})
	}
}

func validTokenReviewToBytes(t *testing.T) []byte {
	tokenReview := &authenticationv1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authenticationv1.SchemeGroupVersion.String(),
			Kind:       "TokenReview",
		},
		Spec: authenticationv1.TokenReviewSpec{
			Token: "token",
		},
	}

	out, err := json.Marshal(tokenReview)
	if err != nil {
		t.Fatalf("marshalling valid token review failed: %v", err)
	}

	return out
}

type mockUserInfo struct {
	Username string
	Groups   []string
	Extra    map[string][]string
	UID      string
}

func (mui *mockUserInfo) GetName() string {
	return mui.Username
}

func (mui *mockUserInfo) GetGroups() []string {
	return mui.Groups
}

func (mui *mockUserInfo) GetExtra() map[string][]string {
	return mui.Extra
}

func (mui *mockUserInfo) GetUID() string {
	return mui.UID
}
