package handlers

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

func NewAuthenticate(authenticator authenticator.Token) *Authenticate {
	return &Authenticate{
		authenticator: authenticator,
	}
}

type Authenticate struct {
	authenticator authenticator.Token
}

func (a *Authenticate) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	requestedTokenReviewBytes, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("error reading request body: %v\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	requestedTokenReview := &authenticationv1.TokenReview{}
	err = json.Unmarshal(requestedTokenReviewBytes, requestedTokenReview)
	if err != nil {
		log.Printf("error unmarshalling request body: %v\n", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	responseTokenReview := &authenticationv1.TokenReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: authenticationv1.SchemeGroupVersion.String(),
			Kind:       "TokenReview",
		},
	}

	resp, authenticated, err := a.authenticator.AuthenticateToken(req.Context(), requestedTokenReview.Spec.Token)
	if err != nil {
		log.Println(err)
		responseTokenReview.Status = authenticationv1.TokenReviewStatus{
			Authenticated: false,
			Error:         err.Error(),
		}
		rw.WriteHeader(http.StatusUnauthorized)
	} else if !authenticated {
		responseTokenReview.Status = authenticationv1.TokenReviewStatus{
			Authenticated: false,
		}
		rw.WriteHeader(http.StatusUnauthorized)
	} else {
		if resp == nil || resp.User == nil {
			log.Println("(authenticate.ServeHTTP) no response or user. Unauthorized.")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		extras := map[string]authenticationv1.ExtraValue{}

		for key, values := range resp.User.GetExtra() {
			extras[key] = authenticationv1.ExtraValue(values)
		}

		responseTokenReview.Status = authenticationv1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1.UserInfo{
				Username: resp.User.GetName(),
				UID:      resp.User.GetUID(),
				Groups:   resp.User.GetGroups(),
				Extra:    extras,
			},
			Audiences: resp.Audiences,
		}

	}

	trBytes, err := json.Marshal(responseTokenReview)
	if err != nil {
		log.Println(err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Write(trBytes)
}
