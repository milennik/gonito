package auth

import (
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"net/http"
	"os"
	"strings"
)

func CheckClaims(w http.ResponseWriter, token jwt.Token, ok bool) bool {
	username, _ := token.Get("cognito:username")
	department, _ := token.Get("custom:department")
	auds, _ := token.Get("aud")
	aud, ok := auds.([]string)
	if !ok && len(aud) != 1 {
		fmt.Printf("Missing audience from JWT.\n")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return true
	}
	fmt.Printf("Username: %v, Department: %v, Audience: %v\n", username, department, auds)
	if auds.([]string)[0] != os.Getenv("AUD") {
		fmt.Printf("Invalid audience %v. Expected audience %v\n", aud[0], os.Getenv("AUD"))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return true
	}
	return false
}

func FetchJWK(w http.ResponseWriter, r *http.Request, cognitoClient *CognitoClient) (jwk.Set, error, bool) {
	pubKeyURL := "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json"
	formattedURL := fmt.Sprintf(pubKeyURL, os.Getenv("AWS_DEFAULT_REGION"), cognitoClient.UserPoolId)

	keySet, err := jwk.Fetch(r.Context(), formattedURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, nil, true
	}
	return keySet, err, false
}

func GetCognitoClient(w http.ResponseWriter, r *http.Request) (*CognitoClient, bool, bool) {
	cognitoClient, ok := r.Context().Value("CognitoClient").(*CognitoClient)
	if !ok {
		http.Error(w, "Could not retrieve CognitoClient from context.", http.StatusInternalServerError)
		return nil, false, true
	}
	return cognitoClient, ok, false
}

func SplitAuthHeader(w http.ResponseWriter, authHeader string) ([]string, bool) {
	splitAuthHeader := strings.Split(authHeader, " ")
	if len(splitAuthHeader) != 2 {
		http.Error(w, "Missing or invalid authorization header.", http.StatusUnauthorized)
		return nil, true
	}
	return splitAuthHeader, false
}

func ParseJWT(w http.ResponseWriter, err error, splitAuthHeader []string, keySet jwk.Set) (jwt.Token, bool) {
	token, err := jwt.Parse(
		[]byte(splitAuthHeader[1]),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
	)
	if err != nil {
		fmt.Println("Invalid or expired JWT.")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, true
	}
	return token, false
}

func ValidateClaims(w http.ResponseWriter, r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	splitAuthHeader, hasErr := SplitAuthHeader(w, authHeader)

	if hasErr {
		return true
	}

	cognitoClient, ok, hasErr := GetCognitoClient(w, r)
	if hasErr {
		return true
	}

	keySet, err, done := FetchJWK(w, r, cognitoClient)
	if done {
		return true
	}

	token, hasErr := ParseJWT(w, err, splitAuthHeader, keySet)
	if hasErr {
		return true
	}

	if CheckClaims(w, token, ok) {
		return true
	}

	return false
}
