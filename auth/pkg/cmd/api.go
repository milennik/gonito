package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/milennik/gonito/internal/auth"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	cognitoClient := auth.Init()

	r := chi.NewRouter()
	r.Use(middleware.Logger, middleware.WithValue("CognitoClient", cognitoClient))

	// Public Endpoints
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Welcome to the auth service."))
		if err != nil {
			return
		}
	})
	r.Post("/signin", signIn)
	r.Post("/signup", signUp)
	// Private Endpoints
	r.Group(func(r chi.Router) {
		r.Use(IsAuth)
		r.Get("/test", testAuth)
	})

	port := os.Getenv("PORT")
	fmt.Println("Starting auth service.")
	err := http.ListenAndServe(fmt.Sprintf(":%s", port), r)
	if err != nil {
		return
	}
}

func IsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.ValidateClaims(w, r) {
			return
		}
		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}

func signUp(w http.ResponseWriter, r *http.Request) {

	var req auth.SignUpRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cognitoClient, _, hasErr := auth.GetCognitoClient(w, r)
	if hasErr {
		return
	}

	awsReq := &cip.SignUpInput{
		ClientId:       aws.String(cognitoClient.AppClientId),
		Username:       aws.String(req.Username),
		Password:       aws.String(req.Password),
		UserAttributes: req.UserAttributes,
	}

	cognitoClient.AppClientId = req.Aud
	_, err = cognitoClient.SignUp(r.Context(), awsReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	confirmInput := &cip.AdminConfirmSignUpInput{
		UserPoolId: aws.String(cognitoClient.UserPoolId),
		Username:   aws.String(req.Username),
	}

	_, err = cognitoClient.AdminConfirmSignUp(r.Context(), confirmInput)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = w.Write([]byte("Successful sign up."))
	if err != nil {
		return
	}
}

func signIn(w http.ResponseWriter, r *http.Request) {

	var req auth.SignInRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cognitoClient, _, hasErr := auth.GetCognitoClient(w, r)
	if hasErr {
		return
	}

	signInInput := &cip.AdminInitiateAuthInput{
		AuthFlow:       "ADMIN_USER_PASSWORD_AUTH",
		ClientId:       aws.String(cognitoClient.AppClientId),
		UserPoolId:     aws.String(cognitoClient.UserPoolId),
		AuthParameters: map[string]string{"USERNAME": req.Username, "PASSWORD": req.Password},
	}

	output, err := cognitoClient.AdminInitiateAuth(r.Context(), signInInput)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res := &auth.SignInResponse{
		AccessToken:  output.AuthenticationResult.AccessToken,
		ExpiresIn:    output.AuthenticationResult.ExpiresIn,
		IdToken:      output.AuthenticationResult.IdToken,
		RefreshToken: output.AuthenticationResult.RefreshToken,
		TokenType:    output.AuthenticationResult.TokenType,
	}
	_ = json.NewEncoder(w).Encode(res)
}

func testAuth(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("Hello from the test endpoint, JWT is valid.\n"))
	return
}
