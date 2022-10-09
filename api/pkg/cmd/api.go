package main

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/milennik/gonito/internal/auth"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	cognitoClient := auth.Init()

	r := chi.NewRouter()
	r.Use(middleware.Logger, middleware.WithValue("CognitoClient", cognitoClient))

	// Public Endpoints
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("Welcome to the test API."))
		if err != nil {
			return
		}
	})

	// Private Endpoints
	r.Group(func(r chi.Router) {
		r.Use(IsAuth)
		r.Get("/test", testAuth)
	})

	port := os.Getenv("PORT")

	fmt.Println("Starting the test API.")
	err := http.ListenAndServe(fmt.Sprintf(":%s", port), r)
	if err != nil {
		return
	}
}

func testAuth(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("Hello from the test endpoint, JWT is valid.\n"))
	return
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
