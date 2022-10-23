package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
)

var tokenAuth *jwtauth.JWTAuth

func init() {
	keyData, _ := os.ReadFile("jwt.key")
	privateKeyBlock, _ := pem.Decode([]byte(keyData))
	privateKey, _ := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	publicKey := privateKey.Public()
	tokenAuth = jwtauth.New("RS256", privateKey, publicKey)
}

func main() {
	addr := "127.0.0.1:3333"
	fmt.Printf("Starting server on %v\n", addr)
	http.ListenAndServe(addr, router())
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)

	r.Group(func(r chi.Router) {
		r.Use(middleware.BasicAuth("home", map[string]string{"bob": "ross"}))

		r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("PROTECTED AREA"))
		})
	})

	r.Group(func(r chi.Router) {
		r.Use(middleware.Timeout(time.Millisecond * 500))

		r.Get("/slow", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			processTime := time.Duration(rand.Intn(4)+1) * time.Second

			select {
			case <-ctx.Done():
				return

			case <-time.After(processTime):
				// The above channel simulates some hard work.
			}

			w.Write([]byte("Well done"))
		})
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(jwtauth.Verifier(tokenAuth))

		r.Use(jwtauth.Authenticator)

		r.Get("/admin", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			w.Write([]byte(fmt.Sprintf("protected area. hi %v", claims["user_id"])))
		})
	})

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
			claims := map[string]interface{}{"user_id": time.Now()}
			jwtauth.SetIssuedNow(claims)
			jwtauth.SetExpiryIn(claims, 1*time.Hour)

			_, jwt, _ := tokenAuth.Encode(claims)

			w.Header().Set("Content-Type", "application/json")
			http.SetCookie(w, &http.Cookie{Name: "jwt", Value: jwt})
			json.NewEncoder(w).Encode(&TokenResponse{jwt, 3600})
		})

		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("welcome anonymous"))
		})
	})

	return r
}
