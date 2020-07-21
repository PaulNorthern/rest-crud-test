package main

import (
	"rest_auth/controller"
	"log"
	"net/http"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	// Create a new User
	r.HandleFunc("/register", controller.RegisterHandler).Methods("POST")
	// Login as a User by Username and Password
	r.HandleFunc("/login", controller.LoginHandler).Methods("POST")
	// Read token from request header
	r.HandleFunc("/profile", controller.ProfileHandler).Methods("GET")

	// Get Access and Refresh token
	r.HandleFunc("/recieve_token/{guid}", controller.RecieveToken).Methods("POST")
	// Refresh tokens
	//r.HandleFunc("/refresh_token{guid}", controller.RefreshToken).Methods("PUT")
	// Delete token
	r.HandleFunc("/delete_token/{refresh_token}", controller.DeleteToken).Methods("DELETE")
	// Delete all tokens for User

	log.Fatal(http.ListenAndServe(":8000", r))
}