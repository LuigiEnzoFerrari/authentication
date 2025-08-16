package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Login struct {
	HashPassword string
	SessionToken string
	CSRFToken    string
}

var users = map[string]Login{}

func main() {

	fmt.Println("Hello, World!")
	http.HandleFunc("/", home)
	http.HandleFunc("/login", login)
	http.HandleFunc("/register", register)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":8080", nil)
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Hello, World!</h1>")
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Register: ", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if _, ok := users[username]; ok {
		http.Error(w, "Register: Username already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Register: Error hashing password", http.StatusInternalServerError)
		return
	}

	users[username] = Login{HashPassword: hashedPassword}
	fmt.Fprintf(w, "Register: %v", users)
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Login: ", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok {
		http.Error(w, "Login: User not found", http.StatusNotFound)
		return
	}

	if !checkPassword(password, user.HashPassword) {
		http.Error(w, "Login: Invalid password", http.StatusUnauthorized)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(1 * time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(1 * time.Hour),
		HttpOnly: false,
	})

	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken
	users[username] = user

	fmt.Fprintf(w, "Login: %v", users)
}

func protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Login: ", http.StatusMethodNotAllowed)
		return
	}
	if err := authorize(r); err != nil {
		http.Error(w, "protected:", http.StatusUnauthorized)

		return
	}

	username := r.FormValue("username")
	fmt.Fprintf(w, "Welcome %s", username)
}

func logout(w http.ResponseWriter, r *http.Request) {
	if err := authorize(r); err != nil {
		http.Error(w, "protected:", http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})
	username := r.FormValue("username")
	user, _ := users[username]
	user.SessionToken = ""
	user.CSRFToken = ""
	users[username] = user

}

var AuthError = errors.New("Unauthorized")

func authorize(r *http.Request) error {
	username := r.FormValue("username")
	user, ok := users[username]
	if !ok {
		return AuthError
	}

	st, err := r.Cookie("session_token")
	if err != nil {
		return err
	}

	if user.SessionToken != st.Value {
		return AuthError
	}

	csrf := r.Header.Get("X-CSRF-Token")
	if user.CSRFToken != csrf {
		return AuthError
	}
	return nil

}

func checkPassword(password string, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func generateToken(length int) string {
	token := make([]byte, length)
	if _, err := rand.Read(token); err != nil {
		log.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(token)
}
