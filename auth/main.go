package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"io"
)

type Login struct {
	HashPassword string
}

var secretKey = []byte("secret-key")

var users = map[string]Login{}

type LoginResponse struct {
	Token string
}

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

	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		if err == io.EOF {
			http.Error(w, "Register: Empty request", http.StatusBadRequest)
			return
		}
		http.Error(w, "Register: Error decoding request", http.StatusBadRequest)
		return
	}

	username := request.Username
	password := request.Password

	if username == "" || password == "" {
		http.Error(w, "Register: Username and password are required", http.StatusBadRequest)
		return
	}

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
}

func createToken(username string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		log.Fatal(err)
	}
	return tokenString
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

	tokenString := createToken(username)

	response := LoginResponse{Token: tokenString}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}


	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)



	users[username] = user

}

func protected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Login: ", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "protected: ", http.StatusUnauthorized)
		return
	}
	tokenString = tokenString[len("Bearer "):]
	if err := verifyToken(tokenString); err != nil {
		http.Error(w, "protected:", http.StatusUnauthorized)
		return
	}

	username := r.FormValue("username")
	fmt.Fprintf(w, "Welcome %s", username)
}

func logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "protected: ", http.StatusUnauthorized)
		return		
	}
	tokenString = tokenString[len("Bearer "):]
	if err := verifyToken(tokenString); err != nil {
		http.Error(w, "protected:", http.StatusUnauthorized)
		return
	}

	username := r.FormValue("username")
	user, _ := users[username]
	users[username] = user

}

var AuthError = errors.New("Unauthorized")

func verifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	   return secretKey, nil
	})
   
	if err != nil {
	   return err
	}
   
	if !token.Valid {
	   return fmt.Errorf("invalid token")
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
