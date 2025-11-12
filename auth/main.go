package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

type Login struct {
	HashPassword string
}

var (
	secretKey []byte
	connStr   string
	appPort   string
)

type LoginResponse struct {
	Token string
}

func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func init() {
	// Load configuration from environment with sensible defaults
	dbHost := getenv("DB_HOST", "localhost")
	dbPort := getenv("DB_PORT", "5433")
	dbUser := getenv("DB_USER", "user")
	dbPassword := getenv("DB_PASSWORD", "password")
	dbName := getenv("DB_NAME", "mydb")

	secretKey = []byte(getenv("SECRET_KEY", "secret-key"))
	appPort = getenv("APP_PORT", "8080")

	connStr = fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName,
	)
}

func main() {

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatalf("Unable to open database connection: %v\n", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Unable to ping database: %v\n", err)
	}

	log.Println("Successfully connected to PostgreSQL!")

	fmt.Println("Hello, World!")
	http.HandleFunc("/", home)
	http.HandleFunc("/login", login)
	http.HandleFunc("/register", register)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/protected", protected)
	http.ListenAndServe(":"+appPort, nil)
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Hello, World!</h1>")
}

func register(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("pgx", connStr)
	if r.Method != http.MethodPost {
		http.Error(w, "Register: ", http.StatusMethodNotAllowed)
		return
	}
	defer db.Close()

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

	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Register: Error hashing password", http.StatusInternalServerError)
		return
	}

	query := "INSERT INTO users (username, hash_password) VALUES ($1, $2)"
	_, err = db.Exec(query, username, hashedPassword)
	if err != nil {
		http.Error(w, "Register: Error inserting user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User registered successfully"))

}

func createToken(username string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		log.Fatal(err)
	}
	return tokenString
}

func login(w http.ResponseWriter, r *http.Request) {

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatalf("Unable to open database connection: %v\n", err)
	}

	defer db.Close()

	if r.Method != http.MethodPost {
		http.Error(w, "Login: ", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	query := "SELECT hash_password FROM users WHERE username = $1"
	rows, err := db.Query(query, username)
	if err != nil {
		http.Error(w, "Login: Error querying user", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	if !rows.Next() {
		http.Error(w, "Login: User not found", http.StatusNotFound)
		return
	}

	var hashedPassword string
	rows.Scan(&hashedPassword)

	if !checkPassword(password, hashedPassword) {
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

}

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
