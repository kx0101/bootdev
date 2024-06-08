package main

import (
	"chirpy/database"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

var (
	secretKey = os.Getenv("JWT_SECRET")
)

type apiConfig struct {
	mu             sync.Mutex
	fileserverHits int
	jwtSecret      string
}

type ResponseError struct {
	Error string `json:"error"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.mu.Lock()
		defer cfg.mu.Unlock()

		cfg.fileserverHits++

		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handleMetrics(w http.ResponseWriter, r *http.Request) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, `
        <html>
        <body>
            <h1>Welcome, Chirpy Admin</h1>
            <p>Chirpy has been visited %d times!</p>
        </body>
        </html>
    `, cfg.fileserverHits)
}

func (cfg *apiConfig) handleReset(w http.ResponseWriter, _ *http.Request) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	cfg.fileserverHits = 0

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
}

func writeJSONReponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("error encoding response: %s", err)
	}
}

func createJWT(user database.User, secretKey []byte, expiresInSeconds int) (string, error) {
	if expiresInSeconds == 0 || expiresInSeconds > 24*36000 {
		expiresInSeconds = 24 * 36000
	}

	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Duration(expiresInSeconds) * time.Second)),
		Subject:   strconv.Itoa(user.Id),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func getChirps(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chirps, err := db.GetChirps()
		if err != nil {
			writeJSONReponse(w, http.StatusInternalServerError, ResponseError{Error: err.Error()})
			return
		}

		writeJSONReponse(w, http.StatusOK, chirps)
	}
}

func getChirp(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("chirpId")
		parsedId, err := strconv.Atoi(id)
		if err != nil {
			writeJSONReponse(w, http.StatusBadRequest, ResponseError{Error: err.Error()})
			return
		}

		chirp, err := db.GetChirp(parsedId)
		if err != nil {
			writeJSONReponse(w, http.StatusNotFound, ResponseError{Error: err.Error()})
			return
		}

		writeJSONReponse(w, http.StatusOK, chirp)
	}
}

func login(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody struct {
			Email            string `json:"email"`
			Password         string `json:"password"`
			ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			writeJSONReponse(w, http.StatusBadRequest, ResponseError{Error: "Invalid request body"})
			return
		}

		user, err := db.Login(database.User{
			Email:    requestBody.Email,
			Password: requestBody.Password,
		})
		if err != nil {
			switch err.Error() {
			case "user not found":
				writeJSONReponse(w, http.StatusNotFound, ResponseError{Error: err.Error()})
			case "invalid credentials":
				writeJSONReponse(w, http.StatusUnauthorized, ResponseError{Error: err.Error()})
			default:
				writeJSONReponse(w, http.StatusInternalServerError, ResponseError{Error: "Internal Server Error"})
			}
			return
		}

		token, err := createJWT(user, []byte(secretKey), requestBody.ExpiresInSeconds)
		if err != nil {
			writeJSONReponse(w, http.StatusInternalServerError, ResponseError{Error: err.Error()})
		}

		responseBody := struct {
			Id    int    `json:"id"`
			Email string `json:"email"`
			Token string `json:"token"`
		}{
			Id:    user.Id,
			Email: user.Email,
			Token: token,
		}

		writeJSONReponse(w, http.StatusOK, responseBody)
	}
}

func extractJWT(r *http.Request, secretKey []byte) (*jwt.Token, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("authorization header is required")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return nil, fmt.Errorf("authorization header format must be Bearer {token}")
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func updateUser(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := extractJWT(r, []byte(secretKey))
		if err != nil {
			writeJSONReponse(w, http.StatusUnauthorized, ResponseError{Error: err.Error()})
			return
		}

		claims, ok := token.Claims.(*jwt.RegisteredClaims)
		if !ok || claims.Subject == "" {
			writeJSONReponse(w, http.StatusUnauthorized, ResponseError{Error: "invalid token claims"})
			return
		}

		userId, err := strconv.Atoi(claims.Subject)
		if err != nil {
			writeJSONReponse(w, http.StatusInternalServerError, ResponseError{Error: "invalid user ID"})
			return
		}

		var requestBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if errParse := json.NewDecoder(r.Body).Decode(&requestBody); errParse != nil {
			writeJSONReponse(w, http.StatusBadRequest, ResponseError{Error: "invalid request body"})
			return
		}

		err = db.UpdateUser(database.User{
			Id:       userId,
			Email:    requestBody.Email,
			Password: requestBody.Password,
		})

		if err != nil {
			writeJSONReponse(w, http.StatusInternalServerError, ResponseError{Error: err.Error()})
			return
		}

		writeJSONReponse(w, http.StatusOK, struct {
			Id    int    `json:"id"`
			Email string `json:"email"`
		}{Id: userId, Email: requestBody.Email})
	}
}

func createUser(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			writeJSONReponse(w, http.StatusBadRequest, ResponseError{Error: "Invalid request body"})
			return
		}

		user, err := db.CreateUser(database.User{
			Email:    requestBody.Email,
			Password: requestBody.Password,
		})
		if err != nil {
			writeJSONReponse(w, http.StatusBadRequest, ResponseError{Error: err.Error()})
			return
		}

		writeJSONReponse(w, http.StatusCreated, user)
	}
}

func createChirp(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody struct {
			Body string `json:"body"`
		}

		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			writeJSONReponse(w, http.StatusBadRequest, ResponseError{Error: "Invalid request body"})
			return
		}

		chirp, err := db.CreateChirp(requestBody.Body)
		if err != nil {
			writeJSONReponse(w, http.StatusBadRequest, ResponseError{Error: err.Error()})
			return
		}

		writeJSONReponse(w, http.StatusCreated, chirp)
	}
}

func main() {
	godotenv.Load()
	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatalf("error while creating database: %s", err)
		return
	}

	apiCfg := apiConfig{}
	mux := http.NewServeMux()

	fileServerHandler := apiCfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))
	mux.Handle("/app/", http.StripPrefix("/app", fileServerHandler))
	mux.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("./assets"))))

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
	mux.HandleFunc("/api/reset", apiCfg.handleReset)

	mux.HandleFunc("POST /api/chirps", createChirp(db))
	mux.HandleFunc("GET /api/chirps", getChirps(db))
	mux.HandleFunc("GET /api/chirps/{chirpId}", getChirp(db))

	mux.HandleFunc("POST /api/users", createUser(db))
	mux.HandleFunc("POST /api/login", login(db))
	mux.HandleFunc("PUT /api/users", updateUser(db))

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	fmt.Println("server is running on 8080")
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("error: %s", err)
	}
}