package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"cloud.google.com/go/auth/credentials/idtoken"
)

type Payload struct {
	Expires int64
	Claims  map[string]any
}

type Verifier interface {
	Validate(context.Context, string, string) (*Payload, error)
}

type GoogleVerifier struct{}

func (GoogleVerifier) Validate(ctx context.Context, token, audience string) (*Payload, error) {
	payload, err := idtoken.Validate(ctx, token, audience)
	if err != nil {
		return nil, err
	}
	return &Payload{Expires: payload.Expires, Claims: payload.Claims}, nil
}

type KMS interface {
	Encrypt(context.Context, string, []byte) ([]byte, error)
	Decrypt(context.Context, string, []byte) ([]byte, error)
	GenerateDataKey(context.Context, string) ([]byte, []byte, error)
	Ping(context.Context) error
}

type Config struct {
	Audience              string
	AllowedServiceAccount string
	MaxBodyBytes          int64
}

type server struct {
	cfg      Config
	verifier Verifier
	kms      KMS
}

func New(cfg Config, verifier Verifier, kms KMS) (http.Handler, error) {
	if cfg.Audience == "" || cfg.AllowedServiceAccount == "" {
		return nil, errors.New("audience and allowed service account are required")
	}
	if cfg.MaxBodyBytes < 1 {
		return nil, errors.New("max body bytes must be positive")
	}
	if verifier == nil || kms == nil {
		return nil, errors.New("verifier and KMS are required")
	}
	s := &server{cfg: cfg, verifier: verifier, kms: kms}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/keys/{key}/encrypt", s.authorize(s.encrypt))
	mux.HandleFunc("POST /v1/keys/{key}/decrypt", s.authorize(s.decrypt))
	mux.HandleFunc("POST /v1/keys/{key}/generate-data-key", s.authorize(s.generateDataKey))
	return securityHeaders(mux), nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *server) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || len(header) <= 7 {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		payload, err := s.verifier.Validate(r.Context(), header[7:], s.cfg.Audience)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid identity token")
			return
		}
		email, _ := payload.Claims["email"].(string)
		verified, _ := payload.Claims["email_verified"].(bool)
		if !verified || email != s.cfg.AllowedServiceAccount {
			writeError(w, http.StatusForbidden, "service account is not authorized")
			return
		}
		next(w, r)
	}
}

type dataRequest struct {
	Data *string `json:"data"`
}

type dataResponse struct {
	Data string `json:"data"`
}

type dataKeyResponse struct {
	Plaintext string `json:"plaintext"`
	Wrapped   string `json:"wrapped"`
}

func (s *server) decode(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body := http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request dataRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return nil, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request must contain one JSON value")
		return nil, false
	}
	if request.Data == nil {
		writeError(w, http.StatusBadRequest, "data is required")
		return nil, false
	}
	data, err := base64.StdEncoding.DecodeString(*request.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "data must be standard base64")
		return nil, false
	}
	return data, true
}

func (s *server) encrypt(w http.ResponseWriter, r *http.Request) {
	data, ok := s.decode(w, r)
	if !ok {
		return
	}
	result, err := s.kms.Encrypt(r.Context(), r.PathValue("key"), data)
	if err != nil {
		writeError(w, http.StatusBadGateway, "marai encryption failed")
		return
	}
	writeJSON(w, http.StatusOK, dataResponse{Data: base64.StdEncoding.EncodeToString(result)})
}

func (s *server) decrypt(w http.ResponseWriter, r *http.Request) {
	data, ok := s.decode(w, r)
	if !ok {
		return
	}
	result, err := s.kms.Decrypt(r.Context(), r.PathValue("key"), data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "decryption failed")
		return
	}
	writeJSON(w, http.StatusOK, dataResponse{Data: base64.StdEncoding.EncodeToString(result)})
}

func (s *server) generateDataKey(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > 0 {
		writeError(w, http.StatusBadRequest, "request body must be empty")
		return
	}
	plaintext, wrapped, err := s.kms.GenerateDataKey(r.Context(), r.PathValue("key"))
	if err != nil {
		writeError(w, http.StatusBadGateway, "data-key generation failed")
		return
	}
	writeJSON(w, http.StatusOK, dataKeyResponse{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
		Wrapped:   base64.StdEncoding.EncodeToString(wrapped),
	})
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.kms.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "marai unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
