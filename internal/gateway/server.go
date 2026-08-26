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

type TenantRoute struct {
	TenantID  string
	Audiences []string
	Callers   []string
	KMS       KMS
}

type MultiConfig struct {
	MaxBodyBytes int64
	Routes       []TenantRoute
}

type server struct {
	cfg       Config
	verifier  Verifier
	kms       KMS
	routes    []TenantRoute
	healthKMS []KMS
}

type kmsContextKey struct{}

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
	s := &server{cfg: cfg, verifier: verifier, kms: kms, healthKMS: []KMS{kms}}
	return s.handler(s.authorize), nil
}

func NewMulti(cfg MultiConfig, verifier Verifier) (http.Handler, error) {
	if cfg.MaxBodyBytes < 1 {
		return nil, errors.New("max body bytes must be positive")
	}
	if verifier == nil {
		return nil, errors.New("verifier is required")
	}
	if len(cfg.Routes) == 0 {
		return nil, errors.New("at least one tenant route is required")
	}
	seen := make(map[string]string)
	health := make([]KMS, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		if route.TenantID == "" || len(route.Audiences) == 0 || len(route.Callers) == 0 || route.KMS == nil {
			return nil, errors.New("tenant route requires tenant id, audiences, callers, and KMS")
		}
		for _, audience := range route.Audiences {
			if audience == "" {
				return nil, errors.New("tenant route audience is empty")
			}
			for _, caller := range route.Callers {
				if caller == "" {
					return nil, errors.New("tenant route caller is empty")
				}
				key := audience + "\x00" + caller
				if existing, ok := seen[key]; ok && existing != route.TenantID {
					return nil, errors.New("ambiguous audience and caller mapping")
				}
				seen[key] = route.TenantID
			}
		}
		health = append(health, route.KMS)
	}
	s := &server{
		cfg:       Config{MaxBodyBytes: cfg.MaxBodyBytes},
		verifier:  verifier,
		routes:    cfg.Routes,
		healthKMS: health,
	}
	return s.handler(s.authorizeMulti), nil
}

func (s *server) handler(authorize func(http.HandlerFunc) http.HandlerFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/keys/{key}/encrypt", authorize(s.encrypt))
	mux.HandleFunc("POST /v1/keys/{key}/decrypt", authorize(s.decrypt))
	mux.HandleFunc("POST /v1/keys/{key}/generate-data-key", authorize(s.generateDataKey))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") || len(header) <= 7 {
		return "", false
	}
	return header[7:], true
}

func (s *server) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		payload, err := s.verifier.Validate(r.Context(), token, s.cfg.Audience)
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

func (s *server) authorizeMulti(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		audiences, err := unverifiedAudiences(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid identity token")
			return
		}
		for _, audience := range audiences {
			for _, route := range s.routes {
				if !contains(route.Audiences, audience) {
					continue
				}
				payload, err := s.verifier.Validate(r.Context(), token, audience)
				if err != nil {
					continue
				}
				email, _ := payload.Claims["email"].(string)
				verified, _ := payload.Claims["email_verified"].(bool)
				if !verified || !contains(route.Callers, email) {
					continue
				}
				ctx := context.WithValue(r.Context(), kmsContextKey{}, route.KMS)
				next(w, r.WithContext(ctx))
				return
			}
		}
		writeError(w, http.StatusForbidden, "service account is not authorized")
	}
}

func unverifiedAudiences(token string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud == "" {
			return nil, errors.New("empty audience")
		}
		return []string{aud}, nil
	case []any:
		values := make([]string, 0, len(aud))
		for _, value := range aud {
			text, ok := value.(string)
			if !ok || text == "" {
				return nil, errors.New("invalid audience")
			}
			values = append(values, text)
		}
		if len(values) == 0 {
			return nil, errors.New("empty audience")
		}
		return values, nil
	default:
		return nil, errors.New("missing audience")
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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

func (s *server) kmsForRequest(r *http.Request) KMS {
	if selected, ok := r.Context().Value(kmsContextKey{}).(KMS); ok && selected != nil {
		return selected
	}
	return s.kms
}

func (s *server) encrypt(w http.ResponseWriter, r *http.Request) {
	data, ok := s.decode(w, r)
	if !ok {
		return
	}
	result, err := s.kmsForRequest(r).Encrypt(r.Context(), r.PathValue("key"), data)
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
	result, err := s.kmsForRequest(r).Decrypt(r.Context(), r.PathValue("key"), data)
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
	plaintext, wrapped, err := s.kmsForRequest(r).GenerateDataKey(r.Context(), r.PathValue("key"))
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
	for _, kms := range s.healthKMS {
		if err := kms.Ping(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "marai unavailable")
			return
		}
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
