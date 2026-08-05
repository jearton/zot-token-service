package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	tokenVersion               = "v2"
	maxDependencyResponseBytes = 4096
)

var (
	buildVersion  = "dev"
	buildRevision = "unknown"
)

type server struct {
	service       string
	realm         string
	ttl           time.Duration
	tokenKey      []byte
	zotURL        string
	httpClient    *http.Client
	healthTimeout time.Duration
}

type accessEntry struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

type claims struct {
	Subject               string        `json:"sub"`
	Audience              string        `json:"aud"`
	IssuedAt              int64         `json:"iat"`
	NotBefore             int64         `json:"nbf"`
	ExpiresAt             int64         `json:"exp"`
	Access                []accessEntry `json:"access"`
	UpstreamAuthorization string        `json:"upstream_authorization,omitempty"`
}

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "healthcheck":
			if err := runHealthcheck(); err != nil {
				log.Fatal(err)
			}
			return
		case "version":
			fmt.Printf("%s %s\n", buildVersion, buildRevision)
			return
		}
	}

	srv, err := newServerFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	addr := envDefault("LISTEN_ADDR", ":8080")
	log.Printf("registry token service listening on %s for %s", addr, srv.service)
	log.Fatal(newHTTPServer(addr, withBuildHeaders(srv.handler())).ListenAndServe())
}

func newServerFromEnv() (*server, error) {
	service, err := requiredEnv("REGISTRY_SERVICE")
	if err != nil {
		return nil, err
	}
	realm, err := requiredHTTPURL("REGISTRY_REALM")
	if err != nil {
		return nil, err
	}
	zotURL, err := requiredHTTPURL("ZOT_URL")
	if err != nil {
		return nil, err
	}
	zotURL = strings.TrimRight(zotURL, "/")

	ttl, err := time.ParseDuration(envDefault("TOKEN_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("invalid TOKEN_TTL: %w", err)
	}
	if ttl <= 0 {
		return nil, errors.New("TOKEN_TTL must be positive")
	}

	encodedTokenKey := os.Getenv("TOKEN_ENCRYPTION_KEY")
	if encodedTokenKey == "" {
		return nil, errors.New("TOKEN_ENCRYPTION_KEY is required")
	}
	tokenKey, err := base64.StdEncoding.Strict().DecodeString(encodedTokenKey)
	if err != nil || len(tokenKey) != 32 {
		return nil, errors.New("TOKEN_ENCRYPTION_KEY must be a Base64-encoded 32-byte key")
	}

	authTimeout, err := time.ParseDuration(envDefault("ZOT_AUTH_TIMEOUT", "10s"))
	if err != nil || authTimeout <= 0 {
		return nil, errors.New("ZOT_AUTH_TIMEOUT must be a positive duration")
	}
	healthTimeout, err := time.ParseDuration(envDefault("ZOT_HEALTH_TIMEOUT", "3s"))
	if err != nil || healthTimeout <= 0 {
		return nil, errors.New("ZOT_HEALTH_TIMEOUT must be a positive duration")
	}

	return &server{
		service:       service,
		realm:         realm,
		ttl:           ttl,
		tokenKey:      tokenKey,
		zotURL:        zotURL,
		httpClient:    &http.Client{Timeout: authTimeout},
		healthTimeout: healthTimeout,
	}, nil
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/v2/", s.handleV2Ping)
	mux.HandleFunc("/authz", s.handleAuthz)
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.healthTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.zotURL, "/")+"/v2/", nil)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDependencyResponseBytes))

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}

func withBuildHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Zot-Token-Service-Version", buildVersion)
		w.Header().Set("X-Zot-Token-Service-Revision", buildRevision)
		next.ServeHTTP(w, r)
	})
}

func runHealthcheck() error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(envDefault("HEALTHCHECK_URL", "http://127.0.0.1:8080/healthz"))
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDependencyResponseBytes))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("healthcheck status: %d", resp.StatusCode)
	}
	return nil
}

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requested := parseScopeValues(r.URL.Query()["scope"])
	requiresPush := scopesRequirePush(requested)
	requiresValidBasic := requiresPush || len(requested) == 0

	subject := "anonymous"
	authenticated := false
	upstreamAuthorization := ""
	if user, password, ok := r.BasicAuth(); ok {
		valid, err := s.validateCredentials(r.Context(), user, password)
		if err != nil {
			log.Printf("Zot credential validation failed: %v", err)
			if requiresValidBasic {
				http.Error(w, "authentication service unavailable", http.StatusServiceUnavailable)
				return
			}
		} else if valid {
			subject = user
			authenticated = true
			upstreamAuthorization = basicAuthValue(user, password)
		} else if requiresValidBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+s.service+`"`)
			http.Error(w, "push requires login", http.StatusUnauthorized)
			return
		}
	} else if requiresPush {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+s.service+`"`)
		http.Error(w, "push requires login", http.StatusUnauthorized)
		return
	}

	allowed := make([]accessEntry, 0, len(requested))
	for _, entry := range requested {
		actions := filterAllowedActions(entry.Actions, authenticated)
		if len(actions) == 0 {
			continue
		}
		allowed = append(allowed, accessEntry{
			Type:    entry.Type,
			Name:    entry.Name,
			Actions: actions,
		})
	}

	now := time.Now().UTC()
	token, err := s.sign(claims{
		Subject:               subject,
		Audience:              s.service,
		IssuedAt:              now.Unix(),
		NotBefore:             now.Add(-30 * time.Second).Unix(),
		ExpiresAt:             now.Add(s.ttl).Unix(),
		Access:                allowed,
		UpstreamAuthorization: upstreamAuthorization,
	})
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":        token,
		"access_token": token,
		"expires_in":   int64(s.ttl.Seconds()),
		"issued_at":    now.Format(time.RFC3339),
	})
}

func (s *server) handleV2Ping(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authz := r.Header.Get("Authorization")
	if authz == "" && !isDockerClientUA(r.UserAgent()) {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	if authz != "" && !isBearerAuthorization(authz) {
		s.writeBearerChallenge(w, "")
		return
	}
	if _, ok := s.verifyRequestToken(r, "", ""); ok {
		w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
		w.WriteHeader(http.StatusOK)
		return
	}
	s.writeBearerChallenge(w, "")
}

func (s *server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	method := r.Header.Get("X-Original-Method")
	uri := r.Header.Get("X-Original-URI")
	if method == "" || uri == "" {
		http.Error(w, "missing original request metadata", http.StatusBadRequest)
		return
	}

	repository := repositoryFromV2URI(uri)
	action := requiredAction(method)
	authz := r.Header.Get("Authorization")
	if authz == "" && r.Header.Get("X-ZOT-API-CLIENT") == "zot-ui" && repository != "" && action == "push" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if authz == "" && !isDockerClientUA(r.Header.Get("X-Original-User-Agent")) && (action == "pull" || repository == "") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if authz != "" && !isBearerAuthorization(authz) {
		s.writeBearerChallenge(w, "")
		return
	}

	if repository == "" || action == "" {
		http.Error(w, "unsupported registry request", http.StatusForbidden)
		return
	}

	scope := fmt.Sprintf("repository:%s:%s", repository, action)
	claims, ok := s.verifyRequestToken(r, repository, action)
	if !ok {
		s.writeBearerChallenge(w, scope)
		return
	}

	if claims.UpstreamAuthorization != "" {
		w.Header().Set("X-Zot-Authorization", claims.UpstreamAuthorization)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) validateCredentials(ctx context.Context, user, password string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.zotURL, "/")+"/v2/", nil)
	if err != nil {
		return false, fmt.Errorf("create Zot authentication request: %w", err)
	}
	req.SetBasicAuth(user, password)
	req.Header.Set("User-Agent", "registry-token-service/1.0")

	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("authenticate with Zot: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDependencyResponseBytes))

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("authenticate with Zot: unexpected status %d", resp.StatusCode)
	}
}

func (s *server) verifyRequestToken(r *http.Request, repository, action string) (claims, bool) {
	authz := r.Header.Get("Authorization")
	fields := strings.Fields(authz)
	if !isBearerAuthorization(authz) {
		return claims{}, false
	}
	token := fields[1]
	claims, err := s.verify(token)
	if err != nil {
		return claims, false
	}
	if repository == "" && action == "" {
		return claims, true
	}
	return claims, hasAction(claims, repository, action)
}

func (s *server) writeBearerChallenge(w http.ResponseWriter, scope string) {
	value := fmt.Sprintf(`Bearer realm="%s",service="%s"`, s.realm, s.service)
	if scope != "" {
		value += fmt.Sprintf(`,scope="%s"`, scope)
	}
	w.Header().Set("WWW-Authenticate", value)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func (s *server) sign(c claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	aead, err := s.tokenAEAD()
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate token nonce: %w", err)
	}

	sealed := aead.Seal(nonce, nonce, payload, []byte(tokenVersion))
	return tokenVersion + "." + b64(sealed), nil
}

func (s *server) verify(token string) (claims, error) {
	prefix := tokenVersion + "."
	if !strings.HasPrefix(token, prefix) {
		return claims{}, errors.New("invalid token format")
	}

	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, prefix))
	if err != nil {
		return claims{}, err
	}

	aead, err := s.tokenAEAD()
	if err != nil {
		return claims{}, fmt.Errorf("initialize token cipher: %w", err)
	}
	if len(sealed) < aead.NonceSize() {
		return claims{}, errors.New("invalid token ciphertext")
	}

	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	payload, err := aead.Open(nil, nonce, ciphertext, []byte(tokenVersion))
	if err != nil {
		return claims{}, errors.New("invalid token ciphertext")
	}

	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return claims{}, err
	}
	now := time.Now().Unix()
	if c.Audience != s.service || now < c.NotBefore || now > c.ExpiresAt {
		return claims{}, errors.New("invalid token claims")
	}
	return c, nil
}

func (s *server) tokenAEAD() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.tokenKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func parseScopeValues(values []string) []accessEntry {
	entries := make([]accessEntry, 0, len(values))
	for _, value := range values {
		for _, raw := range strings.Fields(value) {
			parts := strings.SplitN(raw, ":", 3)
			if len(parts) != 3 {
				continue
			}
			actions := strings.Split(parts[2], ",")
			cleanActions := make([]string, 0, len(actions))
			for _, action := range actions {
				action = strings.TrimSpace(action)
				if action != "" {
					cleanActions = append(cleanActions, action)
				}
			}
			if parts[0] != "" && parts[1] != "" && len(cleanActions) > 0 {
				sort.Strings(cleanActions)
				entries = append(entries, accessEntry{Type: parts[0], Name: parts[1], Actions: cleanActions})
			}
		}
	}
	return entries
}

func scopesRequirePush(entries []accessEntry) bool {
	for _, entry := range entries {
		for _, action := range entry.Actions {
			if action != "pull" {
				return true
			}
		}
	}
	return false
}

func filterAllowedActions(actions []string, authenticated bool) []string {
	allowed := make([]string, 0, len(actions))
	for _, action := range actions {
		switch action {
		case "pull":
			allowed = append(allowed, action)
		case "push":
			if authenticated {
				allowed = append(allowed, action)
			}
		}
	}
	sort.Strings(allowed)
	return allowed
}

func hasAction(c claims, repository, action string) bool {
	for _, entry := range c.Access {
		if entry.Type != "repository" || entry.Name != repository {
			continue
		}
		for _, candidate := range entry.Actions {
			if candidate == action {
				return true
			}
		}
	}
	return false
}

func repositoryFromV2URI(rawURI string) string {
	parsed, err := url.ParseRequestURI(rawURI)
	if err != nil {
		return ""
	}
	path := strings.TrimPrefix(parsed.Path, "/v2/")
	if path == parsed.Path || path == "" {
		return ""
	}

	parts := strings.Split(path, "/")
	end := registryRouteStart(parts)
	if end > 0 {
		return strings.Join(parts[:end], "/")
	}
	return ""
}

func registryRouteStart(parts []string) int {
	n := len(parts)
	switch {
	case n >= 4 && parts[n-3] == "blobs" && parts[n-2] == "uploads":
		return n - 3
	case n >= 3 && parts[n-2] == "manifests":
		return n - 2
	case n >= 3 && parts[n-2] == "blobs":
		return n - 2
	case n >= 3 && parts[n-2] == "referrers":
		return n - 2
	case n >= 3 && parts[n-2] == "tags" && parts[n-1] == "list":
		return n - 2
	default:
		return -1
	}
}

func requiredAction(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return "pull"
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return "push"
	default:
		return ""
	}
}

func isDockerClientUA(ua string) bool {
	ua = strings.ToLower(ua)
	return strings.Contains(ua, "docker-client") || strings.HasPrefix(ua, "docker/")
}

func isBearerAuthorization(value string) bool {
	fields := strings.Fields(value)
	return len(fields) == 2 && strings.EqualFold(fields[0], "Bearer")
}

func basicAuthValue(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func b64(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func requiredEnv(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return value, nil
}

func requiredHTTPURL(key string) (string, error) {
	value, err := requiredEnv(key)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("%s must be an absolute HTTP or HTTPS URL", key)
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", fmt.Errorf("%s must not contain user information or a fragment", key)
	}
	return value, nil
}
