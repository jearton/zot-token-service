package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateCredentialsDelegatesUsernameAndAPIKeyToZot(t *testing.T) {
	const (
		username = "user@example.com"
		apiKey   = "zak_valid"
	)

	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/" {
			t.Fatalf("path = %q, want /v2/", r.URL.Path)
		}
		if got := r.UserAgent(); got != "registry-token-service/1.0" {
			t.Fatalf("User-Agent = %q, want registry-token-service/1.0", got)
		}

		gotUser, gotAPIKey, ok := r.BasicAuth()
		if !ok || gotUser != username || gotAPIKey != apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer zot.Close()

	s := newTestServer(t)
	s.zotURL = zot.URL
	s.httpClient = zot.Client()

	valid, err := s.validateCredentials(context.Background(), username, apiKey)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("valid Zot credentials were rejected")
	}

	valid, err = s.validateCredentials(context.Background(), "other-user", apiKey)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("API key with the wrong username was accepted")
	}
}

func TestNewServerFromEnvDoesNotRequireStaticPushCredentials(t *testing.T) {
	setRequiredServerEnv(t)
	t.Setenv("TOKEN_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("TOKEN_HMAC_SECRET", "")
	t.Setenv("ZOT_PUSH_USERNAME", "")
	t.Setenv("ZOT_PUSH_PASSWORD", "")
	t.Setenv("ZOT_URL", "http://zot:5000")
	t.Setenv("ZOT_AUTH_TIMEOUT", "7s")
	t.Setenv("ZOT_HEALTH_TIMEOUT", "4s")

	s, err := newServerFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if s.zotURL != "http://zot:5000" {
		t.Fatalf("zotURL = %q", s.zotURL)
	}
	if s.httpClient.Timeout != 7*time.Second {
		t.Fatalf("http client timeout = %s, want 7s", s.httpClient.Timeout)
	}
	if s.healthTimeout != 4*time.Second {
		t.Fatalf("health timeout = %s, want 4s", s.healthTimeout)
	}
}

func TestNewServerFromEnvAuthTimeoutExceedsZotFailDelay(t *testing.T) {
	setRequiredServerEnv(t)
	t.Setenv("TOKEN_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("ZOT_AUTH_TIMEOUT", "")

	s, err := newServerFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if s.httpClient.Timeout != 10*time.Second {
		t.Fatalf("default auth timeout = %s, want 10s", s.httpClient.Timeout)
	}
}

func TestNewServerFromEnvRequiresRuntimeConfiguration(t *testing.T) {
	required := []string{"REGISTRY_SERVICE", "REGISTRY_REALM", "ZOT_URL", "TOKEN_ENCRYPTION_KEY"}
	for _, key := range required {
		t.Run(key, func(t *testing.T) {
			setRequiredServerEnv(t)
			t.Setenv(key, "")

			_, err := newServerFromEnv()
			if err == nil || !strings.Contains(err.Error(), key+" is required") {
				t.Fatalf("newServerFromEnv() error = %v, want missing %s", err, key)
			}
		})
	}
}

func TestNewServerFromEnvValidatesRuntimeURLs(t *testing.T) {
	tests := []struct {
		key   string
		value string
		want  string
	}{
		{key: "REGISTRY_REALM", value: "registry.example.com/token", want: "absolute HTTP or HTTPS URL"},
		{key: "REGISTRY_REALM", value: "https://user@example.com/token", want: "must not contain user information"},
		{key: "ZOT_URL", value: "tcp://zot:5000", want: "absolute HTTP or HTTPS URL"},
		{key: "ZOT_URL", value: "http://zot:5000/#fragment", want: "must not contain user information or a fragment"},
	}

	for _, tt := range tests {
		t.Run(tt.key+"/"+tt.value, func(t *testing.T) {
			setRequiredServerEnv(t)
			t.Setenv(tt.key, tt.value)

			_, err := newServerFromEnv()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("newServerFromEnv() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRepositoryFromV2URI(t *testing.T) {
	tests := map[string]string{
		"/v2/smoke/busybox/manifests/latest":                "smoke/busybox",
		"/v2/smoke/busybox/blobs/sha256:abc":                "smoke/busybox",
		"/v2/team/app/api/blobs/uploads/?mount=abc":         "team/app/api",
		"/v2/team/app/api/tags/list":                        "team/app/api",
		"/v2/team/app/api/referrers/sha256:abc?artifact":    "team/app/api",
		"/v2/review/manifests/probe/manifests/latest":       "review/manifests/probe",
		"/v2/review/blobs/probe/blobs/sha256:abc":           "review/blobs/probe",
		"/v2/review/blobs/uploads/blobs/uploads/session-id": "review/blobs/uploads",
		"/v2/review/tags/list/tags/list":                    "review/tags/list",
		"/v2/review/referrers/probe/referrers/sha256:abc":   "review/referrers/probe",
		"/v2/review/probe/blobs/uploads/":                   "review/probe",
		"/v2/review/probe/unknown/value":                    "",
		"/v2/":                                              "",
		"/home":                                             "",
	}

	for input, want := range tests {
		if got := repositoryFromV2URI(input); got != want {
			t.Fatalf("repositoryFromV2URI(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestScopeParsingAndPolicy(t *testing.T) {
	entries := parseScopeValues([]string{"repository:smoke/busybox:pull,push"})
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if !scopesRequirePush(entries) {
		t.Fatal("push scope should require authentication")
	}

	anonymous := filterAllowedActions(entries[0].Actions, false)
	if len(anonymous) != 1 || anonymous[0] != "pull" {
		t.Fatalf("anonymous actions = %#v, want pull only", anonymous)
	}

	authenticated := filterAllowedActions(entries[0].Actions, true)
	if len(authenticated) != 2 || authenticated[0] != "pull" || authenticated[1] != "push" {
		t.Fatalf("authenticated actions = %#v, want pull,push", authenticated)
	}
}

func TestTokenSignVerifyAndAccess(t *testing.T) {
	s := &server{
		service:  "registry.example.com",
		ttl:      time.Minute,
		tokenKey: []byte("01234567890123456789012345678901"),
	}
	now := time.Now().UTC()
	token, err := s.sign(claims{
		Subject:   "anonymous",
		Audience:  s.service,
		IssuedAt:  now.Unix(),
		NotBefore: now.Add(-time.Second).Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Access: []accessEntry{{
			Type:    "repository",
			Name:    "smoke/busybox",
			Actions: []string{"pull"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAction(got, "smoke/busybox", "pull") {
		t.Fatal("verified token should allow pull")
	}
	if hasAction(got, "smoke/busybox", "push") {
		t.Fatal("verified token should not allow push")
	}
}

func TestRequiredAction(t *testing.T) {
	if got := requiredAction(http.MethodGet); got != "pull" {
		t.Fatalf("GET action = %q", got)
	}
	if got := requiredAction(http.MethodPatch); got != "push" {
		t.Fatalf("PATCH action = %q", got)
	}
}

func TestIsDockerClientUA(t *testing.T) {
	if !isDockerClientUA("docker/29.4.0 go/go1.25.0") {
		t.Fatal("docker/ user agent should match")
	}
	if !isDockerClientUA("UpstreamClient(Docker-Client/29.4.0)") {
		t.Fatal("Docker-Client user agent should match")
	}
	if isDockerClientUA("Mozilla/5.0") {
		t.Fatal("browser user agent should not match")
	}
}

func TestV2PingAuthorizationPolicy(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	validToken, err := s.sign(claims{
		Subject:   "anonymous",
		Audience:  s.service,
		IssuedAt:  now.Unix(),
		NotBefore: now.Add(-time.Second).Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	authorizations := []struct {
		name  string
		value string
	}{
		{name: "empty"},
		{name: "basic", value: basicAuthValue("user@example.com", "secret")},
		{name: "unsupported", value: "Digest opaque"},
		{name: "valid bearer", value: "Bearer " + validToken},
		{name: "invalid bearer", value: "Bearer " + tokenVersion + ".invalid"},
	}
	userAgents := []struct {
		name  string
		value string
	}{
		{name: "docker", value: "docker/29.4.0"},
		{name: "browser", value: "Mozilla/5.0"},
	}

	for _, authorization := range authorizations {
		for _, userAgent := range userAgents {
			t.Run(authorization.name+"/"+userAgent.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
				req.Header.Set("User-Agent", userAgent.value)
				if authorization.value != "" {
					req.Header.Set("Authorization", authorization.value)
				}
				rr := httptest.NewRecorder()

				s.handleV2Ping(rr, req)

				wantStatus := http.StatusUnauthorized
				if authorization.name == "valid bearer" ||
					(authorization.name == "empty" && userAgent.name == "browser") {
					wantStatus = http.StatusOK
				}
				if rr.Code != wantStatus {
					t.Fatalf("status = %d, want %d", rr.Code, wantStatus)
				}
				if wantStatus == http.StatusOK {
					if got := rr.Header().Get("Docker-Distribution-API-Version"); got != "registry/2.0" {
						t.Fatalf("Docker-Distribution-API-Version = %q", got)
					}
					if got := rr.Header().Get("WWW-Authenticate"); got != "" {
						t.Fatalf("WWW-Authenticate = %q, want empty", got)
					}
					return
				}
				if got := rr.Header().Get("WWW-Authenticate"); got != `Bearer realm="https://registry.example.com/token",service="registry.example.com"` {
					t.Fatalf("WWW-Authenticate = %q", got)
				}
			})
		}
	}
}

func TestPullTokenUsesValidBasicSubjectWhenProvided(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull", nil)
	req.SetBasicAuth("user@example.com", "secret")
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	got := decodeTokenClaims(t, s, body.Token)
	if got.Subject != "user@example.com" {
		t.Fatalf("subject = %q, want authenticated user", got.Subject)
	}
	if !hasAction(got, "smoke/busybox", "pull") {
		t.Fatal("token should allow pull")
	}
}

func TestPullTokenIgnoresInvalidBasicAndUsesAnonymousSubject(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull", nil)
	req.SetBasicAuth("user@example.com", "wrong")
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	got := decodeTokenClaims(t, s, body.Token)
	if got.Subject != "anonymous" {
		t.Fatalf("subject = %q, want anonymous", got.Subject)
	}
	if !hasAction(got, "smoke/busybox", "pull") {
		t.Fatal("token should allow pull")
	}
}

func TestPullTokenWithoutBasicUsesAnonymousSubject(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull", nil)
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	got := decodeTokenClaims(t, s, body.Token)
	if got.Subject != "anonymous" {
		t.Fatalf("subject = %q, want anonymous", got.Subject)
	}
	if got.UpstreamAuthorization != "" {
		t.Fatal("anonymous token contains upstream credentials")
	}
}

func TestPullTokenFallsBackToAnonymousWhenZotIsUnavailable(t *testing.T) {
	s := newTestServer(t)
	s.httpClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}

	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull", nil)
	req.SetBasicAuth("user@example.com", "secret")
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	got := decodeTokenClaims(t, s, body.Token)
	if got.Subject != "anonymous" {
		t.Fatalf("subject = %q, want anonymous", got.Subject)
	}
}

func TestTokenWithoutScopeRejectsInvalidBasic(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	req.SetBasicAuth("user@example.com", "wrong")
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != `Basic realm="registry.example.com"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestPushTokenRejectsInvalidBasic(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull,push", nil)
	req.SetBasicAuth("user@example.com", "wrong")
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != `Basic realm="registry.example.com"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestPushTokenRejectsMissingBasic(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull,push", nil)
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestPushTokenReturnsServiceUnavailableWhenZotIsUnavailable(t *testing.T) {
	s := newTestServer(t)
	s.httpClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}

	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull,push", nil)
	req.SetBasicAuth("user@example.com", "secret")
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
}

func TestPushTokenUsesCredentialsAcceptedByZot(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull,push", nil)
	req.SetBasicAuth("user@example.com", "secret")
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
}

func TestIssuedTokenIsOpaqueAndDoesNotExposeAPIKey(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull,push", nil)
	req.SetBasicAuth("user@example.com", "secret")
	rr := httptest.NewRecorder()

	s.handleToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body.Token, tokenVersion+".") {
		t.Fatalf("token does not use the opaque %s format: %q", tokenVersion, body.Token)
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(body.Token, tokenVersion+"."))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") {
		t.Fatal("opaque token exposes the API key")
	}
}

func TestModifiedTokenIsRejected(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	token, err := s.sign(claims{
		Subject:   "anonymous",
		Audience:  s.service,
		IssuedAt:  now.Unix(),
		NotBefore: now.Add(-time.Second).Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, tokenVersion+"."))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	tampered := tokenVersion + "." + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := s.verify(tampered); err == nil {
		t.Fatal("modified token was accepted")
	}
}

func TestAuthzForwardsCredentialsCapturedDuringTokenExchange(t *testing.T) {
	s := newTestServer(t)

	tokenReq := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull,push", nil)
	tokenReq.SetBasicAuth("user@example.com", "secret")
	tokenRR := httptest.NewRecorder()
	s.handleToken(tokenRR, tokenReq)
	if tokenRR.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", tokenRR.Code, tokenRR.Body.String())
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokenRR.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	authzReq := httptest.NewRequest(http.MethodGet, "/authz", nil)
	authzReq.Header.Set("Authorization", "Bearer "+body.Token)
	authzReq.Header.Set("X-Original-Method", http.MethodPut)
	authzReq.Header.Set("X-Original-URI", "/v2/smoke/busybox/manifests/latest")
	authzReq.Header.Set("X-Original-User-Agent", "Mozilla/5.0")
	authzRR := httptest.NewRecorder()

	s.handleAuthz(authzRR, authzReq)

	if authzRR.Code != http.StatusNoContent {
		t.Fatalf("authz status = %d, body = %s", authzRR.Code, authzRR.Body.String())
	}
	want := basicAuthValue("user@example.com", "secret")
	if got := authzRR.Header().Get("X-Zot-Authorization"); got != want {
		t.Fatalf("X-Zot-Authorization = %q, want credentials accepted by Zot", got)
	}
}

func TestAuthzRejectsBasicForNonDockerUserAgent(t *testing.T) {
	s := newTestServer(t)

	authzReq := httptest.NewRequest(http.MethodGet, "/authz", nil)
	authzReq.SetBasicAuth("user@example.com", "secret")
	authzReq.Header.Set("X-Original-Method", http.MethodGet)
	authzReq.Header.Set("X-Original-URI", "/v2/smoke/busybox/manifests/latest")
	authzReq.Header.Set("X-Original-User-Agent", "Mozilla/5.0")
	authzRR := httptest.NewRecorder()

	s.handleAuthz(authzRR, authzReq)

	if authzRR.Code != http.StatusUnauthorized {
		t.Fatalf("authz status = %d, want 401", authzRR.Code)
	}
	if got := authzRR.Header().Get("X-Zot-Authorization"); got != "" {
		t.Fatalf("X-Zot-Authorization = %q, want no forwarded credentials", got)
	}
}

func TestAuthzAllowsNonDockerRequestWithoutAuthorization(t *testing.T) {
	s := newTestServer(t)

	authzReq := httptest.NewRequest(http.MethodGet, "/authz", nil)
	authzReq.Header.Set("X-Original-Method", http.MethodGet)
	authzReq.Header.Set("X-Original-URI", "/v2/_zot/ext/search")
	authzReq.Header.Set("X-Original-User-Agent", "Mozilla/5.0")
	authzRR := httptest.NewRecorder()

	s.handleAuthz(authzRR, authzReq)

	if authzRR.Code != http.StatusNoContent {
		t.Fatalf("authz status = %d, want 204", authzRR.Code)
	}
}

func TestAuthzChallengesUnauthenticatedNonDockerPush(t *testing.T) {
	s := newTestServer(t)

	authzReq := httptest.NewRequest(http.MethodGet, "/authz", nil)
	authzReq.Header.Set("X-Original-Method", http.MethodPut)
	authzReq.Header.Set("X-Original-URI", "/v2/devcontainers/features/docker-outside-of-docker/manifests/latest")
	authzReq.Header.Set("X-Original-User-Agent", "devcontainers-cli/0.87.0")
	authzRR := httptest.NewRecorder()

	s.handleAuthz(authzRR, authzReq)

	if authzRR.Code != http.StatusUnauthorized {
		t.Fatalf("authz status = %d, want 401", authzRR.Code)
	}
	want := `Bearer realm="` + s.realm + `",service="` + s.service + `",scope="repository:devcontainers/features/docker-outside-of-docker:push"`
	if got := authzRR.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestAuthzAllowsZotUIWriteWithoutBearer(t *testing.T) {
	s := newTestServer(t)

	authzReq := httptest.NewRequest(http.MethodGet, "/authz", nil)
	authzReq.Header.Set("X-Original-Method", http.MethodDelete)
	authzReq.Header.Set("X-Original-URI", "/v2/backend/unione-message-gateway/manifests/buildcache")
	authzReq.Header.Set("X-Original-User-Agent", "Mozilla/5.0")
	authzReq.Header.Set("X-ZOT-API-CLIENT", "zot-ui")
	authzRR := httptest.NewRecorder()

	s.handleAuthz(authzRR, authzReq)

	if authzRR.Code != http.StatusNoContent {
		t.Fatalf("authz status = %d, want 204", authzRR.Code)
	}
	if got := authzRR.Header().Get("X-Zot-Authorization"); got != "" {
		t.Fatalf("X-Zot-Authorization = %q, want no forwarded credentials", got)
	}
}

func TestAuthzDoesNotForwardCredentialsForAnonymousPull(t *testing.T) {
	s := newTestServer(t)

	tokenReq := httptest.NewRequest(http.MethodGet, "/token?scope=repository:smoke/busybox:pull", nil)
	tokenRR := httptest.NewRecorder()
	s.handleToken(tokenRR, tokenReq)
	if tokenRR.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", tokenRR.Code, tokenRR.Body.String())
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokenRR.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	authzReq := httptest.NewRequest(http.MethodGet, "/authz", nil)
	authzReq.Header.Set("Authorization", "Bearer "+body.Token)
	authzReq.Header.Set("X-Original-Method", http.MethodGet)
	authzReq.Header.Set("X-Original-URI", "/v2/smoke/busybox/manifests/latest")
	authzReq.Header.Set("X-Original-User-Agent", "docker/29.4.0")
	authzRR := httptest.NewRecorder()

	s.handleAuthz(authzRR, authzReq)

	if authzRR.Code != http.StatusNoContent {
		t.Fatalf("authz status = %d, body = %s", authzRR.Code, authzRR.Body.String())
	}
	if got := authzRR.Header().Get("X-Zot-Authorization"); got != "" {
		t.Fatalf("anonymous authz forwarded credentials: %q", got)
	}
}

func TestHealthz(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		err        error
		want       int
	}{
		{name: "zot ready", statusCode: http.StatusOK, want: http.StatusNoContent},
		{name: "zot requires authentication", statusCode: http.StatusUnauthorized, want: http.StatusNoContent},
		{name: "zot failure", statusCode: http.StatusInternalServerError, want: http.StatusServiceUnavailable},
		{name: "zot transport failure", err: context.DeadlineExceeded, want: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestServer(t)
			s.healthTimeout = time.Second
			s.httpClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				if tt.err != nil {
					return nil, tt.err
				}
				return &http.Response{
					StatusCode: tt.statusCode,
					Body:       http.NoBody,
					Header:     make(http.Header),
				}, nil
			})}

			rr := httptest.NewRecorder()
			s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))

			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d", rr.Code, tt.want)
			}
		})
	}
}

func TestLivez(t *testing.T) {
	s := newTestServer(t)
	s.httpClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	})}

	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/livez", nil))

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestBuildHeaders(t *testing.T) {
	oldVersion, oldRevision := buildVersion, buildRevision
	buildVersion = "1.2.3"
	buildRevision = "abc123"
	t.Cleanup(func() {
		buildVersion = oldVersion
		buildRevision = oldRevision
	})

	handler := withBuildHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/livez", nil))

	if got := rr.Header().Get("X-Zot-Token-Service-Version"); got != buildVersion {
		t.Fatalf("version header = %q, want %q", got, buildVersion)
	}
	if got := rr.Header().Get("X-Zot-Token-Service-Revision"); got != buildRevision {
		t.Fatalf("revision header = %q, want %q", got, buildRevision)
	}
}

func TestHTTPServerBounds(t *testing.T) {
	httpServer := newHTTPServer(":8080", http.NotFoundHandler())

	if httpServer.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %s, want 5s", httpServer.ReadHeaderTimeout)
	}
	if httpServer.ReadTimeout != 15*time.Second {
		t.Fatalf("ReadTimeout = %s, want 15s", httpServer.ReadTimeout)
	}
	if httpServer.WriteTimeout != 20*time.Second {
		t.Fatalf("WriteTimeout = %s, want 20s", httpServer.WriteTimeout)
	}
	if httpServer.IdleTimeout != 60*time.Second {
		t.Fatalf("IdleTimeout = %s, want 60s", httpServer.IdleTimeout)
	}
	if httpServer.MaxHeaderBytes != 32<<10 {
		t.Fatalf("MaxHeaderBytes = %d, want %d", httpServer.MaxHeaderBytes, 32<<10)
	}
}

func TestRunHealthcheck(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{name: "ready", statusCode: http.StatusNoContent},
		{name: "not ready", statusCode: http.StatusServiceUnavailable, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()
			t.Setenv("HEALTHCHECK_URL", server.URL)

			err := runHealthcheck()
			if (err != nil) != tt.wantErr {
				t.Fatalf("runHealthcheck() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newTestServer(t *testing.T) *server {
	t.Helper()

	zot := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "user@example.com" || password != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(zot.Close)

	return &server{
		service:    "registry.example.com",
		realm:      "https://registry.example.com/token",
		ttl:        time.Minute,
		tokenKey:   []byte("01234567890123456789012345678901"),
		zotURL:     zot.URL,
		httpClient: zot.Client(),
	}
}

func setRequiredServerEnv(t *testing.T) {
	t.Helper()
	t.Setenv("REGISTRY_SERVICE", "registry.example.com")
	t.Setenv("REGISTRY_REALM", "https://registry.example.com/token")
	t.Setenv("ZOT_URL", "http://zot:5000")
	t.Setenv("TOKEN_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
}

func decodeTokenClaims(t *testing.T, s *server, token string) claims {
	t.Helper()
	got, err := s.verify(token)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
