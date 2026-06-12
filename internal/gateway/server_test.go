package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type fakeVerifier struct {
	user  User
	err   error
	token string
}

func (f *fakeVerifier) Verify(ctx context.Context, accessToken string) (User, error) {
	f.token = accessToken
	if f.err != nil {
		return User{}, f.err
	}
	return f.user, nil
}

func TestProtectedRouteRequiresLogin(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
	}))
	defer upstream.Close()

	api := newTestServer(t, &fakeVerifier{}, upstream.URL+"/v1")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/assets/me/account", nil)
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.Code)
	}
	if upstreamCalled {
		t.Fatal("expected unauthenticated request not to reach upstream")
	}
}

func TestProxyVerifiesSessionAndInjectsTrustedHeaders(t *testing.T) {
	userID := uuid.New()
	verifier := &fakeVerifier{user: User{ID: userID}}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/me/account" {
			t.Fatalf("expected /v1/me/account, got %s", r.URL.Path)
		}
		if r.URL.RawQuery != "limit=10" {
			t.Fatalf("expected query to be forwarded, got %q", r.URL.RawQuery)
		}
		if r.Header.Get("X-Internal-Token") != "internal-secret" {
			t.Fatalf("expected trusted internal token, got %q", r.Header.Get("X-Internal-Token"))
		}
		if r.Header.Get("X-User-Id") != userID.String() {
			t.Fatalf("expected verified user id, got %q", r.Header.Get("X-User-Id"))
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatal("expected user Authorization header to be stripped")
		}
		if r.Header.Get("Cookie") != "" {
			t.Fatal("expected browser cookies to be stripped")
		}
		if r.Header.Get("Idempotency-Key") != "entry-1" {
			t.Fatal("expected safe application headers to be forwarded")
		}

		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	defer upstream.Close()

	api := newTestServer(t, verifier, upstream.URL+"/v1")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/assets/me/account?limit=10", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	request.Header.Set("Cookie", "sb-project-auth-token=should-not-leak")
	request.Header.Set("X-Internal-Token", "client-spoof")
	request.Header.Set("X-User-Id", uuid.NewString())
	request.Header.Set("Idempotency-Key", "entry-1")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if verifier.token != "valid-token" {
		t.Fatalf("expected bearer token to be verified, got %q", verifier.token)
	}
}

func TestProxyAcceptsSupabaseSSRCookie(t *testing.T) {
	userID := uuid.New()
	verifier := &fakeVerifier{user: User{ID: userID}}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"user_id": r.Header.Get("X-User-Id")})
	}))
	defer upstream.Close()

	api := newTestServer(t, verifier, upstream.URL+"/v1")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/assets/me/account", nil)
	request.AddCookie(&http.Cookie{
		Name:  "sb-project-auth-token",
		Value: supabaseCookieValue(t, "cookie-token"),
	})
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if verifier.token != "cookie-token" {
		t.Fatalf("expected cookie token to be verified, got %q", verifier.token)
	}
}

func TestInvalidSessionIsRejectedBeforeProxy(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
	}))
	defer upstream.Close()

	api := newTestServer(t, &fakeVerifier{err: ErrInvalidSession}, upstream.URL+"/v1")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/assets/me/account", nil)
	request.Header.Set("Authorization", "Bearer expired-token")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.Code)
	}
	if upstreamCalled {
		t.Fatal("expected invalid session not to reach upstream")
	}
}

func TestSupabaseVerifierCallsAuthUserEndpoint(t *testing.T) {
	userID := uuid.New()
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/v1/user" {
			t.Fatalf("expected /auth/v1/user, got %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Fatalf("expected bearer token, got %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("apikey") != "anon-key" {
			t.Fatalf("expected anon key, got %q", r.Header.Get("apikey"))
		}

		writeJSON(w, http.StatusOK, map[string]string{"id": userID.String()})
	}))
	defer authServer.Close()

	verifier, err := NewSupabaseVerifier(authServer.URL, "anon-key", authServer.Client())
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	user, err := verifier.Verify(context.Background(), "access-token")
	if err != nil {
		t.Fatalf("verify user: %v", err)
	}
	if user.ID != userID {
		t.Fatalf("expected %s, got %s", userID, user.ID)
	}
}

func TestSupabaseVerifierTreatsAuth401AsInvalidSession(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "expired"})
	}))
	defer authServer.Close()

	verifier, err := NewSupabaseVerifier(authServer.URL, "anon-key", authServer.Client())
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	_, err = verifier.Verify(context.Background(), "expired-token")
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func newTestServer(t *testing.T, verifier AuthVerifier, target string) *Server {
	t.Helper()

	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	return New(Options{
		Verifier:       verifier,
		InternalToken:  "internal-secret",
		AuthCookieName: "sb-project-auth-token",
		Routes: []Route{{
			Name:   "assets",
			Prefix: "/api/v1/assets",
			Target: targetURL,
		}},
	})
}

func supabaseCookieValue(t *testing.T, token string) string {
	t.Helper()

	payload, err := json.Marshal(map[string]string{"access_token": token})
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}

	return "base64-" + base64.RawURLEncoding.EncodeToString(payload)
}

func TestUnknownRouteReturnsNotFoundWithoutAuth(t *testing.T) {
	api := newTestServer(t, &fakeVerifier{}, "http://example.test/v1")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/unknown", strings.NewReader(""))
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", response.Code)
	}
}
