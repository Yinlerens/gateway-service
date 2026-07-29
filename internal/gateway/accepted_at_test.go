package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProxyOverwritesClientAcceptedAtWithTrustedGatewayTime(t *testing.T) {
	acceptedAt := time.Date(2026, time.July, 29, 12, 0, 0, 123456789, time.UTC)
	upstreamAcceptedAt := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAcceptedAt = r.Header.Get(requestAcceptedAtHeader)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL + "/v1")
	if err != nil {
		t.Fatal(err)
	}
	api := New(Options{
		Verifier:      &fakeVerifier{user: User{ID: uuid.New()}},
		InternalToken: "internal-secret",
		Routes: []Route{{
			Name:   "gacha",
			Prefix: "/api/v1/gacha",
			Target: target,
		}},
		Client: upstream.Client(),
		Now: func() time.Time {
			return acceptedAt
		},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/gacha/me/pulls", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	request.Header.Set(requestAcceptedAtHeader, "2000-01-01T00:00:00Z")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if upstreamAcceptedAt != acceptedAt.Format(time.RFC3339Nano) {
		t.Fatalf("expected trusted accepted time %q, got %q", acceptedAt.Format(time.RFC3339Nano), upstreamAcceptedAt)
	}
}
