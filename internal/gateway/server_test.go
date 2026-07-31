package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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

type fakeAuditSink struct {
	pingErr   error
	startErr  error
	finishErr error
	starts    []AuditEntry
	finishes  []AuditEntry
	closed    bool
}

type fakeAuditLogStore struct {
	listFilter AuditLogFilter
	listItems  []json.RawMessage
	listErr    error
	getID      uuid.UUID
	getItem    json.RawMessage
	getFound   bool
	getErr     error
}

func (f *fakeAuditLogStore) ListHTTPAPICalls(ctx context.Context, filter AuditLogFilter) ([]json.RawMessage, error) {
	f.listFilter = filter
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listItems, nil
}

func (f *fakeAuditLogStore) GetHTTPAPICall(ctx context.Context, requestID uuid.UUID) (json.RawMessage, bool, error) {
	f.getID = requestID
	if f.getErr != nil {
		return nil, false, f.getErr
	}
	return f.getItem, f.getFound, nil
}

func (f *fakeAuditSink) Ping(ctx context.Context) error {
	return f.pingErr
}

func (f *fakeAuditSink) Start(ctx context.Context, entry AuditEntry) error {
	if f.startErr != nil {
		return f.startErr
	}
	f.starts = append(f.starts, cloneAuditEntry(entry))
	return nil
}

func (f *fakeAuditSink) Finish(ctx context.Context, entry AuditEntry) error {
	if f.finishErr != nil {
		return f.finishErr
	}
	f.finishes = append(f.finishes, cloneAuditEntry(entry))
	return nil
}

func (f *fakeAuditSink) Close() {
	f.closed = true
}

func cloneAuditEntry(entry AuditEntry) AuditEntry {
	entry.RequestHeaders = append(json.RawMessage(nil), entry.RequestHeaders...)
	entry.ResponseHeaders = append(json.RawMessage(nil), entry.ResponseHeaders...)
	entry.RequestBody.JSON = append(json.RawMessage(nil), entry.RequestBody.JSON...)
	entry.ResponseBody.JSON = append(json.RawMessage(nil), entry.ResponseBody.JSON...)
	return entry
}

func TestProbeEndpointsDoNotEmitAccessLogs(t *testing.T) {
	logs := captureDefaultLogs(t)
	handler := newTestServer(t, &fakeVerifier{}, "http://example.test/v1").Handler()

	for _, path := range []string{"/health", "/ready"} {
		logs.Reset()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, response.Code)
		}
		if strings.Contains(logs.String(), `"msg":"http request"`) {
			t.Fatalf("%s: expected no access log, got %s", path, logs.String())
		}
	}
}

func TestBusinessEndpointStillEmitsAccessLog(t *testing.T) {
	logs := captureDefaultLogs(t)
	api := newTestServer(t, &fakeVerifier{}, "http://example.test/v1")
	request := httptest.NewRequest(http.MethodGet, "/api/v1/assets/me/account", nil)
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if !strings.Contains(logs.String(), `"msg":"http request"`) {
		t.Fatalf("expected business access log, got %s", logs.String())
	}
}

func captureDefaultLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})
	return &output
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

func TestAuditCapturesSuccessfulProxyRequestAndResponse(t *testing.T) {
	userID := uuid.New()
	clientRequestID := uuid.New()
	verifier := &fakeVerifier{user: User{ID: userID}}
	audit := &fakeAuditSink{}
	upstreamRequestID := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/me/credits" {
			t.Fatalf("expected /v1/me/credits, got %s", r.URL.Path)
		}
		if r.URL.RawQuery != "source=test" {
			t.Fatalf("expected query to be forwarded, got %q", r.URL.RawQuery)
		}
		upstreamRequestID = r.Header.Get(requestIDHeader)
		if _, err := uuid.Parse(upstreamRequestID); err != nil {
			t.Fatalf("expected generated request id to be forwarded, got %q", upstreamRequestID)
		}
		if upstreamRequestID == clientRequestID.String() {
			t.Fatal("expected gateway request id to differ from the client correlation id")
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("expected user credentials to be stripped before upstream")
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream request body: %v", err)
		}
		if string(payload) != `{"amount_minor":100}` {
			t.Fatalf("unexpected upstream request body: %s", payload)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", "asset")
		w.Header().Set("Set-Cookie", "should-not-be-audited=true")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true,"balance_minor":900}`))
	}))
	defer upstream.Close()

	api := newTestServerWithAudit(t, verifier, upstream.URL+"/v1", audit)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/assets/me/credits?source=test", strings.NewReader(`{"amount_minor":100}`))
	request.Header.Set("Authorization", "Bearer valid-token")
	request.Header.Set("Cookie", "sb-project-auth-token=should-not-leak")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(requestIDHeader, clientRequestID.String())
	request.Header.Set("X-Internal-Token", "client-spoof")
	request.Header.Set("X-User-Id", uuid.NewString())
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	internalRequestID, err := uuid.Parse(response.Header().Get(requestIDHeader))
	if err != nil {
		t.Fatalf("expected response request id to be a UUID, got %q", response.Header().Get(requestIDHeader))
	}
	if internalRequestID == clientRequestID {
		t.Fatal("expected response request id to be generated by the gateway")
	}
	if upstreamRequestID != internalRequestID.String() {
		t.Fatalf("expected upstream request id %s, got %q", internalRequestID, upstreamRequestID)
	}
	if len(audit.starts) != 1 || len(audit.finishes) != 1 {
		t.Fatalf("expected one audit start and finish, got %d starts and %d finishes", len(audit.starts), len(audit.finishes))
	}

	start := audit.starts[0]
	if start.RequestID != internalRequestID || start.ClientRequestID != clientRequestID.String() {
		t.Fatalf("unexpected audit request id: %s / %q", start.RequestID, start.ClientRequestID)
	}
	if start.Method != http.MethodPost || start.Path != "/api/v1/assets/me/credits" || start.RawQuery != "source=test" {
		t.Fatalf("unexpected audit request metadata: %+v", start)
	}
	if start.AuthResult != "not_checked" {
		t.Fatalf("expected start auth_result not_checked, got %q", start.AuthResult)
	}
	if start.RequestBody.Text != `{"amount_minor":100}` {
		t.Fatalf("unexpected audited request body: %q", start.RequestBody.Text)
	}
	assertJSONRawEqual(t, start.RequestBody.JSON, `{"amount_minor":100}`)

	requestHeaders := decodeHeaderJSON(t, start.RequestHeaders)
	for _, key := range []string{"Authorization", "Cookie", "X-Internal-Token", "X-User-Id"} {
		if _, ok := requestHeaders[key]; ok {
			t.Fatalf("expected %s to be stripped from audit request headers: %v", key, requestHeaders)
		}
	}
	if requestHeaders["Content-Type"][0] != "application/json" {
		t.Fatalf("expected content-type in audited request headers, got %v", requestHeaders)
	}

	finish := audit.finishes[0]
	if finish.ResponseStatus != http.StatusCreated || finish.Route != "assets" || finish.AuthResult != "authenticated" {
		t.Fatalf("unexpected finish audit metadata: %+v", finish)
	}
	if finish.UserID == nil || *finish.UserID != userID {
		t.Fatalf("expected user id %s, got %v", userID, finish.UserID)
	}
	if finish.UpstreamURL != upstream.URL+"/v1/me/credits?source=test" {
		t.Fatalf("unexpected upstream URL: %s", finish.UpstreamURL)
	}
	if finish.ResponseBody.Text != `{"ok":true,"balance_minor":900}` {
		t.Fatalf("unexpected audited response body: %q", finish.ResponseBody.Text)
	}
	assertJSONRawEqual(t, finish.ResponseBody.JSON, `{"balance_minor":900,"ok":true}`)

	responseHeaders := decodeHeaderJSON(t, finish.ResponseHeaders)
	if _, ok := responseHeaders["Set-Cookie"]; ok {
		t.Fatalf("expected Set-Cookie to be stripped from audit response headers: %v", responseHeaders)
	}
	if responseHeaders["X-Upstream"][0] != "asset" {
		t.Fatalf("expected upstream response header to be audited, got %v", responseHeaders)
	}
}

func TestRepeatedClientRequestIDGetsDistinctGatewayRequestIDs(t *testing.T) {
	clientRequestID := uuid.NewString()
	verifier := &fakeVerifier{user: User{ID: uuid.New()}}
	audit := &fakeAuditSink{}
	upstreamRequestIDs := make([]string, 0, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequestIDs = append(upstreamRequestIDs, r.Header.Get(requestIDHeader))
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	defer upstream.Close()

	api := newTestServerWithAudit(t, verifier, upstream.URL+"/v1", audit)
	responseRequestIDs := make([]string, 0, 2)
	for range 2 {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/assets/me/account", nil)
		request.Header.Set("Authorization", "Bearer valid-token")
		request.Header.Set(requestIDHeader, clientRequestID)
		response := httptest.NewRecorder()

		api.Handler().ServeHTTP(response, request)

		if response.Code != http.StatusOK {
			t.Fatalf("expected repeated client id request to reach upstream, got %d: %s", response.Code, response.Body.String())
		}
		responseRequestIDs = append(responseRequestIDs, response.Header().Get(requestIDHeader))
	}

	if responseRequestIDs[0] == responseRequestIDs[1] {
		t.Fatalf("expected distinct gateway request ids, got %q", responseRequestIDs[0])
	}
	if len(upstreamRequestIDs) != 2 || upstreamRequestIDs[0] != responseRequestIDs[0] || upstreamRequestIDs[1] != responseRequestIDs[1] {
		t.Fatalf("expected generated ids to propagate upstream, got responses=%v upstream=%v", responseRequestIDs, upstreamRequestIDs)
	}
	if len(audit.starts) != 2 || len(audit.finishes) != 2 {
		t.Fatalf("expected two complete audits, got %d starts and %d finishes", len(audit.starts), len(audit.finishes))
	}
	if audit.starts[0].RequestID == audit.starts[1].RequestID {
		t.Fatalf("expected distinct audit primary keys, got %s", audit.starts[0].RequestID)
	}
	for _, entry := range audit.starts {
		if entry.ClientRequestID != clientRequestID {
			t.Fatalf("expected client correlation id %q, got %q", clientRequestID, entry.ClientRequestID)
		}
	}
}

func TestClientRequestIDIsBoundedBeforeAuditPersistence(t *testing.T) {
	const expectedMaxClientRequestIDLength = 128
	header := http.Header{}
	header.Set(requestIDHeader, strings.Repeat("a", expectedMaxClientRequestIDLength+50))

	_, clientRequestID := requestIDsFromHeader(header)

	if len(clientRequestID) != expectedMaxClientRequestIDLength {
		t.Fatalf("expected client request id length %d, got %d", expectedMaxClientRequestIDLength, len(clientRequestID))
	}
}

func TestAuditCapturesUnauthorizedRequestAndResponse(t *testing.T) {
	audit := &fakeAuditSink{}
	api := newTestServerWithAudit(t, &fakeVerifier{}, "http://example.test/v1", audit)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/assets/me/credits", strings.NewReader(`{"amount_minor":100}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.Code)
	}
	if _, err := uuid.Parse(response.Header().Get(requestIDHeader)); err != nil {
		t.Fatalf("expected response request id header, got %q", response.Header().Get(requestIDHeader))
	}
	if len(audit.starts) != 1 || len(audit.finishes) != 1 {
		t.Fatalf("expected one audit start and finish, got %d starts and %d finishes", len(audit.starts), len(audit.finishes))
	}
	if audit.starts[0].RequestBody.Text != `{"amount_minor":100}` {
		t.Fatalf("unexpected audited request body: %q", audit.starts[0].RequestBody.Text)
	}
	finish := audit.finishes[0]
	if finish.ResponseStatus != http.StatusUnauthorized || finish.Route != "assets" || finish.AuthResult != "missing_session" {
		t.Fatalf("unexpected finish audit metadata: %+v", finish)
	}
	if finish.ResponseBody.Text != `{"error":{"code":"unauthorized","message":"login is required"}}` {
		t.Fatalf("unexpected audited response body: %q", finish.ResponseBody.Text)
	}
}

func TestAuditMarksOversizedRejectedRequestAsTruncated(t *testing.T) {
	audit := &fakeAuditSink{}
	api := newTestServerWithAudit(t, &fakeVerifier{}, "http://example.test/v1", audit)
	api.maxBodyBytes = 8
	api.auditMaxBodyBytes = 8

	request := httptest.NewRequest(http.MethodPost, "/api/v1/assets/me/credits", strings.NewReader(`{"too":"large"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d: %s", response.Code, response.Body.String())
	}
	if len(audit.starts) != 1 || len(audit.finishes) != 1 {
		t.Fatalf("expected one audit start and finish, got %d starts and %d finishes", len(audit.starts), len(audit.finishes))
	}
	start := audit.starts[0]
	if start.RequestBody.Text != `{"too":"` {
		t.Fatalf("unexpected audited truncated request body: %q", start.RequestBody.Text)
	}
	if start.RequestBody.Size != 9 || !start.RequestBody.Truncated {
		t.Fatalf("expected truncated request body size 9, got size=%d truncated=%v", start.RequestBody.Size, start.RequestBody.Truncated)
	}
	finish := audit.finishes[0]
	if finish.ResponseStatus != http.StatusRequestEntityTooLarge || finish.ErrorCode != "request_too_large" {
		t.Fatalf("unexpected finish audit metadata: %+v", finish)
	}
}

func TestAuditStartFailureFailsClosedBeforeAuthAndProxy(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
	}))
	defer upstream.Close()

	verifier := &fakeVerifier{}
	audit := &fakeAuditSink{startErr: errors.New("audit database down")}
	api := newTestServerWithAudit(t, verifier, upstream.URL+"/v1", audit)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/assets/me/account", nil)
	request.Header.Set("Authorization", "Bearer should-not-be-verified")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", response.Code, response.Body.String())
	}
	if verifier.token != "" {
		t.Fatalf("expected auth verifier not to be called, got token %q", verifier.token)
	}
	if upstreamCalled {
		t.Fatal("expected upstream not to be called")
	}
	if len(audit.finishes) != 0 {
		t.Fatalf("expected no audit finish after start failure, got %d", len(audit.finishes))
	}
}

func TestAuditLogListRequiresLogin(t *testing.T) {
	audit := &fakeAuditSink{}
	store := &fakeAuditLogStore{}
	api := newTestServerWithAuditLogs(t, &fakeVerifier{}, "http://example.test/v1", audit, store, uuid.New())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/http-api-calls", nil)
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", response.Code, response.Body.String())
	}
	if len(store.listItems) != 0 || store.listFilter.Limit != 0 {
		t.Fatal("expected audit log store not to be called")
	}
	if len(audit.starts) != 1 || len(audit.finishes) != 1 {
		t.Fatalf("expected audit record for denied admin request, got %d starts and %d finishes", len(audit.starts), len(audit.finishes))
	}
	if audit.finishes[0].ResponseStatus != http.StatusUnauthorized {
		t.Fatalf("expected audited 401, got %d", audit.finishes[0].ResponseStatus)
	}
}

func TestAuditLogListRejectsNonAdminUser(t *testing.T) {
	userID := uuid.New()
	audit := &fakeAuditSink{}
	store := &fakeAuditLogStore{}
	api := newTestServerWithAuditLogs(t, &fakeVerifier{user: User{ID: userID}}, "http://example.test/v1", audit, store, uuid.New())
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/http-api-calls", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", response.Code, response.Body.String())
	}
	if len(store.listItems) != 0 || store.listFilter.Limit != 0 {
		t.Fatal("expected audit log store not to be called")
	}
	if len(audit.finishes) != 1 || audit.finishes[0].UserID == nil || *audit.finishes[0].UserID != userID {
		t.Fatalf("expected audit finish to include user id, got %+v", audit.finishes)
	}
}

func TestAuditLogListReturnsFilteredRowsForAdmin(t *testing.T) {
	adminID := uuid.New()
	targetRequestID := uuid.New()
	targetUserID := uuid.New()
	audit := &fakeAuditSink{}
	store := &fakeAuditLogStore{
		listItems: []json.RawMessage{
			json.RawMessage(`{"request_id":"` + targetRequestID.String() + `","path":"/api/v1/gacha/me/pulls"}`),
		},
	}
	api := newTestServerWithAuditLogs(t, &fakeVerifier{user: User{ID: adminID}}, "http://example.test/v1", audit, store, adminID)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/http-api-calls?limit=25&path=/gacha&route=gacha&status=502&user_id="+targetUserID.String()+"&request_id="+targetRequestID.String(), nil)
	request.Header.Set("Authorization", "Bearer admin-token")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if store.listFilter.Limit != 25 {
		t.Fatalf("expected limit 25, got %d", store.listFilter.Limit)
	}
	if store.listFilter.PathContains != "/gacha" || store.listFilter.Route != "gacha" {
		t.Fatalf("unexpected filter path/route: %+v", store.listFilter)
	}
	if store.listFilter.ResponseStatus == nil || *store.listFilter.ResponseStatus != 502 {
		t.Fatalf("expected response status filter 502, got %+v", store.listFilter.ResponseStatus)
	}
	if store.listFilter.UserID == nil || *store.listFilter.UserID != targetUserID {
		t.Fatalf("expected user id filter %s, got %+v", targetUserID, store.listFilter.UserID)
	}
	if store.listFilter.RequestID == nil || *store.listFilter.RequestID != targetRequestID {
		t.Fatalf("expected request id filter %s, got %+v", targetRequestID, store.listFilter.RequestID)
	}

	var payload struct {
		Data []json.RawMessage `json:"data"`
		Meta struct {
			Count int `json:"count"`
			Limit int `json:"limit"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Meta.Count != 1 || payload.Meta.Limit != 25 || len(payload.Data) != 1 {
		t.Fatalf("unexpected response payload: %+v", payload)
	}
	if len(audit.finishes) != 1 || audit.finishes[0].ResponseStatus != http.StatusOK {
		t.Fatalf("expected audited 200, got %+v", audit.finishes)
	}
}

func TestAuditLogDetailReturnsSingleRowForAdmin(t *testing.T) {
	adminID := uuid.New()
	targetRequestID := uuid.New()
	audit := &fakeAuditSink{}
	store := &fakeAuditLogStore{
		getItem:  json.RawMessage(`{"request_id":"` + targetRequestID.String() + `","request_body_text":"{}"}`),
		getFound: true,
	}
	api := newTestServerWithAuditLogs(t, &fakeVerifier{user: User{ID: adminID}}, "http://example.test/v1", audit, store, adminID)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit/http-api-calls/"+targetRequestID.String(), nil)
	request.Header.Set("Authorization", "Bearer admin-token")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if store.getID != targetRequestID {
		t.Fatalf("expected detail request id %s, got %s", targetRequestID, store.getID)
	}
	if !strings.Contains(response.Body.String(), `"request_body_text":"{}"`) {
		t.Fatalf("expected response body to contain detail payload, got %s", response.Body.String())
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
	return newTestServerWithAudit(t, verifier, target, nil)
}

func newTestServerWithAudit(t *testing.T, verifier AuthVerifier, target string, auditSink AuditSink) *Server {
	return newTestServerWithAuditLogs(t, verifier, target, auditSink, nil)
}

func newTestServerWithAuditLogs(t *testing.T, verifier AuthVerifier, target string, auditSink AuditSink, auditLogStore AuditLogStore, adminUserIDs ...uuid.UUID) *Server {
	t.Helper()

	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}

	admins := make(map[uuid.UUID]struct{}, len(adminUserIDs))
	for _, id := range adminUserIDs {
		admins[id] = struct{}{}
	}

	return New(Options{
		Verifier:       verifier,
		InternalToken:  "internal-secret",
		AuthCookieName: "sb-project-auth-token",
		AuditSink:      auditSink,
		AuditLogStore:  auditLogStore,
		AdminUserIDs:   admins,
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

func decodeHeaderJSON(t *testing.T, payload json.RawMessage) map[string][]string {
	t.Helper()

	var headers map[string][]string
	if err := json.Unmarshal(payload, &headers); err != nil {
		t.Fatalf("decode header JSON: %v", err)
	}
	return headers
}

func assertJSONRawEqual(t *testing.T, actual json.RawMessage, expected string) {
	t.Helper()

	var actualValue any
	if err := json.Unmarshal(actual, &actualValue); err != nil {
		t.Fatalf("decode actual JSON %q: %v", string(actual), err)
	}
	var expectedValue any
	if err := json.Unmarshal([]byte(expected), &expectedValue); err != nil {
		t.Fatalf("decode expected JSON %q: %v", expected, err)
	}
	actualCanonical, _ := json.Marshal(actualValue)
	expectedCanonical, _ := json.Marshal(expectedValue)
	if string(actualCanonical) != string(expectedCanonical) {
		t.Fatalf("expected JSON %s, got %s", expectedCanonical, actualCanonical)
	}
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
