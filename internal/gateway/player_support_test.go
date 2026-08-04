package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPlayerSupportRejectsNonAdminUser(t *testing.T) {
	userID := uuid.New()
	targetID := uuid.New()
	api := newPlayerSupportTestServer(
		t,
		&fakeVerifier{user: User{ID: userID}},
		"http://example.test/v1",
		http.DefaultClient,
		&fakeAuditSink{},
		&fakeAuditLogStore{},
	)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/admin/player-support/players/"+targetID.String(),
		nil,
	)
	request.Header.Set("Authorization", "Bearer operator-token")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", response.Code, response.Body.String())
	}
}

func TestPlayerSupportAggregatesAllSourcesConcurrentlyForTargetPlayer(t *testing.T) {
	adminID := uuid.New()
	targetID := uuid.New()
	requestID := uuid.New()
	const expectedUpstreamCalls = 6

	var mu sync.Mutex
	paths := make([]string, 0, expectedUpstreamCalls)
	headerFailures := make([]string, 0)
	downstreamRequestIDs := make([]string, 0, expectedUpstreamCalls)
	allStarted := make(chan struct{})
	started := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.RequestURI())
		if r.Header.Get(userIDHeader) != targetID.String() {
			headerFailures = append(headerFailures, "wrong target user header")
		}
		if r.Header.Get(internalTokenHeader) != "internal-secret" {
			headerFailures = append(headerFailures, "wrong internal token")
		}
		downstreamRequestIDs = append(downstreamRequestIDs, r.Header.Get(requestIDHeader))
		started++
		if started == expectedUpstreamCalls {
			close(allStarted)
		}
		mu.Unlock()

		select {
		case <-allStarted:
		case <-r.Context().Done():
			return
		}

		switch r.URL.Path {
		case "/v1/me/account":
			writeJSON(w, http.StatusOK, map[string]any{"user_id": targetID.String(), "balance_minor": 3200})
		case "/v1/me/ledger":
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{map[string]any{
				"reason":   "gacha_pull",
				"metadata": map[string]any{"internal_note": "private-ledger-metadata"},
			}}})
		case "/v1/me/pulls/operations":
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{map[string]any{
				"status":           "event_published",
				"request_hash":     "private-request-hash",
				"recovery_context": map[string]any{"seed": "private-recovery-seed"},
			}}})
		case "/v1/me/inventory":
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{map[string]any{"item_id": "character-1"}}})
		case "/v1/me/pull-events":
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{map[string]any{
				"event_id": uuid.NewString(),
				"seed":     "private-event-seed",
			}}})
		case "/v1/me/pull-records":
			writeJSON(w, http.StatusOK, map[string]any{"items": []any{map[string]any{"item_name": "测试角色"}}})
		default:
			writeError(w, http.StatusNotFound, "not_found", "not found")
		}
	}))
	defer upstream.Close()

	audit := &fakeAuditSink{}
	auditLogs := &fakeAuditLogStore{listItems: []json.RawMessage{
		json.RawMessage(`{"request_id":"` + uuid.NewString() + `","response_status":200,"request_body_preview":"private-request-preview","response_body_preview":"private-response-preview"}`),
	}}
	api := newPlayerSupportTestServer(
		t,
		&fakeVerifier{user: User{ID: adminID}},
		upstream.URL+"/v1",
		upstream.Client(),
		audit,
		auditLogs,
		adminID,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/admin/player-support/players/"+targetID.String(),
		nil,
	).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer admin-token")
	request.Header.Set(requestIDHeader, requestID.String())
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	responseBody := response.Body.String()
	var payload playerSupportResponse
	if err := json.Unmarshal([]byte(responseBody), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, privateValue := range []string{
		"private-ledger-metadata",
		"private-request-hash",
		"private-recovery-seed",
		"private-event-seed",
		"private-request-preview",
		"private-response-preview",
	} {
		if strings.Contains(responseBody, privateValue) {
			t.Fatalf("player support response exposed private value %q: %s", privateValue, responseBody)
		}
	}
	if payload.PlayerID != targetID.String() || payload.Partial {
		t.Fatalf("unexpected response identity/partial state: %+v", payload)
	}
	for name, section := range map[string]playerSupportSection{
		"account":         payload.Sections.Account,
		"ledger":          payload.Sections.Ledger,
		"pull_operations": payload.Sections.PullOperations,
		"inventory":       payload.Sections.Inventory,
		"pull_events":     payload.Sections.PullEvents,
		"pull_records":    payload.Sections.PullRecords,
	} {
		if section.Status != playerSupportSectionOK || len(section.Data) == 0 {
			t.Fatalf("expected %s section to be available, got %+v", name, section)
		}
	}

	mu.Lock()
	gotPaths := append([]string(nil), paths...)
	gotHeaderFailures := append([]string(nil), headerFailures...)
	gotDownstreamRequestIDs := append([]string(nil), downstreamRequestIDs...)
	mu.Unlock()
	sort.Strings(gotPaths)
	expectedPaths := []string{
		"/v1/me/account?create=false",
		"/v1/me/inventory?limit=50",
		"/v1/me/ledger?limit=20",
		"/v1/me/pull-events?limit=20",
		"/v1/me/pull-records?limit=50",
		"/v1/me/pulls/operations?limit=20",
	}
	sort.Strings(expectedPaths)
	if len(gotHeaderFailures) != 0 {
		t.Fatalf("unexpected downstream headers: %v", gotHeaderFailures)
	}
	gatewayRequestID := response.Header().Get(requestIDHeader)
	if _, err := uuid.Parse(gatewayRequestID); err != nil {
		t.Fatalf("expected gateway request UUID, got %q", gatewayRequestID)
	}
	for _, downstreamRequestID := range gotDownstreamRequestIDs {
		if downstreamRequestID != gatewayRequestID {
			t.Fatalf("expected downstream request id %s, got %s", gatewayRequestID, downstreamRequestID)
		}
	}
	if len(gotPaths) != len(expectedPaths) {
		t.Fatalf("expected paths %v, got %v", expectedPaths, gotPaths)
	}
	for index := range expectedPaths {
		if gotPaths[index] != expectedPaths[index] {
			t.Fatalf("expected paths %v, got %v", expectedPaths, gotPaths)
		}
	}
	if strings.Contains(responseBody, "api_calls") {
		t.Fatalf("player support response should not include API calls: %s", responseBody)
	}
	if auditLogs.listFilter.UserID != nil || auditLogs.listFilter.Limit != 0 {
		t.Fatalf("player support should not query API logs, got %+v", auditLogs.listFilter)
	}
	if len(audit.finishes) != 1 || audit.finishes[0].Route != playerSupportAdminRouteName {
		t.Fatalf("expected one completed player support audit entry, got %+v", audit.finishes)
	}
	if audit.finishes[0].UserID == nil || *audit.finishes[0].UserID != adminID {
		t.Fatalf("expected audit actor %s, got %+v", adminID, audit.finishes[0].UserID)
	}
}

func TestPlayerSupportPullReplayAggregatesExactDurableEvidence(t *testing.T) {
	adminID := uuid.New()
	targetID := uuid.New()
	operationID := uuid.New()
	eventID := uuid.New()
	requestID := uuid.New()

	var mu sync.Mutex
	paths := make([]string, 0, 3)
	headerFailures := make([]string, 0)
	downstreamStarted := make(chan struct{})
	started := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.RequestURI())
		if r.Header.Get(userIDHeader) != targetID.String() {
			headerFailures = append(headerFailures, "wrong target user header")
		}
		if r.Header.Get(internalTokenHeader) != "internal-secret" {
			headerFailures = append(headerFailures, "wrong internal token")
		}
		isEvidence := r.URL.Path == "/v1/me/ledger-entry" || strings.HasPrefix(r.URL.Path, "/v1/me/pull-events/")
		if isEvidence {
			started++
			if started == 2 {
				close(downstreamStarted)
			}
		}
		mu.Unlock()

		if isEvidence {
			select {
			case <-downstreamStarted:
			case <-r.Context().Done():
				return
			}
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/pulls/operations/"+operationID.String()+"/replay"):
			writeJSON(w, http.StatusOK, map[string]any{
				"operation_id": operationID.String(),
				"request_id":   nil,
				"status":       "succeeded",
				"request": map[string]any{
					"source":       "persisted_result",
					"banner_id":    "limited-character-001",
					"count":        10,
					"seed":         "durable-seed",
					"event_id":     eventID.String(),
					"amount_minor": 1600,
				},
				"response":   map[string]any{"event_id": eventID.String(), "records": []any{}},
				"event":      map[string]any{"event_id": eventID.String(), "user_id": targetID.String()},
				"error":      nil,
				"created_at": "2026-08-04T01:00:00Z",
				"updated_at": "2026-08-04T01:00:01Z",
			})
		case r.URL.Path == "/v1/me/ledger-entry":
			if r.URL.Query().Get("idempotency_key") != "spend:gacha-pull:"+eventID.String() {
				writeError(w, http.StatusBadRequest, "wrong_key", "wrong idempotency key")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"id":                   uuid.NewString(),
				"idempotency_key":      "spend:gacha-pull:" + eventID.String(),
				"delta_minor":          -1600,
				"balance_before_minor": 3200,
				"balance_after_minor":  1600,
				"reason":               "gacha_pull",
				"metadata":             map[string]any{"private": "must-not-leak"},
				"created_at":           "2026-08-04T01:00:00Z",
			})
		case r.URL.Path == "/v1/me/pull-events/"+eventID.String():
			writeJSON(w, http.StatusOK, map[string]any{
				"event": map[string]any{
					"event_id":      eventID.String(),
					"event_type":    "gacha.pull_completed.v1",
					"banner_id":     "limited-character-001",
					"seed":          "durable-seed",
					"state_version": 9,
					"previous_pity": map[string]any{"version": 8},
					"next_pity":     map[string]any{"version": 9},
					"received_at":   "2026-08-04T01:00:02Z",
				},
				"records": []any{map[string]any{
					"id": uuid.NewString(), "event_id": eventID.String(), "index": 0,
					"item_id": "character-1", "item_name": "测试角色", "item_type": "character",
					"rarity": 5, "banner_id": "limited-character-001", "banner_name": "测试卡池",
					"pity_at_five": 80, "pity_at_four": 1, "is_featured": true,
				}},
			})
		default:
			writeError(w, http.StatusNotFound, "not_found", "not found")
		}
	}))
	defer upstream.Close()

	api := newPlayerSupportTestServer(
		t,
		&fakeVerifier{user: User{ID: adminID}},
		upstream.URL+"/v1",
		upstream.Client(),
		&fakeAuditSink{},
		&fakeAuditLogStore{},
		adminID,
	)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/admin/player-support/players/"+targetID.String()+"/pulls/"+operationID.String()+"/replay",
		nil,
	)
	request.Header.Set("Authorization", "Bearer admin-token")
	request.Header.Set(requestIDHeader, requestID.String())
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var payload playerSupportPullReplayResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.PlayerID != targetID.String() || payload.Operation.OperationID != operationID.String() {
		t.Fatalf("unexpected replay identity: %+v", payload)
	}
	if payload.Partial || payload.AssetSpend.Status != playerSupportSectionOK || payload.BackpackDelivery.Status != playerSupportSectionOK {
		t.Fatalf("expected complete replay evidence, got %+v", payload)
	}
	if strings.Contains(response.Body.String(), "must-not-leak") {
		t.Fatalf("replay exposed unprojected asset metadata: %s", response.Body.String())
	}

	mu.Lock()
	gotPaths := append([]string(nil), paths...)
	gotHeaderFailures := append([]string(nil), headerFailures...)
	mu.Unlock()
	if len(gotHeaderFailures) != 0 {
		t.Fatalf("unexpected downstream headers: %v", gotHeaderFailures)
	}
	if len(gotPaths) != 3 {
		t.Fatalf("expected exact gacha, asset, and backpack lookups, got %v", gotPaths)
	}
}

func TestPlayerSupportPullReplayKeepsMissingDeliveryVisible(t *testing.T) {
	adminID := uuid.New()
	targetID := uuid.New()
	operationID := uuid.New()
	eventID := uuid.New()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/pulls/operations/"):
			writeJSON(w, http.StatusOK, map[string]any{
				"operation_id": operationID.String(),
				"status":       "succeeded",
				"request":      map[string]any{"event_id": eventID.String()},
				"response":     map[string]any{"event_id": eventID.String()},
				"event":        map[string]any{"event_id": eventID.String()},
				"created_at":   "2026-08-04T01:00:00Z",
				"updated_at":   "2026-08-04T01:00:01Z",
			})
		default:
			writeError(w, http.StatusNotFound, "not_found", "not found")
		}
	}))
	defer upstream.Close()
	api := newPlayerSupportTestServer(t, &fakeVerifier{user: User{ID: adminID}}, upstream.URL+"/v1", upstream.Client(), &fakeAuditSink{}, &fakeAuditLogStore{}, adminID)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/player-support/players/"+targetID.String()+"/pulls/"+operationID.String()+"/replay", nil)
	request.Header.Set("Authorization", "Bearer admin-token")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var payload playerSupportPullReplayResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.AssetSpend.Status != playerSupportSectionNotFound || payload.BackpackDelivery.Status != playerSupportSectionNotFound {
		t.Fatalf("expected missing evidence to remain visible, got %+v", payload)
	}
}

func TestPlayerSupportReturnsPartialEvidenceWhenOneSourceFails(t *testing.T) {
	adminID := uuid.New()
	targetID := uuid.New()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/me/pulls/operations" {
			writeError(w, http.StatusServiceUnavailable, "state_store_unavailable", "unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}})
	}))
	defer upstream.Close()

	api := newPlayerSupportTestServer(
		t,
		&fakeVerifier{user: User{ID: adminID}},
		upstream.URL+"/v1",
		upstream.Client(),
		&fakeAuditSink{},
		&fakeAuditLogStore{},
		adminID,
	)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/admin/player-support/players/"+targetID.String(),
		nil,
	)
	request.Header.Set("Authorization", "Bearer admin-token")
	response := httptest.NewRecorder()

	api.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var payload playerSupportResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.Partial {
		t.Fatal("expected partial response")
	}
	if payload.Sections.PullOperations.Status != playerSupportSectionUnavailable {
		t.Fatalf("expected pull operations unavailable, got %+v", payload.Sections.PullOperations)
	}
	if payload.Sections.Inventory.Status != playerSupportSectionOK {
		t.Fatalf("expected inventory evidence to remain available, got %+v", payload.Sections.Inventory)
	}
}

func newPlayerSupportTestServer(
	t *testing.T,
	verifier AuthVerifier,
	target string,
	client *http.Client,
	auditSink AuditSink,
	auditLogStore AuditLogStore,
	adminUserIDs ...uuid.UUID,
) *Server {
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
		Client:         client,
		AuditSink:      auditSink,
		AuditLogStore:  auditLogStore,
		AdminUserIDs:   admins,
		Routes: []Route{
			{Name: "assets", Prefix: "/api/v1/assets", Target: targetURL},
			{Name: "gacha", Prefix: "/api/v1/gacha", Target: targetURL},
			{Name: "backpack", Prefix: "/api/v1/backpack", Target: targetURL},
		},
	})
}
