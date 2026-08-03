package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	playerSupportAdminRouteName     = "player-support-admin"
	playerSupportSectionOK          = "ok"
	playerSupportSectionNotFound    = "not_found"
	playerSupportSectionUnavailable = "unavailable"
	playerSupportAuditLogLimit      = 20
)

type playerSupportResponse struct {
	PlayerID    string                `json:"player_id"`
	GeneratedAt time.Time             `json:"generated_at"`
	Partial     bool                  `json:"partial"`
	Sections    playerSupportSections `json:"sections"`
}

type playerSupportSections struct {
	Account        playerSupportSection `json:"account"`
	Ledger         playerSupportSection `json:"ledger"`
	PullOperations playerSupportSection `json:"pull_operations"`
	Inventory      playerSupportSection `json:"inventory"`
	PullEvents     playerSupportSection `json:"pull_events"`
	PullRecords    playerSupportSection `json:"pull_records"`
	APICalls       playerSupportSection `json:"api_calls"`
}

type playerSupportSection struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data"`
	Error  *apiError       `json:"error,omitempty"`
}

type playerSupportSectionResult struct {
	name    string
	section playerSupportSection
}

type playerSupportUpstreamQuery struct {
	name          string
	routeName     string
	path          string
	query         url.Values
	allowNotFound bool
}

type playerSupportPage[T any] struct {
	Items []T `json:"items"`
}

type playerSupportAccount struct {
	BalanceMinor int64  `json:"balance_minor"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

type playerSupportLedgerEntry struct {
	ID                 string `json:"id,omitempty"`
	IdempotencyKey     string `json:"idempotency_key,omitempty"`
	DeltaMinor         int64  `json:"delta_minor"`
	BalanceBeforeMinor int64  `json:"balance_before_minor"`
	BalanceAfterMinor  int64  `json:"balance_after_minor"`
	Reason             string `json:"reason,omitempty"`
	CreatedAt          string `json:"created_at,omitempty"`
}

type playerSupportPitySnapshot struct {
	SinceFive              int  `json:"since_five"`
	SinceFour              int  `json:"since_four"`
	GuaranteedFeaturedFive bool `json:"guaranteed_featured_five"`
	Version                int  `json:"version"`
}

type playerSupportOperation struct {
	OperationID     string                     `json:"operation_id,omitempty"`
	EventID         *string                    `json:"event_id"`
	RequestID       *string                    `json:"request_id"`
	BannerID        *string                    `json:"banner_id"`
	BannerVersionID *string                    `json:"banner_version_id"`
	PityGroupID     *string                    `json:"pity_group_id"`
	Count           *int                       `json:"count"`
	Status          string                     `json:"status"`
	Error           *apiError                  `json:"error"`
	NextPity        *playerSupportPitySnapshot `json:"next_pity"`
	CreatedAt       string                     `json:"created_at,omitempty"`
	UpdatedAt       string                     `json:"updated_at,omitempty"`
}

type playerSupportInventoryItem struct {
	ItemID    string `json:"item_id,omitempty"`
	ItemName  string `json:"item_name,omitempty"`
	ItemType  string `json:"item_type,omitempty"`
	Rarity    int    `json:"rarity"`
	Quantity  int64  `json:"quantity"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type playerSupportPullEvent struct {
	EventID      string `json:"event_id,omitempty"`
	BannerID     string `json:"banner_id,omitempty"`
	StateVersion int64  `json:"state_version"`
	ReceivedAt   string `json:"received_at,omitempty"`
}

type playerSupportPullRecord struct {
	ID         string `json:"id,omitempty"`
	EventID    string `json:"event_id,omitempty"`
	Index      int    `json:"index"`
	ItemID     string `json:"item_id,omitempty"`
	ItemName   string `json:"item_name,omitempty"`
	ItemType   string `json:"item_type,omitempty"`
	Rarity     int    `json:"rarity"`
	BannerID   string `json:"banner_id,omitempty"`
	BannerName string `json:"banner_name,omitempty"`
	PityAtFive int    `json:"pity_at_five"`
	PityAtFour int    `json:"pity_at_four"`
	IsFeatured bool   `json:"is_featured"`
	ReceivedAt string `json:"received_at,omitempty"`
}

type playerSupportAPICall struct {
	RequestID      string  `json:"request_id,omitempty"`
	StartedAt      string  `json:"started_at,omitempty"`
	FinishedAt     *string `json:"finished_at"`
	DurationMS     *int64  `json:"duration_ms"`
	Method         string  `json:"method,omitempty"`
	Path           string  `json:"path,omitempty"`
	RawQuery       string  `json:"raw_query,omitempty"`
	Route          *string `json:"route"`
	AuthResult     string  `json:"auth_result,omitempty"`
	ResponseStatus *int    `json:"response_status"`
	ErrorCode      *string `json:"error_code"`
	ErrorMessage   *string `json:"error_message"`
	AuditStatus    string  `json:"audit_status,omitempty"`
}

func (s *Server) handlePlayerSupport(w http.ResponseWriter, r *http.Request) {
	entry, request := s.beginDirectAudit(w, r, playerSupportAdminRouteName)
	if !s.startAuditOrFail(w, request, entry) {
		return
	}

	user, ok := s.authorizeAuditLogAdmin(w, request, entry)
	if !ok {
		return
	}
	entry.UserID = &user.ID

	playerID, err := uuid.Parse(strings.TrimSpace(r.PathValue("user_id")))
	if err != nil {
		s.writeAuditedError(w, request, entry, http.StatusBadRequest, "invalid_user_id", "user_id must be a UUID")
		return
	}

	response := s.loadPlayerSupport(request, playerID)
	s.writeAuditedJSON(w, request, entry, http.StatusOK, response)
}

func (s *Server) loadPlayerSupport(r *http.Request, playerID uuid.UUID) playerSupportResponse {
	queries := []playerSupportUpstreamQuery{
		{
			name:          "account",
			routeName:     "assets",
			path:          "/me/account",
			query:         url.Values{"create": {"false"}},
			allowNotFound: true,
		},
		{
			name:      "ledger",
			routeName: "assets",
			path:      "/me/ledger",
			query:     url.Values{"limit": {"20"}},
		},
		{
			name:      "pull_operations",
			routeName: "gacha",
			path:      "/me/pulls/operations",
			query:     url.Values{"limit": {"20"}},
		},
		{
			name:      "inventory",
			routeName: "backpack",
			path:      "/me/inventory",
			query:     url.Values{"limit": {"50"}},
		},
		{
			name:      "pull_events",
			routeName: "backpack",
			path:      "/me/pull-events",
			query:     url.Values{"limit": {"20"}},
		},
		{
			name:      "pull_records",
			routeName: "backpack",
			path:      "/me/pull-records",
			query:     url.Values{"limit": {"50"}},
		},
	}

	results := make(chan playerSupportSectionResult, len(queries)+1)
	var workers sync.WaitGroup
	workers.Add(len(queries) + 1)
	for _, query := range queries {
		query := query
		go func() {
			defer workers.Done()
			results <- playerSupportSectionResult{
				name:    query.name,
				section: s.loadPlayerSupportUpstream(r, playerID, query),
			}
		}()
	}
	go func() {
		defer workers.Done()
		results <- playerSupportSectionResult{
			name:    "api_calls",
			section: s.loadPlayerSupportAuditCalls(r, playerID),
		}
	}()

	workers.Wait()
	close(results)

	response := playerSupportResponse{
		PlayerID:    playerID.String(),
		GeneratedAt: s.now().UTC(),
	}
	for result := range results {
		response.Partial = response.Partial || result.section.Status == playerSupportSectionUnavailable
		switch result.name {
		case "account":
			response.Sections.Account = result.section
		case "ledger":
			response.Sections.Ledger = result.section
		case "pull_operations":
			response.Sections.PullOperations = result.section
		case "inventory":
			response.Sections.Inventory = result.section
		case "pull_events":
			response.Sections.PullEvents = result.section
		case "pull_records":
			response.Sections.PullRecords = result.section
		case "api_calls":
			response.Sections.APICalls = result.section
		}
	}

	return response
}

func (s *Server) loadPlayerSupportUpstream(
	r *http.Request,
	playerID uuid.UUID,
	query playerSupportUpstreamQuery,
) playerSupportSection {
	route, ok := s.routeByName(query.routeName)
	if !ok {
		return unavailablePlayerSupportSection("route_unavailable", query.routeName+" route is unavailable")
	}

	target := *route.Target
	target.Path = joinURLPath(route.Target.Path, query.path)
	target.RawQuery = query.query.Encode()
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		return unavailablePlayerSupportSection("request_unavailable", "upstream request could not be created")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set(internalTokenHeader, s.internalToken)
	request.Header.Set(userIDHeader, playerID.String())
	request.Header.Set(requestIDHeader, requestIDFromContext(r.Context()))

	response, err := s.client.Do(request)
	if err != nil {
		slog.Warn(
			"player support upstream request failed",
			"section", query.name,
			"route", query.routeName,
			"request_id", requestIDFromContext(r.Context()),
			"error", err,
		)
		return unavailablePlayerSupportSection("upstream_unavailable", query.routeName+" service is unavailable")
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, s.maxBodyBytes+1))
	if err != nil || int64(len(body)) > s.maxBodyBytes {
		return unavailablePlayerSupportSection("upstream_response_unavailable", "upstream response could not be read")
	}
	if query.allowNotFound && response.StatusCode == http.StatusNotFound {
		return playerSupportSection{
			Status: playerSupportSectionNotFound,
			Data:   json.RawMessage("null"),
		}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return unavailablePlayerSupportSection(
			fmt.Sprintf("upstream_http_%d", response.StatusCode),
			query.routeName+" service returned an error",
		)
	}
	safeBody, err := projectPlayerSupportData(query.name, body)
	if err != nil {
		return unavailablePlayerSupportSection("invalid_upstream_response", "upstream response was not valid JSON")
	}

	return playerSupportSection{
		Status: playerSupportSectionOK,
		Data:   safeBody,
	}
}

func projectPlayerSupportData(section string, body []byte) (json.RawMessage, error) {
	var destination any
	switch section {
	case "account":
		destination = &playerSupportAccount{}
	case "ledger":
		destination = &playerSupportPage[playerSupportLedgerEntry]{}
	case "pull_operations":
		destination = &playerSupportPage[playerSupportOperation]{}
	case "inventory":
		destination = &playerSupportPage[playerSupportInventoryItem]{}
	case "pull_events":
		destination = &playerSupportPage[playerSupportPullEvent]{}
	case "pull_records":
		destination = &playerSupportPage[playerSupportPullRecord]{}
	default:
		return nil, fmt.Errorf("unknown player support section %q", section)
	}

	if err := json.Unmarshal(body, destination); err != nil {
		return nil, err
	}
	projected, err := json.Marshal(destination)
	if err != nil {
		return nil, err
	}
	return projected, nil
}

func (s *Server) loadPlayerSupportAuditCalls(r *http.Request, playerID uuid.UUID) playerSupportSection {
	if s.auditLogStore == nil {
		return unavailablePlayerSupportSection("audit_log_unavailable", "API request records are unavailable")
	}

	items, err := s.auditLogStore.ListHTTPAPICalls(r.Context(), AuditLogFilter{
		Limit:  playerSupportAuditLogLimit,
		UserID: &playerID,
	})
	if err != nil {
		slog.Warn(
			"player support audit query failed",
			"player_id", playerID.String(),
			"request_id", requestIDFromContext(r.Context()),
			"error", err,
		)
		return unavailablePlayerSupportSection("audit_log_unavailable", "API request records are unavailable")
	}

	safeItems := make([]playerSupportAPICall, 0, len(items))
	for _, item := range items {
		var safeItem playerSupportAPICall
		if err := json.Unmarshal(item, &safeItem); err != nil {
			return unavailablePlayerSupportSection("audit_log_unavailable", "API request records could not be encoded")
		}
		safeItems = append(safeItems, safeItem)
	}

	body, err := json.Marshal(playerSupportPage[playerSupportAPICall]{Items: safeItems})
	if err != nil {
		return unavailablePlayerSupportSection("audit_log_unavailable", "API request records could not be encoded")
	}
	return playerSupportSection{Status: playerSupportSectionOK, Data: body}
}

func (s *Server) routeByName(name string) (Route, bool) {
	for _, route := range s.routes {
		if route.Name == name {
			return route, true
		}
	}
	return Route{}, false
}

func unavailablePlayerSupportSection(code string, message string) playerSupportSection {
	return playerSupportSection{
		Status: playerSupportSectionUnavailable,
		Data:   json.RawMessage("null"),
		Error:  &apiError{Code: code, Message: message},
	}
}
