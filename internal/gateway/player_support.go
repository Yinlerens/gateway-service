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
	playerSupportAdminRouteName       = "player-support-admin"
	playerSupportSectionOK            = "ok"
	playerSupportSectionNotFound      = "not_found"
	playerSupportSectionNotApplicable = "not_applicable"
	playerSupportSectionUnavailable   = "unavailable"
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

type playerSupportReplayRequest struct {
	Source          string  `json:"source,omitempty"`
	BannerID        *string `json:"banner_id"`
	BannerVersionID *string `json:"banner_version_id"`
	PityGroupID     *string `json:"pity_group_id"`
	Count           *int    `json:"count"`
	Seed            *string `json:"seed"`
	EventID         *string `json:"event_id"`
	AmountMinor     *int64  `json:"amount_minor"`
	AcceptedAt      *string `json:"accepted_at"`
}

type playerSupportPullReplayOperation struct {
	OperationID string                     `json:"operation_id"`
	RequestID   *string                    `json:"request_id"`
	Status      string                     `json:"status"`
	Request     playerSupportReplayRequest `json:"request"`
	Response    json.RawMessage            `json:"response"`
	Event       json.RawMessage            `json:"event"`
	Error       *apiError                  `json:"error"`
	CreatedAt   string                     `json:"created_at"`
	UpdatedAt   string                     `json:"updated_at"`
}

type playerSupportReplayPullEvent struct {
	EventID      string          `json:"event_id,omitempty"`
	EventType    string          `json:"event_type,omitempty"`
	BannerID     string          `json:"banner_id,omitempty"`
	Seed         string          `json:"seed,omitempty"`
	StateVersion int64           `json:"state_version"`
	PreviousPity json.RawMessage `json:"previous_pity"`
	NextPity     json.RawMessage `json:"next_pity"`
	ReceivedAt   string          `json:"received_at,omitempty"`
}

type playerSupportReplayBackpackDetail struct {
	Event   playerSupportReplayPullEvent `json:"event"`
	Records []playerSupportPullRecord    `json:"records"`
}

type playerSupportPullReplayResponse struct {
	PlayerID         string                           `json:"player_id"`
	GeneratedAt      time.Time                        `json:"generated_at"`
	Partial          bool                             `json:"partial"`
	Operation        playerSupportPullReplayOperation `json:"operation"`
	AssetSpend       playerSupportSection             `json:"asset_spend"`
	BackpackDelivery playerSupportSection             `json:"backpack_delivery"`
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

	results := make(chan playerSupportSectionResult, len(queries))
	var workers sync.WaitGroup
	workers.Add(len(queries))
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

func (s *Server) routeByName(name string) (Route, bool) {
	for _, route := range s.routes {
		if route.Name == name {
			return route, true
		}
	}
	return Route{}, false
}

func (s *Server) handlePlayerSupportPullReplay(w http.ResponseWriter, r *http.Request) {
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
	operationID, err := uuid.Parse(strings.TrimSpace(r.PathValue("operation_id")))
	if err != nil {
		s.writeAuditedError(w, request, entry, http.StatusBadRequest, "invalid_operation_id", "operation_id must be a UUID")
		return
	}

	body, statusCode, err := s.readPlayerSupportUpstream(
		request,
		playerID,
		"gacha",
		"/me/pulls/operations/"+url.PathEscape(operationID.String())+"/replay",
		nil,
	)
	if err != nil {
		s.writeAuditedError(w, request, entry, http.StatusBadGateway, "pull_replay_unavailable", "pull replay is unavailable")
		return
	}
	if statusCode == http.StatusNotFound {
		s.writeAuditedError(w, request, entry, http.StatusNotFound, "pull_operation_not_found", "pull operation was not found")
		return
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		s.writeAuditedError(w, request, entry, http.StatusBadGateway, "pull_replay_unavailable", "pull replay is unavailable")
		return
	}

	var operation playerSupportPullReplayOperation
	if err := json.Unmarshal(body, &operation); err != nil || operation.OperationID != operationID.String() {
		s.writeAuditedError(w, request, entry, http.StatusBadGateway, "invalid_pull_replay", "pull replay response was invalid")
		return
	}

	assetSpend := notApplicablePlayerSupportSection("pull event has not been created")
	backpackDelivery := notApplicablePlayerSupportSection("pull event has not been created")
	if operation.Request.EventID != nil && strings.TrimSpace(*operation.Request.EventID) != "" {
		eventID := strings.TrimSpace(*operation.Request.EventID)
		results := make(chan playerSupportSectionResult, 2)
		var workers sync.WaitGroup
		workers.Add(2)
		go func() {
			defer workers.Done()
			results <- playerSupportSectionResult{
				name: "asset_spend",
				section: s.loadPlayerSupportReplayEvidence(
					request,
					playerID,
					"assets",
					"/me/ledger-entry",
					url.Values{"idempotency_key": {"spend:gacha-pull:" + eventID}},
					"asset_spend",
				),
			}
		}()
		go func() {
			defer workers.Done()
			results <- playerSupportSectionResult{
				name: "backpack_delivery",
				section: s.loadPlayerSupportReplayEvidence(
					request,
					playerID,
					"backpack",
					"/me/pull-events/"+url.PathEscape(eventID),
					nil,
					"backpack_delivery",
				),
			}
		}()
		workers.Wait()
		close(results)
		for result := range results {
			switch result.name {
			case "asset_spend":
				assetSpend = result.section
			case "backpack_delivery":
				backpackDelivery = result.section
			}
		}
	}

	response := playerSupportPullReplayResponse{
		PlayerID:         playerID.String(),
		GeneratedAt:      s.now().UTC(),
		Operation:        operation,
		AssetSpend:       assetSpend,
		BackpackDelivery: backpackDelivery,
	}
	response.Partial = assetSpend.Status == playerSupportSectionUnavailable || backpackDelivery.Status == playerSupportSectionUnavailable
	s.writeAuditedJSON(w, request, entry, http.StatusOK, response)
}

func (s *Server) loadPlayerSupportReplayEvidence(
	r *http.Request,
	playerID uuid.UUID,
	routeName string,
	path string,
	query url.Values,
	sectionName string,
) playerSupportSection {
	body, statusCode, err := s.readPlayerSupportUpstream(r, playerID, routeName, path, query)
	if err != nil {
		return unavailablePlayerSupportSection("upstream_unavailable", routeName+" service is unavailable")
	}
	if statusCode == http.StatusNotFound {
		return playerSupportSection{Status: playerSupportSectionNotFound, Data: json.RawMessage("null")}
	}
	if statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices {
		return unavailablePlayerSupportSection(fmt.Sprintf("upstream_http_%d", statusCode), routeName+" service returned an error")
	}

	var destination any
	switch sectionName {
	case "asset_spend":
		destination = &playerSupportLedgerEntry{}
	case "backpack_delivery":
		destination = &playerSupportReplayBackpackDetail{}
	default:
		return unavailablePlayerSupportSection("invalid_replay_section", "replay evidence could not be decoded")
	}
	if err := json.Unmarshal(body, destination); err != nil {
		return unavailablePlayerSupportSection("invalid_upstream_response", "upstream response was not valid JSON")
	}
	projected, err := json.Marshal(destination)
	if err != nil {
		return unavailablePlayerSupportSection("invalid_upstream_response", "upstream response could not be encoded")
	}
	return playerSupportSection{Status: playerSupportSectionOK, Data: projected}
}

func (s *Server) readPlayerSupportUpstream(
	r *http.Request,
	playerID uuid.UUID,
	routeName string,
	path string,
	query url.Values,
) ([]byte, int, error) {
	route, ok := s.routeByName(routeName)
	if !ok {
		return nil, 0, fmt.Errorf("%s route is unavailable", routeName)
	}
	target := *route.Target
	target.Path = joinURLPath(route.Target.Path, path)
	if query != nil {
		target.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set(internalTokenHeader, s.internalToken)
	request.Header.Set(userIDHeader, playerID.String())
	request.Header.Set(requestIDHeader, requestIDFromContext(r.Context()))

	response, err := s.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, s.maxBodyBytes+1))
	if err != nil || int64(len(body)) > s.maxBodyBytes {
		return nil, response.StatusCode, fmt.Errorf("upstream response could not be read")
	}
	return body, response.StatusCode, nil
}

func notApplicablePlayerSupportSection(message string) playerSupportSection {
	return playerSupportSection{
		Status: playerSupportSectionNotApplicable,
		Data:   json.RawMessage("null"),
		Error:  &apiError{Code: "not_applicable", Message: message},
	}
}

func unavailablePlayerSupportSection(code string, message string) playerSupportSection {
	return playerSupportSection{
		Status: playerSupportSectionUnavailable,
		Data:   json.RawMessage("null"),
		Error:  &apiError{Code: code, Message: message},
	}
}
