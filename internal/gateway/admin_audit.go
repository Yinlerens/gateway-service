package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const auditAdminRouteName = "audit-admin"

type auditLogListResponse struct {
	Data []json.RawMessage `json:"data"`
	Meta auditLogListMeta  `json:"meta"`
}

type auditLogListMeta struct {
	Count int `json:"count"`
	Limit int `json:"limit"`
}

type auditLogDetailResponse struct {
	Data json.RawMessage `json:"data"`
}

func (s *Server) handleAuditLogList(w http.ResponseWriter, r *http.Request) {
	entry, request := s.beginDirectAudit(w, r, auditAdminRouteName)
	if !s.startAuditOrFail(w, request, entry) {
		return
	}

	user, ok := s.authorizeAuditLogAdmin(w, request, entry)
	if !ok {
		return
	}
	entry.UserID = &user.ID

	filter, err := parseAuditLogFilter(r)
	if err != nil {
		s.writeAuditedError(w, request, entry, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}

	if s.auditLogStore == nil {
		s.writeAuditedError(w, request, entry, http.StatusServiceUnavailable, "audit_log_unavailable", "audit log store is unavailable")
		return
	}

	items, err := s.auditLogStore.ListHTTPAPICalls(request.Context(), filter)
	if err != nil {
		slog.ErrorContext(request.Context(), "query audit log entries failed", "request_id", entry.RequestID.String(), "error", err)
		s.writeAuditedError(w, request, entry, http.StatusServiceUnavailable, "audit_log_unavailable", "audit logs are unavailable")
		return
	}

	s.writeAuditedJSON(w, request, entry, http.StatusOK, auditLogListResponse{
		Data: items,
		Meta: auditLogListMeta{Count: len(items), Limit: normalizeAuditLogFilter(filter).Limit},
	})
}

func (s *Server) handleAuditLogDetail(w http.ResponseWriter, r *http.Request) {
	entry, request := s.beginDirectAudit(w, r, auditAdminRouteName)
	if !s.startAuditOrFail(w, request, entry) {
		return
	}

	user, ok := s.authorizeAuditLogAdmin(w, request, entry)
	if !ok {
		return
	}
	entry.UserID = &user.ID

	requestID, err := uuid.Parse(strings.TrimSpace(r.PathValue("request_id")))
	if err != nil {
		s.writeAuditedError(w, request, entry, http.StatusBadRequest, "invalid_request_id", "request_id must be a UUID")
		return
	}

	if s.auditLogStore == nil {
		s.writeAuditedError(w, request, entry, http.StatusServiceUnavailable, "audit_log_unavailable", "audit log store is unavailable")
		return
	}

	item, found, err := s.auditLogStore.GetHTTPAPICall(request.Context(), requestID)
	if err != nil {
		slog.ErrorContext(request.Context(), "query audit log entry failed", "request_id", entry.RequestID.String(), "target_request_id", requestID.String(), "error", err)
		s.writeAuditedError(w, request, entry, http.StatusServiceUnavailable, "audit_log_unavailable", "audit logs are unavailable")
		return
	}
	if !found {
		s.writeAuditedError(w, request, entry, http.StatusNotFound, "not_found", "audit log entry was not found")
		return
	}

	s.writeAuditedJSON(w, request, entry, http.StatusOK, auditLogDetailResponse{Data: item})
}

func (s *Server) beginDirectAudit(w http.ResponseWriter, r *http.Request, route string) (*AuditEntry, *http.Request) {
	started := time.Now().UTC()
	requestID, clientRequestID := requestIDsFromHeader(r.Header)
	w.Header().Set(requestIDHeader, requestID.String())
	request := r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, requestID.String()))

	return &AuditEntry{
		RequestID:       requestID,
		ClientRequestID: clientRequestID,
		StartedAt:       started,
		Method:          r.Method,
		Path:            r.URL.Path,
		RawQuery:        r.URL.RawQuery,
		Route:           route,
		RemoteIP:        remoteIP(r.RemoteAddr),
		AuthResult:      "not_checked",
		RequestHeaders:  sanitizedRequestHeaders(r.Header),
		RequestBody:     AuditBody{Encoding: bodyEncodingUTF8},
		AuditStatus:     auditStatusStarted,
	}, request
}

func (s *Server) authorizeAuditLogAdmin(w http.ResponseWriter, r *http.Request, entry *AuditEntry) (User, bool) {
	accessToken, ok := extractAccessToken(r, s.authCookieName)
	if !ok {
		entry.AuthResult = "missing_session"
		s.writeAuditedError(w, r, entry, http.StatusUnauthorized, "unauthorized", "login is required")
		return User{}, false
	}
	if s.verifier == nil {
		entry.AuthResult = "auth_verifier_missing"
		s.writeAuditedError(w, r, entry, http.StatusServiceUnavailable, "auth_unavailable", "auth verifier is unavailable")
		return User{}, false
	}

	user, err := s.verifier.Verify(r.Context(), accessToken)
	if err != nil {
		if errors.Is(err, ErrInvalidSession) {
			entry.AuthResult = "invalid_session"
			s.writeAuditedError(w, r, entry, http.StatusUnauthorized, "unauthorized", "login is required")
			return User{}, false
		}

		entry.AuthResult = "auth_verification_failed"
		s.writeAuditedError(w, r, entry, http.StatusServiceUnavailable, "auth_unavailable", "auth verifier is unavailable")
		return User{}, false
	}

	entry.AuthResult = "authenticated"
	entry.UserID = &user.ID
	if !s.isAuditLogAdmin(user.ID) {
		entry.AuthResult = "forbidden"
		s.writeAuditedError(w, r, entry, http.StatusForbidden, "forbidden", "admin access is required")
		return User{}, false
	}

	return user, true
}

func (s *Server) isAuditLogAdmin(userID uuid.UUID) bool {
	if len(s.adminUserIDs) == 0 {
		return false
	}
	_, ok := s.adminUserIDs[userID]
	return ok
}

func (s *Server) writeAuditedJSON(w http.ResponseWriter, r *http.Request, entry *AuditEntry, statusCode int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		s.writeAuditedError(w, r, entry, http.StatusInternalServerError, "internal_error", "response could not be encoded")
		return
	}

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")

	entry.ResponseStatus = statusCode
	entry.ResponseHeaders = sanitizedResponseHeaders(headers)
	entry.ResponseBody = auditBodyFromBytes(body, "application/json", s.auditMaxBodyBytes)
	entry.AuditStatus = auditStatusComplete
	s.finishAudit(r.Context(), entry)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}

func parseAuditLogFilter(r *http.Request) (AuditLogFilter, error) {
	values := r.URL.Query()
	filter := AuditLogFilter{Limit: defaultAuditLogLimit}

	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			return AuditLogFilter{}, errors.New("limit must be a positive integer")
		}
		filter.Limit = limit
	}

	if raw := strings.TrimSpace(values.Get("request_id")); raw != "" {
		requestID, err := uuid.Parse(raw)
		if err != nil {
			return AuditLogFilter{}, errors.New("request_id must be a UUID")
		}
		filter.RequestID = &requestID
	}

	if raw := strings.TrimSpace(values.Get("user_id")); raw != "" {
		userID, err := uuid.Parse(raw)
		if err != nil {
			return AuditLogFilter{}, errors.New("user_id must be a UUID")
		}
		filter.UserID = &userID
	}

	if raw := strings.TrimSpace(values.Get("status")); raw != "" {
		statusCode, err := strconv.Atoi(raw)
		if err != nil || statusCode < 100 || statusCode > 599 {
			return AuditLogFilter{}, errors.New("status must be an HTTP status code")
		}
		filter.ResponseStatus = &statusCode
	}

	filter.Method = values.Get("method")
	filter.PathContains = values.Get("path")
	filter.Route = values.Get("route")
	filter.AuthResult = values.Get("auth_result")

	if raw := strings.TrimSpace(values.Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return AuditLogFilter{}, errors.New("since must be an RFC3339 timestamp")
		}
		filter.Since = &since
	}

	if raw := strings.TrimSpace(values.Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return AuditLogFilter{}, errors.New("until must be an RFC3339 timestamp")
		}
		filter.Until = &until
	}

	return normalizeAuditLogFilter(filter), nil
}
