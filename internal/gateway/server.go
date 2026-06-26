package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	internalTokenHeader = "X-Internal-Token"
	userIDHeader        = "X-User-Id"
	defaultMaxBodyBytes = 4 << 20
)

type Route struct {
	Name   string
	Prefix string
	Target *url.URL
}

type Options struct {
	Verifier          AuthVerifier
	InternalToken     string
	AuthCookieName    string
	Routes            []Route
	Client            *http.Client
	MaxBodyBytes      int64
	AuditSink         AuditSink
	AuditLogStore     AuditLogStore
	AuditMaxBodyBytes int64
	AdminUserIDs      map[uuid.UUID]struct{}
}

type Server struct {
	verifier          AuthVerifier
	internalToken     string
	authCookieName    string
	routes            []Route
	client            *http.Client
	maxBodyBytes      int64
	auditSink         AuditSink
	auditLogStore     AuditLogStore
	auditMaxBodyBytes int64
	adminUserIDs      map[uuid.UUID]struct{}
}

func New(opts Options) *Server {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}

	maxBodyBytes := opts.MaxBodyBytes
	if maxBodyBytes < 1 {
		maxBodyBytes = defaultMaxBodyBytes
	}

	routes := append([]Route(nil), opts.Routes...)
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Prefix) > len(routes[j].Prefix)
	})

	auditLogStore := opts.AuditLogStore
	if auditLogStore == nil {
		if store, ok := opts.AuditSink.(AuditLogStore); ok {
			auditLogStore = store
		}
	}

	adminUserIDs := make(map[uuid.UUID]struct{}, len(opts.AdminUserIDs))
	for id := range opts.AdminUserIDs {
		adminUserIDs[id] = struct{}{}
	}

	return &Server{
		verifier:          opts.Verifier,
		internalToken:     strings.TrimSpace(opts.InternalToken),
		authCookieName:    strings.TrimSpace(opts.AuthCookieName),
		routes:            routes,
		client:            client,
		maxBodyBytes:      maxBodyBytes,
		auditSink:         opts.AuditSink,
		auditLogStore:     auditLogStore,
		auditMaxBodyBytes: normalizeAuditMaxBodyBytes(opts.AuditMaxBodyBytes),
		adminUserIDs:      adminUserIDs,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.HandleFunc("GET /api/v1/admin/audit/http-api-calls", s.handleAuditLogList)
	mux.HandleFunc("GET /api/v1/admin/audit/http-api-calls/{request_id}", s.handleAuditLogDetail)
	mux.HandleFunc("/", s.handleProxy)
	return s.accessLog(securityHeaders(mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.verifier == nil || s.internalToken == "" || len(s.routes) == 0 {
		slog.Error(
			"gateway not ready",
			"verifier_configured", s.verifier != nil,
			"internal_token_configured", s.internalToken != "",
			"route_count", len(s.routes),
		)
		writeError(w, http.StatusServiceUnavailable, "gateway_not_ready", "gateway is not ready")
		return
	}

	if s.auditSink != nil {
		if err := s.auditSink.Ping(r.Context()); err != nil {
			slog.Error("gateway audit sink not ready", "error", err)
			writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "audit sink is unavailable")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	started := time.Now().UTC()
	requestID, clientRequestID := requestIDsFromHeader(r.Header)
	w.Header().Set(requestIDHeader, requestID.String())
	r = r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, requestID.String()))

	auditEntry := AuditEntry{
		RequestID:       requestID,
		ClientRequestID: clientRequestID,
		StartedAt:       started,
		Method:          r.Method,
		Path:            r.URL.Path,
		RawQuery:        r.URL.RawQuery,
		RemoteIP:        remoteIP(r.RemoteAddr),
		AuthResult:      "not_checked",
		RequestHeaders:  sanitizedRequestHeaders(r.Header),
		AuditStatus:     auditStatusStarted,
	}

	requestBody, auditBody, tooLarge, err := s.readProxyRequestBody(r)
	auditEntry.RequestBody = auditBody
	if err != nil {
		slog.Warn("gateway request rejected", "reason", "request_body_unavailable", "method", r.Method, "path", r.URL.Path, "request_id", requestID.String(), "error", err)
		if !s.startAuditOrFail(w, r, &auditEntry) {
			return
		}
		s.writeAuditedError(w, r, &auditEntry, http.StatusBadRequest, "invalid_request_body", "request body could not be read")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(requestBody))
	r.ContentLength = int64(len(requestBody))

	if tooLarge {
		slog.Warn(
			"gateway request rejected",
			"reason", "request_too_large",
			"method", r.Method,
			"path", r.URL.Path,
			"content_length", r.ContentLength,
			"max_body_bytes", s.maxBodyBytes,
			"request_id", requestID.String(),
		)
		if !s.startAuditOrFail(w, r, &auditEntry) {
			return
		}
		s.writeAuditedError(w, r, &auditEntry, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
		return
	}

	if !s.startAuditOrFail(w, r, &auditEntry) {
		return
	}

	route, ok := s.matchRoute(r.URL.Path)
	if !ok {
		slog.Warn(
			"gateway request rejected",
			"reason", "route_not_found",
			"method", r.Method,
			"path", r.URL.Path,
			"request_id", requestID.String(),
		)
		auditEntry.AuthResult = "route_not_found"
		s.writeAuditedError(w, r, &auditEntry, http.StatusNotFound, "not_found", "route not found")
		return
	}
	auditEntry.Route = route.Name

	accessToken, ok := extractAccessToken(r, s.authCookieName)
	if !ok {
		slog.Warn(
			"gateway request rejected",
			"reason", "missing_session",
			"method", r.Method,
			"path", r.URL.Path,
			"route", route.Name,
			"request_id", requestID.String(),
		)
		auditEntry.AuthResult = "missing_session"
		s.writeAuditedError(w, r, &auditEntry, http.StatusUnauthorized, "unauthorized", "login is required")
		return
	}
	if s.verifier == nil {
		slog.Error(
			"gateway request rejected",
			"reason", "auth_verifier_missing",
			"method", r.Method,
			"path", r.URL.Path,
			"route", route.Name,
			"request_id", requestID.String(),
		)
		auditEntry.AuthResult = "auth_verifier_missing"
		s.writeAuditedError(w, r, &auditEntry, http.StatusServiceUnavailable, "auth_unavailable", "auth verifier is unavailable")
		return
	}

	user, err := s.verifier.Verify(r.Context(), accessToken)
	if err != nil {
		if errors.Is(err, ErrInvalidSession) {
			slog.Warn(
				"gateway request rejected",
				"reason", "invalid_session",
				"method", r.Method,
				"path", r.URL.Path,
				"route", route.Name,
				"request_id", requestID.String(),
			)
			auditEntry.AuthResult = "invalid_session"
			s.writeAuditedError(w, r, &auditEntry, http.StatusUnauthorized, "unauthorized", "login is required")
			return
		}

		slog.Error(
			"gateway auth verification failed",
			"method", r.Method,
			"path", r.URL.Path,
			"route", route.Name,
			"error", err,
			"request_id", requestID.String(),
		)
		auditEntry.AuthResult = "auth_verification_failed"
		s.writeAuditedError(w, r, &auditEntry, http.StatusServiceUnavailable, "auth_unavailable", "auth verifier is unavailable")
		return
	}
	auditEntry.AuthResult = "authenticated"
	auditEntry.UserID = &user.ID

	result, err := s.proxyAuthenticatedRequest(r, route, user)
	if err != nil {
		slog.Error(
			"gateway upstream request failed",
			"method", r.Method,
			"path", r.URL.Path,
			"route", route.Name,
			"target_host", route.Target.Host,
			"error", err,
			"request_id", requestID.String(),
		)
		s.writeAuditedError(w, r, &auditEntry, http.StatusBadGateway, "upstream_unavailable", "upstream service is unavailable")
		return
	}

	auditEntry.UpstreamURL = result.TargetURL
	auditEntry.ResponseStatus = result.StatusCode
	auditEntry.ResponseHeaders = sanitizedResponseHeaders(result.Header)
	auditEntry.ResponseBody = result.AuditBody
	auditEntry.AuditStatus = auditStatusComplete
	s.finishAudit(r.Context(), &auditEntry)

	copyResponseHeaders(w.Header(), result.Header)
	w.WriteHeader(result.StatusCode)
	_, _ = w.Write(result.Body)
}

func (s *Server) matchRoute(path string) (Route, bool) {
	for _, route := range s.routes {
		if path == route.Prefix || strings.HasPrefix(path, route.Prefix+"/") {
			return route, true
		}
	}

	return Route{}, false
}

func (s *Server) readProxyRequestBody(r *http.Request) ([]byte, AuditBody, bool, error) {
	if r.Body == nil {
		return nil, AuditBody{Encoding: bodyEncodingUTF8}, false, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBodyBytes+1))
	if err != nil {
		return nil, AuditBody{}, false, err
	}

	tooLarge := int64(len(body)) > s.maxBodyBytes
	originalSize := len(body)
	if tooLarge {
		body = body[:s.maxBodyBytes]
	}

	return body, auditBodyFromBytesWithOriginalSize(body, r.Header.Get("Content-Type"), s.auditMaxBodyBytes, originalSize), tooLarge, nil
}

func (s *Server) startAuditOrFail(w http.ResponseWriter, r *http.Request, entry *AuditEntry) bool {
	if s.auditSink == nil {
		return true
	}

	if err := s.auditSink.Start(r.Context(), *entry); err != nil {
		slog.Error(
			"gateway audit start failed",
			"method", r.Method,
			"path", r.URL.Path,
			"request_id", entry.RequestID.String(),
			"error", err,
		)
		writeError(w, http.StatusServiceUnavailable, "audit_unavailable", "audit sink is unavailable")
		return false
	}

	return true
}

func (s *Server) writeAuditedError(w http.ResponseWriter, r *http.Request, entry *AuditEntry, statusCode int, code string, message string) {
	payload, _ := json.Marshal(errorResponse{
		Error: apiError{
			Code:    code,
			Message: message,
		},
	})

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")

	entry.ResponseStatus = statusCode
	entry.ResponseHeaders = sanitizedResponseHeaders(headers)
	entry.ResponseBody = auditBodyFromBytes(payload, "application/json", s.auditMaxBodyBytes)
	entry.ErrorCode = code
	entry.ErrorMessage = message
	entry.AuditStatus = auditStatusComplete
	s.finishAudit(r.Context(), entry)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(payload)
}

func (s *Server) finishAudit(ctx context.Context, entry *AuditEntry) {
	if s.auditSink == nil {
		return
	}

	entry.FinishedAt = time.Now().UTC()
	entry.Duration = entry.FinishedAt.Sub(entry.StartedAt)
	if entry.AuditStatus == "" {
		entry.AuditStatus = auditStatusComplete
	}

	if err := s.auditSink.Finish(ctx, *entry); err != nil {
		slog.Error(
			"gateway audit finish failed",
			"request_id", entry.RequestID.String(),
			"method", entry.Method,
			"path", entry.Path,
			"status", entry.ResponseStatus,
			"error", err,
		)
	}
}

type proxyResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	AuditBody  AuditBody
	TargetURL  string
}

func (s *Server) proxyAuthenticatedRequest(r *http.Request, route Route, user User) (proxyResult, error) {
	targetURL := buildTargetURL(route, r.URL)

	request, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		return proxyResult{}, err
	}
	request.ContentLength = r.ContentLength
	copyForwardHeaders(request.Header, r.Header)
	request.Header.Set(internalTokenHeader, s.internalToken)
	request.Header.Set(userIDHeader, user.ID.String())
	request.Header.Set(requestIDHeader, requestIDFromContext(r.Context()))
	setForwardedHeaders(request, r)

	response, err := s.client.Do(request)
	if err != nil {
		return proxyResult{}, err
	}
	defer response.Body.Close()

	auditBody, responseBody, err := readResponseAuditBody(response.Body, response.Header.Get("Content-Type"), s.auditMaxBodyBytes)
	if err != nil {
		return proxyResult{}, err
	}

	if response.StatusCode >= http.StatusInternalServerError {
		slog.Error(
			"gateway upstream returned error",
			"method", r.Method,
			"path", r.URL.Path,
			"route", route.Name,
			"target_host", route.Target.Host,
			"target_path", targetURL.Path,
			"upstream_status", response.StatusCode,
			"request_id", requestIDFromContext(r.Context()),
		)
	} else if response.StatusCode >= http.StatusBadRequest {
		slog.Warn(
			"gateway upstream returned client error",
			"method", r.Method,
			"path", r.URL.Path,
			"route", route.Name,
			"target_host", route.Target.Host,
			"target_path", targetURL.Path,
			"upstream_status", response.StatusCode,
			"request_id", requestIDFromContext(r.Context()),
		)
	}

	return proxyResult{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       responseBody,
		AuditBody:  auditBody,
		TargetURL:  targetURL.String(),
	}, nil
}

func buildTargetURL(route Route, source *url.URL) url.URL {
	target := *route.Target
	suffix := strings.TrimPrefix(source.Path, route.Prefix)
	target.Path = joinURLPath(route.Target.Path, suffix)
	target.RawQuery = source.RawQuery
	return target
}

func joinURLPath(base string, suffix string) string {
	base = strings.TrimRight(base, "/")
	suffix = strings.TrimLeft(suffix, "/")
	if suffix == "" {
		if base == "" {
			return "/"
		}
		return base
	}
	if base == "" {
		return "/" + suffix
	}
	return base + "/" + suffix
}

func copyForwardHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		if shouldDropRequestHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func copyResponseHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		if shouldDropResponseHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func shouldDropRequestHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Authorization",
		"Connection",
		"Cookie",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		internalTokenHeader,
		userIDHeader:
		return true
	default:
		return false
	}
}

func shouldDropResponseHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Set-Cookie",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade":
		return true
	default:
		return false
	}
}

func setForwardedHeaders(dst *http.Request, src *http.Request) {
	if clientIP := remoteIP(src.RemoteAddr); clientIP != "" {
		dst.Header.Set("X-Forwarded-For", clientIP)
	}
	dst.Header.Set("X-Forwarded-Host", src.Host)
	if src.TLS != nil {
		dst.Header.Set("X-Forwarded-Proto", "https")
	} else {
		dst.Header.Set("X-Forwarded-Proto", "http")
	}
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

type requestIDContextKey struct{}

func requestIDFromContext(ctx context.Context) string {
	requestID, ok := ctx.Value(requestIDContextKey{}).(string)
	if !ok {
		return ""
	}
	return requestID
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		response := &accessLogResponseWriter{ResponseWriter: w}

		next.ServeHTTP(response, r)

		status := response.status
		if status == 0 {
			status = http.StatusOK
		}
		requestID := requestIDFromContext(r.Context())
		if requestID == "" {
			requestID = response.Header().Get(requestIDHeader)
		}

		slog.Info(
			"http request",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"route", s.routeName(r.URL.Path),
			"status", status,
			"duration_ms", time.Since(started).Milliseconds(),
			"bytes", response.bytes,
			"remote_ip", remoteIP(r.RemoteAddr),
		)
	})
}

func (s *Server) routeName(path string) string {
	switch path {
	case "/health":
		return "health"
	case "/ready":
		return "ready"
	}
	if path == "/api/v1/admin/audit/http-api-calls" || strings.HasPrefix(path, "/api/v1/admin/audit/http-api-calls/") {
		return auditAdminRouteName
	}

	route, ok := s.matchRoute(path)
	if !ok {
		return "unmatched"
	}
	return route.Name
}

type accessLogResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *accessLogResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *accessLogResponseWriter) Write(payload []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}

	written, err := w.ResponseWriter.Write(payload)
	w.bytes += int64(written)
	return written, err
}

func (w *accessLogResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, errorResponse{
		Error: apiError{
			Code:    code,
			Message: message,
		},
	})
}

func validateRoute(route Route) error {
	if strings.TrimSpace(route.Name) == "" {
		return fmt.Errorf("route name is required")
	}
	if route.Prefix == "" || !strings.HasPrefix(route.Prefix, "/") {
		return fmt.Errorf("route %s prefix must start with /", route.Name)
	}
	if strings.HasSuffix(route.Prefix, "/") && route.Prefix != "/" {
		return fmt.Errorf("route %s prefix must not end with /", route.Name)
	}
	if route.Target == nil || route.Target.Scheme == "" || route.Target.Host == "" {
		return fmt.Errorf("route %s target must be an absolute URL", route.Name)
	}

	return nil
}

func TimeoutClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}
