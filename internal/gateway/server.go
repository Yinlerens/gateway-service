package gateway

import (
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
	Verifier       AuthVerifier
	InternalToken  string
	AuthCookieName string
	Routes         []Route
	Client         *http.Client
	MaxBodyBytes   int64
}

type Server struct {
	verifier       AuthVerifier
	internalToken  string
	authCookieName string
	routes         []Route
	client         *http.Client
	maxBodyBytes   int64
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

	return &Server{
		verifier:       opts.Verifier,
		internalToken:  strings.TrimSpace(opts.InternalToken),
		authCookieName: strings.TrimSpace(opts.AuthCookieName),
		routes:         routes,
		client:         client,
		maxBodyBytes:   maxBodyBytes,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.HandleFunc("/", s.handleProxy)
	return s.accessLog(securityHeaders(mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.verifier == nil || s.internalToken == "" || len(s.routes) == 0 {
		writeError(w, http.StatusServiceUnavailable, "gateway_not_ready", "gateway is not ready")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	route, ok := s.matchRoute(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "route not found")
		return
	}

	accessToken, ok := extractAccessToken(r, s.authCookieName)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "login is required")
		return
	}
	if s.verifier == nil {
		writeError(w, http.StatusServiceUnavailable, "auth_unavailable", "auth verifier is unavailable")
		return
	}

	user, err := s.verifier.Verify(r.Context(), accessToken)
	if err != nil {
		if errors.Is(err, ErrInvalidSession) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "login is required")
			return
		}

		writeError(w, http.StatusServiceUnavailable, "auth_unavailable", "auth verifier is unavailable")
		return
	}

	if r.ContentLength > s.maxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBodyBytes)

	if err := s.proxyAuthenticatedRequest(w, r, route, user); err != nil {
		writeError(w, http.StatusBadGateway, "upstream_unavailable", "upstream service is unavailable")
	}
}

func (s *Server) matchRoute(path string) (Route, bool) {
	for _, route := range s.routes {
		if path == route.Prefix || strings.HasPrefix(path, route.Prefix+"/") {
			return route, true
		}
	}

	return Route{}, false
}

func (s *Server) proxyAuthenticatedRequest(w http.ResponseWriter, r *http.Request, route Route, user User) error {
	targetURL := buildTargetURL(route, r.URL)

	request, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		return err
	}
	request.ContentLength = r.ContentLength
	copyForwardHeaders(request.Header, r.Header)
	request.Header.Set(internalTokenHeader, s.internalToken)
	request.Header.Set(userIDHeader, user.ID.String())
	setForwardedHeaders(request, r)

	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	copyResponseHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, err = io.Copy(w, response.Body)
	return err
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

		slog.Info(
			"http request",
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
