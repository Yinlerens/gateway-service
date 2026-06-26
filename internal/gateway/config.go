package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultPort                  = "8080"
	defaultRequestTimeoutSeconds = 15
)

type Config struct {
	Addr                 string
	SupabaseURL          string
	SupabaseAnonKey      string
	InternalToken        string
	AuthCookieName       string
	Routes               []Route
	RequestTimeout       time.Duration
	MaxBodyBytes         int64
	AuditDatabaseURL     string
	AuditMaxBodyBytes    int64
	AuditWriteTimeout    time.Duration
	AuditLogAdminUserIDs map[uuid.UUID]struct{}
}

func LoadConfig() (Config, error) {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = defaultPort
	}

	supabaseURL := strings.TrimSpace(os.Getenv("SUPABASE_URL"))
	if supabaseURL == "" {
		return Config{}, errors.New("SUPABASE_URL is required")
	}

	supabaseAnonKey := strings.TrimSpace(os.Getenv("SUPABASE_ANON_KEY"))
	if supabaseAnonKey == "" {
		return Config{}, errors.New("SUPABASE_ANON_KEY is required")
	}

	internalToken := strings.TrimSpace(os.Getenv("INTERNAL_TOKEN"))
	if internalToken == "" {
		return Config{}, errors.New("INTERNAL_TOKEN is required")
	}

	routes, err := loadRoutes()
	if err != nil {
		return Config{}, err
	}

	requestTimeout, err := durationFromSecondsEnv("REQUEST_TIMEOUT_SECONDS", defaultRequestTimeoutSeconds)
	if err != nil {
		return Config{}, err
	}

	maxBodyBytes := int64(defaultMaxBodyBytes)
	if value := strings.TrimSpace(os.Getenv("MAX_BODY_BYTES")); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 1 {
			return Config{}, errors.New("MAX_BODY_BYTES must be a positive integer")
		}
		maxBodyBytes = parsed
	}

	auditMaxBodyBytes := int64(defaultAuditMaxBodyBytes)
	if value := strings.TrimSpace(os.Getenv("AUDIT_MAX_BODY_BYTES")); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 1 {
			return Config{}, errors.New("AUDIT_MAX_BODY_BYTES must be a positive integer")
		}
		auditMaxBodyBytes = parsed
	}

	auditWriteTimeout, err := durationFromSecondsEnv("AUDIT_WRITE_TIMEOUT_SECONDS", int(defaultAuditWriteTimeout/time.Second))
	if err != nil {
		return Config{}, err
	}

	authCookieName := strings.TrimSpace(os.Getenv("SUPABASE_AUTH_COOKIE_NAME"))
	if authCookieName == "" {
		authCookieName = inferSupabaseCookieName(supabaseURL)
	}

	auditLogAdminUserIDs, err := uuidSetFromEnv("AUDIT_LOG_ADMIN_USER_IDS")
	if err != nil {
		return Config{}, err
	}

	return Config{
		Addr:                 ":" + port,
		SupabaseURL:          supabaseURL,
		SupabaseAnonKey:      supabaseAnonKey,
		InternalToken:        internalToken,
		AuthCookieName:       authCookieName,
		Routes:               routes,
		RequestTimeout:       requestTimeout,
		MaxBodyBytes:         maxBodyBytes,
		AuditDatabaseURL:     strings.TrimSpace(os.Getenv("AUDIT_DATABASE_URL")),
		AuditMaxBodyBytes:    auditMaxBodyBytes,
		AuditWriteTimeout:    auditWriteTimeout,
		AuditLogAdminUserIDs: auditLogAdminUserIDs,
	}, nil
}

func loadRoutes() ([]Route, error) {
	value := strings.TrimSpace(os.Getenv("UPSTREAM_ROUTES"))
	if value != "" {
		return parseRoutes(value)
	}

	assetURL := strings.TrimRight(strings.TrimSpace(os.Getenv("ASSET_SERVICE_URL")), "/")
	if assetURL == "" {
		return nil, errors.New("UPSTREAM_ROUTES or ASSET_SERVICE_URL is required")
	}

	return parseRoutes("assets=/api/v1/assets|" + assetURL + "/v1")
}

func parseRoutes(value string) ([]Route, error) {
	parts := strings.Split(value, ",")
	routes := make([]Route, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		nameAndRest := strings.SplitN(part, "=", 2)
		if len(nameAndRest) != 2 {
			return nil, fmt.Errorf("invalid UPSTREAM_ROUTES entry %q", part)
		}
		prefixAndTarget := strings.SplitN(nameAndRest[1], "|", 2)
		if len(prefixAndTarget) != 2 {
			return nil, fmt.Errorf("invalid UPSTREAM_ROUTES entry %q", part)
		}

		target, err := url.Parse(strings.TrimSpace(prefixAndTarget[1]))
		if err != nil {
			return nil, fmt.Errorf("parse route %s target: %w", strings.TrimSpace(nameAndRest[0]), err)
		}

		route := Route{
			Name:   strings.TrimSpace(nameAndRest[0]),
			Prefix: strings.TrimRight(strings.TrimSpace(prefixAndTarget[0]), "/"),
			Target: target,
		}
		if route.Prefix == "" {
			route.Prefix = "/"
		}
		if err := validateRoute(route); err != nil {
			return nil, err
		}

		routes = append(routes, route)
	}

	if len(routes) == 0 {
		return nil, errors.New("at least one upstream route is required")
	}

	return routes, nil
}

func durationFromSecondsEnv(name string, defaultSeconds int) (time.Duration, error) {
	seconds := defaultSeconds
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			return 0, fmt.Errorf("%s must be a positive integer", name)
		}
		seconds = parsed
	}

	return time.Duration(seconds) * time.Second, nil
}

func uuidSetFromEnv(name string) (map[uuid.UUID]struct{}, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, nil
	}

	parts := strings.Split(value, ",")
	result := make(map[uuid.UUID]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		id, err := uuid.Parse(part)
		if err != nil {
			return nil, fmt.Errorf("%s must contain comma-separated UUIDs", name)
		}
		result[id] = struct{}{}
	}

	return result, nil
}

func inferSupabaseCookieName(supabaseURL string) string {
	parsed, err := url.Parse(supabaseURL)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}

	projectRef := strings.Split(parsed.Hostname(), ".")[0]
	if projectRef == "" {
		return ""
	}

	return "sb-" + projectRef + "-auth-token"
}
