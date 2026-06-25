package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	requestIDHeader             = "X-Request-Id"
	defaultAuditWriteTimeout    = 3 * time.Second
	defaultAuditMaxBodyBytes    = defaultMaxBodyBytes
	auditStatusStarted          = "started"
	auditStatusComplete         = "complete"
	bodyEncodingUTF8            = "utf8"
	bodyEncodingBase64          = "base64"
	bodyContentTypeJSONFragment = "json"
)

type AuditSink interface {
	Ping(ctx context.Context) error
	Start(ctx context.Context, entry AuditEntry) error
	Finish(ctx context.Context, entry AuditEntry) error
	Close()
}

type AuditEntry struct {
	RequestID       uuid.UUID
	ClientRequestID string
	StartedAt       time.Time
	FinishedAt      time.Time
	Duration        time.Duration
	Method          string
	Path            string
	RawQuery        string
	Route           string
	UpstreamURL     string
	UserID          *uuid.UUID
	RemoteIP        string
	AuthResult      string
	RequestHeaders  json.RawMessage
	RequestBody     AuditBody
	ResponseStatus  int
	ResponseHeaders json.RawMessage
	ResponseBody    AuditBody
	ErrorCode       string
	ErrorMessage    string
	AuditStatus     string
}

type AuditBody struct {
	Text      string
	Base64    string
	JSON      json.RawMessage
	Encoding  string
	Size      int
	Truncated bool
}

type PostgresAuditSink struct {
	pool         *pgxpool.Pool
	writeTimeout time.Duration
}

func NewPostgresAuditSink(ctx context.Context, databaseURL string, writeTimeout time.Duration) (*PostgresAuditSink, error) {
	writeTimeout = normalizeAuditWriteTimeout(writeTimeout)

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse audit database url: %w", err)
	}
	config.MaxConns = 4
	config.MinConns = 0

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create audit database pool: %w", err)
	}

	sink := &PostgresAuditSink{pool: pool, writeTimeout: writeTimeout}
	if err := sink.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return sink, nil
}

func (s *PostgresAuditSink) Close() {
	if s == nil || s.pool == nil {
		return
	}
	s.pool.Close()
}

func (s *PostgresAuditSink) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()

	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping audit database: %w", err)
	}
	return nil
}

func (s *PostgresAuditSink) Start(ctx context.Context, entry AuditEntry) error {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()

	if entry.AuditStatus == "" {
		entry.AuditStatus = auditStatusStarted
	}

	_, err := s.pool.Exec(ctx, `
		insert into audit.http_api_calls (
			request_id, client_request_id, started_at, method, path, raw_query,
			route, upstream_url, user_id, remote_ip, auth_result, request_headers,
			request_body_text, request_body_base64, request_body_json, request_body_encoding,
			request_body_size, request_body_truncated, error_code, error_message, audit_status
		)
		values (
			$1, nullif($2, ''), $3, $4, $5, $6,
			nullif($7, ''), nullif($8, ''), $9, nullif($10, ''), $11, $12,
			$13, nullif($14, ''), $15, $16,
			$17, $18, nullif($19, ''), nullif($20, ''), $21
		)
	`, entry.RequestID, entry.ClientRequestID, entry.StartedAt, entry.Method, entry.Path, entry.RawQuery,
		entry.Route, entry.UpstreamURL, entry.UserID, entry.RemoteIP, entry.AuthResult, entry.RequestHeaders,
		entry.RequestBody.Text, entry.RequestBody.Base64, nullJSON(entry.RequestBody.JSON), entry.RequestBody.Encoding,
		entry.RequestBody.Size, entry.RequestBody.Truncated, entry.ErrorCode, entry.ErrorMessage, entry.AuditStatus)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

func (s *PostgresAuditSink) Finish(ctx context.Context, entry AuditEntry) error {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()

	if entry.AuditStatus == "" {
		entry.AuditStatus = auditStatusComplete
	}

	commandTag, err := s.pool.Exec(ctx, `
		update audit.http_api_calls
		set finished_at = $2,
		    duration_ms = $3,
		    route = nullif($4, ''),
		    upstream_url = nullif($5, ''),
		    user_id = $6,
		    auth_result = $7,
		    response_status = $8,
		    response_headers = $9,
		    response_body_text = $10,
		    response_body_base64 = nullif($11, ''),
		    response_body_json = $12,
		    response_body_encoding = $13,
		    response_body_size = $14,
		    response_body_truncated = $15,
		    error_code = nullif($16, ''),
		    error_message = nullif($17, ''),
		    audit_status = $18,
		    updated_at = now()
		where request_id = $1
	`, entry.RequestID, entry.FinishedAt, entry.Duration.Milliseconds(), entry.Route, entry.UpstreamURL,
		entry.UserID, entry.AuthResult, entry.ResponseStatus, entry.ResponseHeaders, entry.ResponseBody.Text,
		entry.ResponseBody.Base64, nullJSON(entry.ResponseBody.JSON), entry.ResponseBody.Encoding,
		entry.ResponseBody.Size, entry.ResponseBody.Truncated, entry.ErrorCode, entry.ErrorMessage, entry.AuditStatus)
	if err != nil {
		return fmt.Errorf("finish audit entry: %w", err)
	}
	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("finish audit entry: request %s was not found", entry.RequestID)
	}
	return nil
}

func normalizeAuditWriteTimeout(value time.Duration) time.Duration {
	if value <= 0 {
		return defaultAuditWriteTimeout
	}
	return value
}

func normalizeAuditMaxBodyBytes(value int64) int64 {
	if value <= 0 {
		return defaultAuditMaxBodyBytes
	}
	return value
}

func requestIDsFromHeader(header http.Header) (uuid.UUID, string) {
	clientRequestID := strings.TrimSpace(header.Get(requestIDHeader))
	if parsed, err := uuid.Parse(clientRequestID); err == nil {
		return parsed, clientRequestID
	}
	return uuid.New(), clientRequestID
}

func readResponseAuditBody(reader io.Reader, contentType string, maxBytes int64) (AuditBody, []byte, error) {
	body, err := io.ReadAll(reader)
	if err != nil {
		return AuditBody{}, nil, err
	}
	auditBody := body
	truncated := int64(len(auditBody)) > maxBytes
	if truncated {
		auditBody = auditBody[:maxBytes]
	}

	return newAuditBody(auditBody, contentType, truncated, len(body)), body, nil
}

func auditBodyFromBytes(body []byte, contentType string, maxBytes int64) AuditBody {
	return auditBodyFromBytesWithOriginalSize(body, contentType, maxBytes, len(body))
}

func auditBodyFromBytesWithOriginalSize(body []byte, contentType string, maxBytes int64, originalSize int) AuditBody {
	auditBody := body
	truncated := int64(len(auditBody)) > maxBytes
	if truncated {
		auditBody = auditBody[:maxBytes]
	}
	if originalSize > len(auditBody) {
		truncated = true
	}
	return newAuditBody(auditBody, contentType, truncated, originalSize)
}

func newAuditBody(body []byte, contentType string, truncated bool, originalSize int) AuditBody {
	result := AuditBody{
		Encoding:  bodyEncodingUTF8,
		Size:      originalSize,
		Truncated: truncated,
	}
	if len(body) == 0 {
		return result
	}

	if utf8.Valid(body) {
		result.Text = string(body)
	} else {
		result.Encoding = bodyEncodingBase64
		result.Base64 = base64.StdEncoding.EncodeToString(body)
	}

	if strings.Contains(strings.ToLower(contentType), bodyContentTypeJSONFragment) && !truncated {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err == nil {
			if err := decoder.Decode(&struct{}{}); err == io.EOF {
				if normalized, err := json.Marshal(value); err == nil {
					result.JSON = normalized
				}
			}
		}
	}

	return result
}

func sanitizedRequestHeaders(headers http.Header) json.RawMessage {
	return sanitizedHeaders(headers, shouldDropAuditRequestHeader)
}

func sanitizedResponseHeaders(headers http.Header) json.RawMessage {
	return sanitizedHeaders(headers, shouldDropAuditResponseHeader)
}

func sanitizedHeaders(headers http.Header, drop func(string) bool) json.RawMessage {
	values := make(map[string][]string)
	for key, headerValues := range headers {
		key = http.CanonicalHeaderKey(key)
		if drop(key) {
			continue
		}
		values[key] = append([]string(nil), headerValues...)
	}

	payload, err := json.Marshal(values)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return payload
}

func shouldDropAuditRequestHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Apikey",
		"Api-Key",
		"X-Api-Key",
		"Authorization",
		"Cookie",
		"Proxy-Authorization",
		"X-Internal-Token",
		"X-User-Id":
		return true
	default:
		return false
	}
}

func shouldDropAuditResponseHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Authorization",
		"Set-Cookie",
		"X-Internal-Token":
		return true
	default:
		return false
	}
}

func nullJSON(value json.RawMessage) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
