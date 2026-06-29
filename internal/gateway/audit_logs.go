package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	defaultAuditLogLimit = 50
	maxAuditLogLimit     = 200
)

type AuditLogStore interface {
	ListHTTPAPICalls(ctx context.Context, filter AuditLogFilter) ([]json.RawMessage, error)
	GetHTTPAPICall(ctx context.Context, requestID uuid.UUID) (json.RawMessage, bool, error)
}

type AuditLogFilter struct {
	Limit          int
	RequestID      *uuid.UUID
	UserID         *uuid.UUID
	Method         string
	PathContains   string
	Route          string
	AuthResult     string
	ResponseStatus *int
	Since          *time.Time
	Until          *time.Time
}

func (s *PostgresAuditSink) ListHTTPAPICalls(ctx context.Context, filter AuditLogFilter) ([]json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()

	filter = normalizeAuditLogFilter(filter)
	conditions, args := auditLogWhereClause(filter)
	args = append(args, filter.Limit)
	limitPlaceholder := len(args)

	query := fmt.Sprintf(`
		select jsonb_build_object(
			'request_id', request_id,
			'client_request_id', client_request_id,
			'started_at', started_at,
			'finished_at', finished_at,
			'duration_ms', duration_ms,
			'method', method,
			'path', path,
			'raw_query', raw_query,
			'route', route,
			'user_id', user_id,
			'remote_ip', remote_ip,
			'auth_result', auth_result,
			'response_status', response_status,
			'request_body_size', request_body_size,
			'request_body_truncated', request_body_truncated,
			'request_body_preview', left(coalesce(request_body_text, request_body_base64, ''), 320),
			'response_body_size', response_body_size,
			'response_body_truncated', response_body_truncated,
			'response_body_preview', left(coalesce(response_body_text, response_body_base64, ''), 320),
			'error_code', error_code,
			'error_message', error_message,
			'audit_status', audit_status
		)
		from audit.http_api_calls
		%s
		order by started_at desc, request_id desc
		limit $%d
	`, conditions, limitPlaceholder)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit log entries: %w", err)
	}
	defer rows.Close()

	items := make([]json.RawMessage, 0, filter.Limit)
	for rows.Next() {
		var item json.RawMessage
		if err := rows.Scan(&item); err != nil {
			return nil, fmt.Errorf("scan audit log entry: %w", err)
		}
		items = append(items, append(json.RawMessage(nil), item...))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit log entries: %w", err)
	}

	return items, nil
}

func (s *PostgresAuditSink) GetHTTPAPICall(ctx context.Context, requestID uuid.UUID) (json.RawMessage, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout)
	defer cancel()

	var item json.RawMessage
	err := s.pool.QueryRow(ctx, `
		select jsonb_build_object(
			'request_id', request_id,
			'client_request_id', client_request_id,
			'started_at', started_at,
			'finished_at', finished_at,
			'duration_ms', duration_ms,
			'method', method,
			'path', path,
			'raw_query', raw_query,
			'route', route,
			'upstream_url', upstream_url,
			'user_id', user_id,
			'remote_ip', remote_ip,
			'auth_result', auth_result,
			'request_headers', request_headers,
			'request_body_text', request_body_text,
			'request_body_base64', request_body_base64,
			'request_body_json', request_body_json,
			'request_body_encoding', request_body_encoding,
			'request_body_size', request_body_size,
			'request_body_truncated', request_body_truncated,
			'response_status', response_status,
			'response_headers', response_headers,
			'response_body_text', response_body_text,
			'response_body_base64', response_body_base64,
			'response_body_json', response_body_json,
			'response_body_encoding', response_body_encoding,
			'response_body_size', response_body_size,
			'response_body_truncated', response_body_truncated,
			'error_code', error_code,
			'error_message', error_message,
			'audit_status', audit_status
		)
		from audit.http_api_calls
		where request_id = $1
	`, requestID).Scan(&item)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("query audit log entry: %w", err)
	}

	return append(json.RawMessage(nil), item...), true, nil
}

func normalizeAuditLogFilter(filter AuditLogFilter) AuditLogFilter {
	if filter.Limit <= 0 {
		filter.Limit = defaultAuditLogLimit
	}
	if filter.Limit > maxAuditLogLimit {
		filter.Limit = maxAuditLogLimit
	}
	filter.Method = strings.ToUpper(strings.TrimSpace(filter.Method))
	filter.PathContains = strings.TrimSpace(filter.PathContains)
	filter.Route = strings.TrimSpace(filter.Route)
	filter.AuthResult = strings.TrimSpace(filter.AuthResult)
	return filter
}

func auditLogWhereClause(filter AuditLogFilter) (string, []any) {
	filter = normalizeAuditLogFilter(filter)
	conditions := make([]string, 0, 8)
	args := make([]any, 0, 8)
	add := func(condition string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(condition, len(args)))
	}

	if filter.RequestID != nil {
		add("request_id = $%d", *filter.RequestID)
	}
	if filter.UserID != nil {
		add("user_id = $%d", *filter.UserID)
	}
	if filter.Method != "" {
		add("method = $%d", filter.Method)
	}
	if filter.PathContains != "" {
		add("path ilike '%%' || $%d || '%%'", filter.PathContains)
	}
	if filter.Route != "" {
		add("route = $%d", filter.Route)
	} else if filter.RequestID == nil {
		add("(route is null or route <> $%d)", auditAdminRouteName)
	}
	if filter.AuthResult != "" {
		add("auth_result = $%d", filter.AuthResult)
	}
	if filter.ResponseStatus != nil {
		add("response_status = $%d", *filter.ResponseStatus)
	}
	if filter.Since != nil {
		add("started_at >= $%d", *filter.Since)
	}
	if filter.Until != nil {
		add("started_at < $%d", *filter.Until)
	}

	if len(conditions) == 0 {
		return "", args
	}
	return "where " + strings.Join(conditions, " and "), args
}
