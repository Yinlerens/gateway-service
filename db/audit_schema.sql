create schema if not exists audit;

create table if not exists audit.http_api_calls (
  request_id uuid primary key,
  client_request_id text,
  started_at timestamptz not null,
  finished_at timestamptz,
  duration_ms bigint,
  method text not null,
  path text not null,
  raw_query text not null default '',
  route text,
  upstream_url text,
  user_id uuid,
  remote_ip text,
  auth_result text not null,
  request_headers jsonb not null default '{}'::jsonb,
  request_body_text text,
  request_body_base64 text,
  request_body_json jsonb,
  request_body_encoding text not null default 'utf8',
  request_body_size integer not null default 0,
  request_body_truncated boolean not null default false,
  response_status integer,
  response_headers jsonb,
  response_body_text text,
  response_body_base64 text,
  response_body_json jsonb,
  response_body_encoding text,
  response_body_size integer,
  response_body_truncated boolean,
  error_code text,
  error_message text,
  audit_status text not null default 'started',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint http_api_calls_method_check check (method <> ''),
  constraint http_api_calls_duration_check check (duration_ms is null or duration_ms >= 0),
  constraint http_api_calls_request_body_encoding_check check (request_body_encoding in ('utf8', 'base64')),
  constraint http_api_calls_response_body_encoding_check check (response_body_encoding is null or response_body_encoding in ('utf8', 'base64')),
  constraint http_api_calls_audit_status_check check (audit_status in ('started', 'complete'))
);

create index if not exists http_api_calls_started_at_idx
  on audit.http_api_calls (started_at desc);

create index if not exists http_api_calls_user_started_idx
  on audit.http_api_calls (user_id, started_at desc);

create index if not exists http_api_calls_path_started_idx
  on audit.http_api_calls (path, started_at desc);

create index if not exists http_api_calls_status_started_idx
  on audit.http_api_calls (response_status, started_at desc);

alter table audit.http_api_calls enable row level security;
