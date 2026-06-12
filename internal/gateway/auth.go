package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrInvalidSession  = errors.New("invalid session")
	ErrAuthUnavailable = errors.New("auth unavailable")
)

type AuthVerifier interface {
	Verify(ctx context.Context, accessToken string) (User, error)
}

type SupabaseVerifier struct {
	userURL string
	anonKey string
	client  *http.Client
}

func NewSupabaseVerifier(supabaseURL string, anonKey string, client *http.Client) (*SupabaseVerifier, error) {
	base, err := url.Parse(strings.TrimSpace(supabaseURL))
	if err != nil {
		return nil, fmt.Errorf("parse SUPABASE_URL: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("SUPABASE_URL must be an absolute URL")
	}
	if strings.TrimSpace(anonKey) == "" {
		return nil, fmt.Errorf("SUPABASE_ANON_KEY is required")
	}
	if client == nil {
		client = http.DefaultClient
	}

	userURL, err := url.JoinPath(base.String(), "auth", "v1", "user")
	if err != nil {
		return nil, fmt.Errorf("build Supabase user URL: %w", err)
	}

	return &SupabaseVerifier{
		userURL: userURL,
		anonKey: strings.TrimSpace(anonKey),
		client:  client,
	}, nil
}

func (v *SupabaseVerifier) Verify(ctx context.Context, accessToken string) (User, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return User{}, ErrInvalidSession
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.userURL, nil)
	if err != nil {
		return User{}, fmt.Errorf("%w: create auth request", ErrAuthUnavailable)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("apikey", v.anonKey)

	response, err := v.client.Do(request)
	if err != nil {
		return User{}, fmt.Errorf("%w: %v", ErrAuthUnavailable, err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return User{}, ErrInvalidSession
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return User{}, fmt.Errorf("%w: auth returned %d", ErrAuthUnavailable, response.StatusCode)
	}

	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return User{}, fmt.Errorf("%w: decode auth response", ErrAuthUnavailable)
	}

	userID, err := uuid.Parse(strings.TrimSpace(body.ID))
	if err != nil {
		return User{}, ErrInvalidSession
	}

	return User{ID: userID}, nil
}
