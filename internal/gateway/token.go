package gateway

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const base64CookiePrefix = "base64-"

func extractAccessToken(r *http.Request, authCookieName string) (string, bool) {
	if token, ok := bearerToken(r.Header.Get("Authorization")); ok {
		return token, true
	}

	return accessTokenFromCookies(r.Cookies(), authCookieName)
}

func bearerToken(value string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", false
	}

	token := strings.TrimSpace(fields[1])
	return token, token != ""
}

func accessTokenFromCookies(cookies []*http.Cookie, preferredName string) (string, bool) {
	values := make(map[string]string, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		values[cookie.Name] = cookie.Value
	}

	if preferredName != "" {
		if token, ok := accessTokenFromCookie(values, preferredName); ok {
			return token, true
		}
	}

	candidates := make(map[string]struct{})
	for name := range values {
		baseName := chunkBaseName(name)
		if strings.HasPrefix(baseName, "sb-") && strings.HasSuffix(baseName, "-auth-token") {
			candidates[baseName] = struct{}{}
		}
	}

	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if token, ok := accessTokenFromCookie(values, name); ok {
			return token, true
		}
	}

	return "", false
}

func accessTokenFromCookie(values map[string]string, name string) (string, bool) {
	rawValue := combineCookieChunks(values, name)
	if rawValue == "" {
		return "", false
	}

	return decodeSessionAccessToken(rawValue)
}

func combineCookieChunks(values map[string]string, name string) string {
	if value := values[name]; value != "" {
		return value
	}

	var builder strings.Builder
	for index := 0; ; index++ {
		value, ok := values[name+"."+strconv.Itoa(index)]
		if !ok {
			break
		}
		builder.WriteString(value)
	}

	return builder.String()
}

func chunkBaseName(name string) string {
	dot := strings.LastIndex(name, ".")
	if dot == -1 || dot == len(name)-1 {
		return name
	}
	for _, char := range name[dot+1:] {
		if char < '0' || char > '9' {
			return name
		}
	}
	return name[:dot]
}

func decodeSessionAccessToken(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}

	if strings.HasPrefix(value, base64CookiePrefix) {
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, base64CookiePrefix))
		if err != nil {
			return "", false
		}
		value = string(decoded)
	} else if decoded, err := url.QueryUnescape(value); err == nil {
		value = decoded
	}

	var session struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(value), &session); err == nil && strings.TrimSpace(session.AccessToken) != "" {
		return strings.TrimSpace(session.AccessToken), true
	}

	var legacy []string
	if err := json.Unmarshal([]byte(value), &legacy); err == nil && len(legacy) > 0 && strings.TrimSpace(legacy[0]) != "" {
		return strings.TrimSpace(legacy[0]), true
	}

	return "", false
}
