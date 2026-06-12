package gateway

import "github.com/google/uuid"

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type User struct {
	ID uuid.UUID
}
