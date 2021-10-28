package exceptions

import (
	"net/http"
)

type AppError struct {
	Code    int `json:",omitempty"`
	Message string
}

func (error AppError) AsMessage() *AppError {
	return &AppError{
		Message: error.Message,
	}
}
func NewDatabaseError(message string) *AppError {
	return &AppError{http.StatusInternalServerError, message}
}

func NewPayloadParseError(message string) *AppError {
	return &AppError{http.StatusInternalServerError, message}
}

func NewJwtError(message string) *AppError {
	return &AppError{http.StatusForbidden, message}
}
