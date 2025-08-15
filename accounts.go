package main

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

var errUnauthorized = errors.New("unauthorized")

func (a *app) getTokenFromRequest(req *http.Request) (*jwt.Token, error) {
	// Extract the JWT token from the Authorization header
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errUnauthorized
	}

	// The token is expected to be in the format "Bearer <token>"
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return nil, errUnauthorized
	}

	token := authHeader[7:]
	kf, err := keyfunc.New(keyfunc.Options{
		Ctx:     req.Context(),
		Storage: a.jwks,
	})
	if err != nil {
		slog.ErrorContext(req.Context(), "Failed to create keyfunc", "error", err)
		return nil, errUnauthorized
	}
	// No audience validation, signature by us is enough to trust the token
	jwtToken, err := jwt.Parse(token, kf.Keyfunc)
	if err != nil {
		slog.ErrorContext(req.Context(), "Failed to parse JWT token", "error", err)
		return nil, errUnauthorized
	}
	if !jwtToken.Valid {
		slog.ErrorContext(req.Context(), "Invalid JWT token", "error", err)
		return nil, errUnauthorized
	}

	return jwtToken, nil
}
