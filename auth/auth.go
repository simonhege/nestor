package auth

import "context"

// AuthData represents the data associated with an authentication request.
type AuthData struct {
	ClientID            string
	Code                string
	CodeChallenge       string
	CodeChallengeMethod string
	GrantedScopes       []string
	AccountID           string
}

// Store defines the interface for storing and retrieving authentication data.
type Store interface {
	Put(ctx context.Context, authData AuthData) error
	Get(ctx context.Context, code string) (*AuthData, error)
	Delete(ctx context.Context, code string) error
}
