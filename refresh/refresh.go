package refresh

import (
	"context"
	"time"
)

// Data represents server-side persisted refresh token metadata.
type Data struct {
	TokenHash     string
	ClientID      string
	AccountID     string
	GrantedScopes []string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// Store defines refresh token persistence operations.
type Store interface {
	Put(ctx context.Context, data Data) error
	Get(ctx context.Context, tokenHash string) (*Data, error)
	Delete(ctx context.Context, tokenHash string) error
}
