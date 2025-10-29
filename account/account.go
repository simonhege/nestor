package account

import (
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Account struct {
	ID           string        `json:"id"`
	Email        string        `json:"email"`
	Name         string        `json:"name"`
	Picture      string        `json:"picture"`
	Status       AccountStatus `json:"status"`
	Roles        []string      `json:"roles"`
	PasswordHash []byte        `json:"password_hash,omitempty"` // Use nil if no password is set
	ExternalRefs []ExternalRef `json:"external_refs,omitempty"` // References to external accounts

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ExternalRef struct {
	Connector string `json:"connector"`
	Sub       string `json:"sub"`
}

type AccountStatus string

const (
	StatusPending   AccountStatus = "pending"   // Account is created but email not yet verified
	StatusActive    AccountStatus = "active"    // Account is active and email is verified
	StatusSuspended AccountStatus = "suspended" // Account is suspended, cannot log in or perform actions
)

func (a *Account) CheckPassword(password string) bool {
	if a.PasswordHash == nil {
		return false // No password set, cannot check
	}
	return bcrypt.CompareHashAndPassword(a.PasswordHash, []byte(password)) == nil
}

type Store interface {
	GetById(ctx context.Context, id string) (*Account, error)
	GetByEmail(ctx context.Context, email string) (*Account, error)
	GetByExternalRef(ctx context.Context, connector, sub string) (*Account, error)
	Put(ctx context.Context, account Account) error
	Delete(ctx context.Context, id string) error
}
