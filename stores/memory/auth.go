package memory

import (
	"context"

	"github.com/simonhege/nestor/auth"
)

// AuthStore is an in-memory implementation of the auth.Store interface.
type AuthStore struct {
	Data map[string]auth.AuthData
}

// Put stores the given AuthData in the in-memory store.
func (s *AuthStore) Put(ctx context.Context, authData auth.AuthData) error {
	s.Data[authData.Code] = authData
	return nil
}

// Get retrieves the AuthData associated with the given code from the in-memory store.
func (s *AuthStore) Get(ctx context.Context, code string) (*auth.AuthData, error) {
	authData, exists := s.Data[code]
	if !exists {
		return nil, nil
	}
	return &authData, nil
}

// Delete removes the AuthData associated with the given code from the in-memory store.
func (s *AuthStore) Delete(ctx context.Context, code string) error {
	delete(s.Data, code)
	return nil
}
