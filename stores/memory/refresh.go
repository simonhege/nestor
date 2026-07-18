package memory

import (
	"context"

	"github.com/simonhege/nestor/refresh"
)

// RefreshStore is an in-memory implementation of the refresh.Store interface.
type RefreshStore struct {
	Data map[string]refresh.Data
}

// Put stores the given refresh.Data in the in-memory store.
func (s *RefreshStore) Put(ctx context.Context, data refresh.Data) error {
	s.Data[data.TokenHash] = data
	return nil
}

// Get retrieves the refresh.Data associated with the given token hash from the in-memory store.
func (s *RefreshStore) Get(ctx context.Context, tokenHash string) (*refresh.Data, error) {
	data, exists := s.Data[tokenHash]
	if !exists {
		return nil, nil
	}
	return &data, nil
}

// Delete removes the refresh.Data associated with the given token hash from the in-memory store.
func (s *RefreshStore) Delete(ctx context.Context, tokenHash string) error {
	delete(s.Data, tokenHash)
	return nil
}
