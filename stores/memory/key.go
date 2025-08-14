package memory

import (
	"context"

	"github.com/simonhege/nestor/privatekeys"
)

type PrivateKeyStore struct{}

// All implements privatekeys.Store.
func (p PrivateKeyStore) All() ([]privatekeys.PrivateKey, error) {
	return nil, nil
}

// Put implements privatekeys.Store.
func (p PrivateKeyStore) Put(ctx context.Context, key privatekeys.PrivateKey) error {
	return nil
}

var _ privatekeys.Store = PrivateKeyStore{}
