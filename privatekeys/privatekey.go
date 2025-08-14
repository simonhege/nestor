package privatekeys

import (
	"context"
)

type Store interface {
	All() ([]PrivateKey, error)
	Put(ctx context.Context, key PrivateKey) error
}

type PrivateKey struct {
	KID        string `json:"kid"`
	PrivateKey []byte `json:"private_key"`
}
