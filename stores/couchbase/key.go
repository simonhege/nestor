package couchbase

import (
	"context"

	"github.com/couchbase/gocb/v2"
	"github.com/simonhege/nestor/privatekeys"
)

type privateKeyStore struct {
	scope      *gocb.Scope
	collection *gocb.Collection
}

func NewPrivateKeyStore(scope *gocb.Scope) (privatekeys.Store, error) {
	collection := scope.Collection("privatekeys")
	return &privateKeyStore{
		scope:      scope,
		collection: collection,
	}, nil
}

// All implements privatekeys.Store.
func (p privateKeyStore) All() ([]privatekeys.PrivateKey, error) {
	rows, err := p.scope.Query("SELECT `kid`, `private_key` FROM `"+p.collection.Name()+"`", nil)
	if err != nil {
		return nil, err
	}

	var keys []privatekeys.PrivateKey
	for rows.Next() {
		var key privatekeys.PrivateKey
		if err := rows.Row(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	return keys, nil
}

// Put implements privatekeys.Store.
func (p privateKeyStore) Put(ctx context.Context, key privatekeys.PrivateKey) error {
	_, err := p.collection.Upsert(key.KID, key, &gocb.UpsertOptions{
		Expiry: 0, // No expiry
	})
	return err
}
