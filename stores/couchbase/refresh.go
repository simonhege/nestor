package couchbase

import (
	"context"
	"errors"

	"github.com/couchbase/gocb/v2"
	"github.com/simonhege/nestor/refresh"
)

// refreshStore is a Couchbase implementation of the refresh.Store interface.
type refreshStore struct {
	scope      *gocb.Scope
	collection *gocb.Collection
}

// NewRefreshStore creates a new instance of refreshStore with the given Couchbase scope.
func NewRefreshStore(scope *gocb.Scope) (refresh.Store, error) {
	collection := scope.Collection("refresh_tokens")
	return &refreshStore{
		scope:      scope,
		collection: collection,
	}, nil
}

// Put stores the given refresh.Data in the Couchbase collection.
func (r *refreshStore) Put(ctx context.Context, data refresh.Data) error {
	_, err := r.collection.Upsert(data.TokenHash, data, nil)
	return err
}

// Get retrieves the refresh.Data associated with the given token hash from the Couchbase collection.
func (r *refreshStore) Get(ctx context.Context, tokenHash string) (*refresh.Data, error) {
	var data refresh.Data
	doc, err := r.collection.Get(tokenHash, nil)
	if err != nil {
		if errors.Is(err, gocb.ErrDocumentNotFound) {
			return nil, nil
		}
		return nil, err
	}
	err = doc.Content(&data)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

// Delete removes the refresh.Data associated with the given token hash from the Couchbase collection.
func (r *refreshStore) Delete(ctx context.Context, tokenHash string) error {
	_, err := r.collection.Remove(tokenHash, nil)
	return err
}
