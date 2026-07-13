package couchbase

import (
	"context"
	"errors"

	"github.com/couchbase/gocb/v2"
	"github.com/simonhege/nestor/auth"
)

// authStore is a Couchbase implementation of the auth.Store interface.
type authStore struct {
	scope      *gocb.Scope
	collection *gocb.Collection
}

// NewAuthStore creates a new instance of authStore with the given Couchbase scope.
func NewAuthStore(scope *gocb.Scope) (auth.Store, error) {
	collection := scope.Collection("auth_data")
	return &authStore{
		scope:      scope,
		collection: collection,
	}, nil
}

// Put stores the given AuthData in the Couchbase collection.
func (a *authStore) Put(ctx context.Context, data auth.AuthData) error {
	_, err := a.collection.Upsert(data.Code, data, nil)
	return err
}

// Get retrieves the AuthData associated with the given code from the Couchbase collection.
func (a *authStore) Get(ctx context.Context, code string) (*auth.AuthData, error) {
	var data auth.AuthData
	doc, err := a.collection.Get(code, nil)
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

// Delete removes the AuthData associated with the given code from the Couchbase collection.
func (a *authStore) Delete(ctx context.Context, code string) error {
	_, err := a.collection.Remove(code, nil)
	return err
}
