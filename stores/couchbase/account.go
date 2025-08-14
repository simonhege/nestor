package couchbase

import (
	"context"
	"errors"

	"github.com/couchbase/gocb/v2"
	"github.com/simonhege/nestor/account"
)

type accountStore struct {
	scope      *gocb.Scope
	collection *gocb.Collection
}

func NewAccountStore(scope *gocb.Scope) (account.Store, error) {
	collection := scope.Collection("accounts")
	return &accountStore{
		scope:      scope,
		collection: collection,
	}, nil
}

// GetByEmail implements account.Store.
func (a *accountStore) GetByEmail(ctx context.Context, email string) (*account.Account, error) {
	query := "SELECT id, email, name, picture, status, password_hash, created, updated_at FROM `" + a.collection.Name() + "` WHERE email = $email"
	parameters := map[string]interface{}{
		"email": email,
	}

	rows, err := a.scope.Query(query, &gocb.QueryOptions{
		NamedParameters: parameters,
	})
	if err != nil {
		return nil, err
	}

	var acct account.Account
	if err := rows.One(&acct); err != nil {
		return nil, err
	}
	return &acct, nil
}

// GetById implements account.Store.
func (a *accountStore) GetById(ctx context.Context, id string) (*account.Account, error) {
	var acct account.Account
	doc, err := a.collection.Get(id, nil)
	if err != nil {
		if errors.Is(err, gocb.ErrDocumentNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if err := doc.Content(&acct); err != nil {
		return nil, err
	}
	return &acct, nil
}

// Put implements account.Store.
func (a *accountStore) Put(ctx context.Context, account account.Account) error {
	_, err := a.collection.Upsert(account.ID, account, &gocb.UpsertOptions{
		Expiry: 0, // No expiry
	})
	return err
}
