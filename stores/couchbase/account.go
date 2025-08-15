package couchbase

import (
	"context"
	"errors"
	"fmt"

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
	query := "SELECT acct.* FROM `" + a.collection.Name() +
		"` as acct WHERE acct.email = $email"
	parameters := map[string]interface{}{
		"email": email,
	}

	rows, err := a.scope.Query(query, &gocb.QueryOptions{
		NamedParameters: parameters,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query accounts by email: %w", err)
	}

	var acct account.Account
	if err := rows.One(&acct); err != nil {
		if errors.Is(err, gocb.ErrNoResult) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to decode account: %w", err)
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

// GetByExternalRef implements account.Store.
func (a *accountStore) GetByExternalRef(ctx context.Context, connector string, sub string) (*account.Account, error) {
	query := "SELECT acct.* FROM `" + a.collection.Name() +
		"` as acct WHERE ANY ref IN acct.external_refs SATISFIES ref.connector = $connector AND ref.sub = $sub END;"
	parameters := map[string]interface{}{
		"connector": connector,
		"sub":       sub,
	}

	rows, err := a.scope.Query(query, &gocb.QueryOptions{
		NamedParameters: parameters,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query accounts by external reference: %w", err)
	}

	var acct account.Account
	if err := rows.One(&acct); err != nil {
		if errors.Is(err, gocb.ErrNoResult) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to decode account: %w", err)
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

// Delete implements account.Store.
func (a *accountStore) Delete(ctx context.Context, id string) error {
	_, err := a.collection.Remove(id, nil)
	return err
}
