package memory

import (
	"context"

	"github.com/simonhege/nestor/account"
)

type AccountStore struct {
	Data map[string]account.Account
}

func (s *AccountStore) Put(ctx context.Context, account account.Account) error {
	s.Data[account.ID] = account
	return nil
}

func (s *AccountStore) GetByExternalRef(ctx context.Context, connector, sub string) (*account.Account, error) {
	for _, account := range s.Data {
		for _, ref := range account.ExternalRefs {
			if ref.Connector == connector && ref.Sub == sub {
				return &account, nil
			}
		}
	}
	return nil, nil
}

func (s *AccountStore) GetByEmail(ctx context.Context, email string) (*account.Account, error) {
	for _, account := range s.Data {
		if account.Email == email {
			return &account, nil
		}
	}
	return nil, nil
}

func (s *AccountStore) GetById(ctx context.Context, id string) (*account.Account, error) {
	account, exists := s.Data[id]
	if !exists {
		return nil, nil
	}
	return &account, nil
}

func (s *AccountStore) Delete(ctx context.Context, id string) error {
	delete(s.Data, id)
	return nil
}
