package zitadel

import "github.com/zitadel/zitadel-go/v3/pkg/client"

var _ Storer = (*Store)(nil)

type Storer interface {
	GetQuerier() Querier
}
type Store struct {
	client *client.Client
}

func (s *Store) GetQuerier() Querier {
	return newQuerier(s.client)
}

func NewZitadelStore(client *client.Client) *Store {
	return &Store{
		client: client,
	}
}
