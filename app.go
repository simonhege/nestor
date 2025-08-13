package main

import (
	"context"

	"github.com/MicahParks/jwkset"
	"github.com/simonhege/nestor/account"
	"github.com/simonhege/nestor/connector"
	"github.com/simonhege/nestor/privatekeys"
)

type app struct {
	baseURL         string
	jwks            jwkset.Storage
	oidcConfig      *OpenIDConfiguration
	clients         map[string]Client
	accountStore    account.Store
	privateKeyStore privatekeys.Store
}

func (a *app) getClient(ctx context.Context, clientID string) (*Client, error) {
	client, exists := a.clients[clientID]
	if !exists {
		return nil, nil // Client not found
	}
	return &client, nil
}

type Client struct {
	ClientID                 string        `json:"client_id"`
	RedirectURIs             []string      `json:"redirect_uris"`
	DefaultResourceIndicator string        `json:"default_resource_indicator"`
	Connectors               []connector.C `json:"connectors"`
	LoginPage                LoginPage     `json:"login_page"`
}

func (c *Client) GetConnector(connectorID string) *connector.C {
	for _, connector := range c.Connectors {
		if connector.ID == connectorID {
			return &connector
		}
	}
	return nil
}

type LoginPage struct {
	Title       string `json:"title"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Submit      string `json:"submit"`
	ConnectWith string `json:"connect_with"`
}

type AuthorizationData struct {
	ClientID            string
	Code                string
	CodeChallenge       string
	CodeChallengeMethod string

	GrantedScopes []string
	AccountID     string
}
