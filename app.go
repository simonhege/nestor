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
	oidcConfig      *openIDConfiguration
	clients         map[string]client
	connectors      []connector.C
	accountStore    account.Store
	privateKeyStore privatekeys.Store
}

func (a *app) getClient(ctx context.Context, clientID string) (*client, error) {
	client, exists := a.clients[clientID]
	if !exists {
		return nil, nil // Client not found
	}
	return &client, nil
}

type client struct {
	ClientID                 string    `json:"client_id"`
	RedirectURIs             []string  `json:"redirect_uris"`
	DefaultResourceIndicator string    `json:"default_resource_indicator"`
	LoginPage                loginPage `json:"login_page"`
}

type loginPage struct {
	Title       string `json:"title"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Submit      string `json:"submit"`
	ConnectWith string `json:"connect_with"`
}

type authorizationData struct {
	ClientID            string
	Code                string
	CodeChallenge       string
	CodeChallengeMethod string

	GrantedScopes []string
	AccountID     string
}
