package main

import (
	"crypto/rand"
	"log/slog"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/simonhege/nestor/account"
	"github.com/simonhege/nestor/signed"
	"golang.org/x/oauth2"
)

func (a *app) handleLogin(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	connectorID := req.PathValue("connector")

	// Get OAuth parameters from the cookie
	var oauthParams OAuthParams
	if err := signed.ReadCookie(req, "oauth_params", &oauthParams); err != nil {
		slog.WarnContext(ctx, "Failed to decode OAuth params", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	client, err := a.getClient(ctx, oauthParams.ClientID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get client", "client_id", oauthParams.ClientID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	connector := client.GetConnector(connectorID)
	if connector == nil {
		slog.ErrorContext(ctx, "Connector not found", "client_id", oauthParams.ClientID, "connector_id", connectorID)
		http.Error(w, "Connector not found", http.StatusNotFound)
		return
	}

	slog.InfoContext(ctx, "Starting OIDC login flow", "issuer", connector.Config.Issuer, "client_id", connector.Config.ClientID)

	provider, err := oidc.NewProvider(ctx, connector.Config.Issuer) // TODO cache this provider
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create OIDC provider", "issuer", connector.Config.Issuer, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	oauth2Config := oauth2.Config{
		ClientID:     connector.Config.ClientID,
		ClientSecret: connector.Config.ClientSecret,
		RedirectURL:  a.baseURL + "/" + connectorID + "/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	state := rand.Text() // Generate a random state parameter
	authURL := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOnline)

	signed.SetCrossSiteCookie(ctx, w, "connector_state", state)
	signed.SetCrossSiteCookie(ctx, w, "oauth_params", oauthParams)

	http.Redirect(w, req, authURL, http.StatusFound)
}

func (a *app) handleCallback(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	connectorID := req.PathValue("connector")

	// Get OAuth parameters from the cookie
	var oauthParams OAuthParams
	if err := signed.ReadCookie(req, "oauth_params", &oauthParams); err != nil {
		slog.WarnContext(ctx, "Failed to decode OAuth params", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	client, err := a.getClient(ctx, oauthParams.ClientID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get client", "client_id", oauthParams.ClientID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	connector := client.GetConnector(connectorID)
	if connector == nil {
		slog.ErrorContext(ctx, "Connector not found", "client_id", oauthParams.ClientID, "connector_id", connectorID)
		http.Error(w, "Connector not found", http.StatusNotFound)
		return
	}

	provider, err := oidc.NewProvider(ctx, connector.Config.Issuer)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create OIDC provider", "issuer", connector.Config.Issuer, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: connector.Config.ClientID})

	oauth2Config := oauth2.Config{
		ClientID:     connector.Config.ClientID,
		ClientSecret: connector.Config.ClientSecret,
		RedirectURL:  a.baseURL + "/" + connectorID + "/callback",

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "email"},
	}

	token, err := oauth2Config.Exchange(ctx, req.FormValue("code"))

	if err != nil {
		slog.ErrorContext(ctx, "Failed to exchange code for token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		slog.ErrorContext(ctx, "No id_token in token response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to verify ID token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	// Extract custom claims
	var claims struct {
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		slog.ErrorContext(ctx, "Failed to extract claims from ID token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	slog.InfoContext(ctx, "User authenticated", "claims", claims)

	accountID := connectorID + "|" + idToken.Subject

	acc, err := a.accountStore.GetById(ctx, accountID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to retrieve account", "accountID", accountID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if acc == nil {
		slog.InfoContext(ctx, "No account found, creating new")
		tNow := time.Now()
		acc = &account.Account{
			ID:        accountID,
			Email:     claims.Email,
			Name:      claims.Name,
			Picture:   claims.Picture,
			CreatedAt: tNow,
			UpdatedAt: tNow,
			Status:    account.StatusActive,
		}
		if err := a.accountStore.Put(ctx, *acc); err != nil {
			slog.ErrorContext(ctx, "Failed to create account", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		updateNeeded := false
		if acc.Email != claims.Email {
			acc.Email = claims.Email
			updateNeeded = true
		}
		if acc.Name != claims.Name {
			acc.Name = claims.Name
			updateNeeded = true
		}
		if acc.Picture != claims.Picture {
			acc.Picture = claims.Picture
			updateNeeded = true
		}

		if updateNeeded {
			acc.UpdatedAt = time.Now()
			if err := a.accountStore.Put(ctx, *acc); err != nil {
				slog.ErrorContext(ctx, "Failed to update account", "error", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}
	}

	a.handleRedirect(ctx, w, req, oauthParams, acc)
}
