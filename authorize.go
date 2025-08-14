package main

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/simonhege/nestor/account"
	"github.com/simonhege/nestor/csrf"
	"github.com/simonhege/nestor/signed"
)

type OAuthParams struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func (a *app) handleAuthorize(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	oauthParams := OAuthParams{
		ClientID:            req.URL.Query().Get("client_id"),
		RedirectURI:         req.URL.Query().Get("redirect_uri"),
		ResponseType:        req.URL.Query().Get("response_type"),
		Scope:               req.URL.Query().Get("scope"),
		State:               req.URL.Query().Get("state"),
		CodeChallenge:       req.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: req.URL.Query().Get("code_challenge_method"),
	}

	if oauthParams.ResponseType != "code" {
		slog.WarnContext(ctx, "Unsupported response_type", "client_id", oauthParams.ClientID, "response_type", oauthParams.ResponseType)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Verify client exists and redirect URI is accepted
	client, err := a.getClient(ctx, oauthParams.ClientID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to get clients", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if client == nil {
		slog.WarnContext(ctx, "Client not found", "client_id", oauthParams.ClientID)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if !slices.Contains(client.RedirectURIs, oauthParams.RedirectURI) {
		slog.WarnContext(ctx, "Invalid redirect URI", "client_id", oauthParams.ClientID, "redirect_uri", oauthParams.RedirectURI)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	csrfToken := csrf.NewToken()

	signed.SetCookie(ctx, w, "oauth_params", oauthParams)
	csrf.SetCookie(w, csrfToken)

	err = executeTemplate(w, "authorize.tmpl", map[string]any{
		"CSRFToken": csrfToken,
		"Client":    client,
	})
	if err != nil {
		slog.ErrorContext(ctx, "Failed to render authorize template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (a *app) handlePostAuthorize(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// Validate against CSRF attacks
	if !csrf.ValidateToken(req) {
		slog.WarnContext(ctx, "CSRF token validation failed")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get OAuth parameters from the cookie
	var oauthParams OAuthParams
	if err := signed.ReadCookie(req, "oauth_params", &oauthParams); err != nil {
		slog.WarnContext(ctx, "Failed to decode OAuth params", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Authenticate the user
	email := req.FormValue("email")
	if email == "" {
		slog.WarnContext(ctx, "Email is required for authorization")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	password := req.FormValue("password")
	if password == "" {
		slog.WarnContext(ctx, "Password is required for authorization")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	acc, _ := a.accountStore.GetByEmail(ctx, email)
	if acc == nil {
		slog.WarnContext(ctx, "Unauthorized", "client_id", oauthParams.ClientID, "email", email)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !acc.CheckPassword(password) {
		slog.WarnContext(ctx, "Invalid password", "client_id", oauthParams.ClientID, "email", email)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	a.handleRedirect(ctx, w, req, oauthParams, acc)
}

func (a *app) handleRedirect(ctx context.Context, w http.ResponseWriter, req *http.Request, oauthParams OAuthParams, acc *account.Account) {

	authData := AuthorizationData{
		ClientID:            oauthParams.ClientID,
		Code:                rand.Text(),
		CodeChallenge:       oauthParams.CodeChallenge,
		CodeChallengeMethod: oauthParams.CodeChallengeMethod,

		GrantedScopes: strings.Split(oauthParams.Scope, " "),
		AccountID:     acc.ID,
	}

	// Save the authorization data for token exchange in a same site strict cookie
	signed.SetCookie(ctx, w, "auth_data", authData)

	// Generate the code and redirect to the redirect_uri
	params := url.Values{
		"code":  []string{authData.Code},
		"state": []string{oauthParams.State},
	}
	redirectURL := oauthParams.RedirectURI + "?" + params.Encode()
	slog.InfoContext(ctx, "redirecting to", "url", redirectURL)
	http.Redirect(w, req, redirectURL, http.StatusFound)
}
