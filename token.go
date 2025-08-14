package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/simonhege/nestor/account"
	"github.com/simonhege/nestor/signed"
	"github.com/simonhege/server"
)

func (a *app) handleToken(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	// Dump the request for debugging purposes
	b, _ := httputil.DumpRequest(req, true)
	slog.DebugContext(ctx, "token request received", "request", string(b))

	client_id := req.FormValue("client_id")
	// redirect_uri := req.FormValue("redirect_uri") // TODO why do we receive a redirect uri?
	grant_type := req.FormValue("grant_type")
	code := req.FormValue("code")
	code_verifier := req.FormValue("code_verifier")

	if grant_type != "authorization_code" {
		slog.WarnContext(ctx, "Unsupported grant_type", "client_id", client_id, "grant_type", grant_type)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Retrieve the authorization data
	var authData AuthorizationData
	if err := signed.ReadCookie(req, "auth_data", &authData); err != nil {
		slog.ErrorContext(ctx, "Failed to retrieve authorization data", "client_id", client_id, "code", code)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Delete the cookie to prevent reuse
	signed.DeleteCookie(w, "auth_data")

	if authData.ClientID != client_id {
		slog.WarnContext(ctx, "Incorrect client id", "client_id", client_id, "authData.ClientID", authData.ClientID)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Compute the hash from the generated code and compare
	codeChallengeResult, err := a.computeCodeChallenge(ctx, authData.CodeChallengeMethod, code_verifier)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to compute code challenge", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if codeChallengeResult != authData.CodeChallenge {
		slog.WarnContext(ctx, "Incorrect code challenge")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Retrieve the account associated with the authorization data
	acc, err := a.accountStore.GetById(ctx, authData.AccountID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to retrieve account", "account_id", authData.AccountID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if acc == nil {
		slog.WarnContext(ctx, "Account not found", "account_id", authData.AccountID)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if acc.Status != account.StatusActive {
		slog.WarnContext(ctx, "Account not active", "account_id", acc.ID, "status", acc.Status)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Retrieve the client information
	client, err := a.getClient(ctx, client_id)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to retrieve client", "client_id", client_id, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	accessToken, err := a.createSignedToken(ctx, client.DefaultResourceIndicator, acc)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create signed token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	id_token, err := a.createSignedToken(ctx, client_id, acc)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create signed token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600, // 1 hour
		IDToken:     id_token,
	}

	server.RenderJSON(w, resp)
}

func (a *app) computeCodeChallenge(context context.Context, method string, generated_code string) (string, error) {
	switch method {
	case "S256":
		hash := sha256.Sum256([]byte(generated_code))
		return base64.RawURLEncoding.EncodeToString(hash[:]), nil
	}
	return "", fmt.Errorf("unsupported code challenge method '%s'", method)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (a *app) createSignedToken(ctx context.Context, audience string, account *account.Account) (string, error) {

	keys, err := a.jwks.KeyReadAll(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to read JWKs: %w", err)
	}
	if len(keys) == 0 {
		return "", fmt.Errorf("no JWKs available for signing")
	}
	k := keys[0]

	tNow := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":            a.oidcConfig.Issuer,
		"aud":            audience,
		"iat":            tNow.Unix(),
		"auth_time":      tNow.Unix(),
		"nbf":            tNow.Unix(),
		"sub":            account.ID,
		"exp":            tNow.Add(24 * time.Hour).Unix(),
		"email":          account.Email,
		"email_verified": true,
		"name":           account.Name,
		"picture":        account.Picture,
	})
	token.Header["kid"] = k.Marshal().KID

	signedToken, err := token.SignedString(k.Key())
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return signedToken, nil
}
