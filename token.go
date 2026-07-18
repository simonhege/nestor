package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/simonhege/nestor/account"
	"github.com/simonhege/nestor/refresh"
	"github.com/simonhege/server"
)

const (
	accessTokenTTL  = 1 * time.Hour
	refreshTokenTTL = 30 * 24 * time.Hour
)

func (a *app) handleToken(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	// Dump the request for debugging purposes
	b, _ := httputil.DumpRequest(req, true)
	slog.DebugContext(ctx, "token request received", "request", string(b))

	clientID := req.FormValue("client_id")
	grantType := req.FormValue("grant_type")
	var (
		resp tokenResponse
		err  error
	)

	switch grantType {
	case "authorization_code":
		resp, err = a.handleAuthorizationCodeGrant(ctx, clientID, req)
	case "refresh_token":
		resp, err = a.handleRefreshTokenGrant(ctx, clientID, req)
	default:
		slog.WarnContext(ctx, "Unsupported grant_type", "client_id", clientID, "grant_type", grantType)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if err != nil {
		if errors.Is(err, errBadRequest) {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if errors.Is(err, errUnauthorized) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, errForbidden) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		slog.ErrorContext(ctx, "Token request failed", "client_id", clientID, "grant_type", grantType, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	server.RenderJSON(w, resp)
}

var (
	errBadRequest   = errors.New("bad request")
	errUnauthorized = errors.New("unauthorized")
	errForbidden    = errors.New("forbidden")
)

func (a *app) handleAuthorizationCodeGrant(ctx context.Context, clientID string, req *http.Request) (tokenResponse, error) {
	code := req.FormValue("code")
	codeVerifier := req.FormValue("code_verifier")
	if code == "" || codeVerifier == "" {
		slog.WarnContext(ctx, "Missing code or code_verifier", "client_id", clientID)
		return tokenResponse{}, errBadRequest
	}

	authData, err := a.authStore.Get(ctx, code)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to retrieve authorization data", "client_id", clientID, "code", code, "error", err)
		return tokenResponse{}, err
	}
	if authData == nil {
		slog.WarnContext(ctx, "Authorization code not found", "client_id", clientID, "code", code)
		return tokenResponse{}, errBadRequest
	}
	if authData.ClientID != clientID {
		slog.WarnContext(ctx, "Incorrect client id", "client_id", clientID, "authData.ClientID", authData.ClientID)
		return tokenResponse{}, errBadRequest
	}

	codeChallengeResult, err := a.computeCodeChallenge(ctx, authData.CodeChallengeMethod, codeVerifier)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to compute code challenge", "error", err)
		return tokenResponse{}, err
	}
	if codeChallengeResult != authData.CodeChallenge {
		slog.WarnContext(ctx, "Incorrect code challenge")
		return tokenResponse{}, errBadRequest
	}

	resp, err := a.issueTokens(ctx, clientID, authData.AccountID, authData.GrantedScopes)
	if err != nil {
		return tokenResponse{}, err
	}

	if err := a.authStore.Delete(ctx, code); err != nil {
		slog.ErrorContext(ctx, "Failed to delete authorization data", "client_id", clientID, "code", code, "error", err)
		return tokenResponse{}, err
	}

	return resp, nil
}

func (a *app) handleRefreshTokenGrant(ctx context.Context, clientID string, req *http.Request) (tokenResponse, error) {
	rawRefreshToken := req.FormValue("refresh_token")
	if rawRefreshToken == "" {
		slog.WarnContext(ctx, "Missing refresh token", "client_id", clientID)
		return tokenResponse{}, errBadRequest
	}

	tokenHash := hashToken(rawRefreshToken)
	storedRefreshData, err := a.refreshStore.Get(ctx, tokenHash)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to retrieve refresh token", "client_id", clientID, "error", err)
		return tokenResponse{}, err
	}
	if storedRefreshData == nil {
		slog.WarnContext(ctx, "Unknown refresh token", "client_id", clientID)
		return tokenResponse{}, errUnauthorized
	}

	if storedRefreshData.ClientID != clientID {
		slog.WarnContext(ctx, "Refresh token client mismatch", "client_id", clientID, "stored_client_id", storedRefreshData.ClientID)
		return tokenResponse{}, errBadRequest
	}
	if time.Now().After(storedRefreshData.ExpiresAt) {
		slog.WarnContext(ctx, "Refresh token expired", "client_id", clientID)
		return tokenResponse{}, errUnauthorized
	}

	resp, err := a.issueTokens(ctx, clientID, storedRefreshData.AccountID, storedRefreshData.GrantedScopes)
	if err != nil {
		return tokenResponse{}, err
	}

	if err := a.refreshStore.Delete(ctx, tokenHash); err != nil {
		slog.ErrorContext(ctx, "Failed to rotate refresh token (delete old)", "client_id", clientID, "error", err)
		return tokenResponse{}, err
	}

	return resp, nil
}

func (a *app) issueTokens(ctx context.Context, clientID, accountID string, grantedScopes []string) (tokenResponse, error) {
	acc, err := a.accountStore.GetById(ctx, accountID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to retrieve account", "account_id", accountID, "error", err)
		return tokenResponse{}, err
	}
	if acc == nil {
		slog.WarnContext(ctx, "Account not found", "account_id", accountID)
		return tokenResponse{}, errUnauthorized
	}
	if acc.Status != account.StatusActive {
		slog.WarnContext(ctx, "Account not active", "account_id", acc.ID, "status", acc.Status)
		return tokenResponse{}, errForbidden
	}

	client, err := a.getClient(ctx, clientID)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to retrieve client", "client_id", clientID, "error", err)
		return tokenResponse{}, err
	}
	if client == nil {
		slog.WarnContext(ctx, "Client not found", "client_id", clientID)
		return tokenResponse{}, errUnauthorized
	}

	accessToken, err := a.createSignedToken(ctx, client.DefaultResourceIndicator, acc)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create access token", "client_id", clientID, "error", err)
		return tokenResponse{}, err
	}

	idToken, err := a.createSignedToken(ctx, clientID, acc)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create ID token", "client_id", clientID, "error", err)
		return tokenResponse{}, err
	}

	resp := tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTokenTTL.Seconds()),
		IDToken:     idToken,
	}

	if slices.Contains(grantedScopes, "offline_access") {
		rawRefreshToken := rand.Text()
		tNow := time.Now()
		refreshData := refresh.Data{
			TokenHash:     hashToken(rawRefreshToken),
			ClientID:      clientID,
			AccountID:     acc.ID,
			GrantedScopes: grantedScopes,
			CreatedAt:     tNow,
			ExpiresAt:     tNow.Add(refreshTokenTTL),
		}
		if err := a.refreshStore.Put(ctx, refreshData); err != nil {
			slog.ErrorContext(ctx, "Failed to persist refresh token", "client_id", clientID, "error", err)
			return tokenResponse{}, err
		}
		resp.RefreshToken = rawRefreshToken
	}

	return resp, nil
}

func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (a *app) computeCodeChallenge(context context.Context, method string, generatedCode string) (string, error) {
	switch method {
	case "S256":
		hash := sha256.Sum256([]byte(generatedCode))
		return base64.RawURLEncoding.EncodeToString(hash[:]), nil
	}
	return "", fmt.Errorf("unsupported code challenge method '%s'", method)
}

type tokenResponse struct {
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
		"exp":            tNow.Add(accessTokenTTL).Unix(),
		"email":          account.Email,
		"email_verified": true,
		"name":           account.Name,
		"picture":        account.Picture,
		"roles":          account.Roles,
	})
	token.Header["kid"] = k.Marshal().KID

	signedToken, err := token.SignedString(k.Key())
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return signedToken, nil
}
