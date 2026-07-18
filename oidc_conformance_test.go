package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/simonhege/nestor/account"
	"github.com/simonhege/nestor/auth"
	"github.com/simonhege/nestor/refresh"
	"github.com/simonhege/nestor/stores/memory"
)

const (
	testClientID          = "test-client"
	testRedirectURI       = "http://localhost:3000/callback"
	testResourceIndicator = "https://api.example.com"
)

// newTestServer creates an app wired with in-memory stores, a freshly generated RSA key,
// and a single test client, then starts an httptest.Server with all OIDC routes registered.
func newTestServer(t *testing.T) (*app, *httptest.Server) {
	t.Helper()

	ctx := context.Background()

	mux := http.NewServeMux()
	ts := httptest.NewUnstartedServer(mux)
	ts.Start()
	t.Cleanup(ts.Close)

	// Generate a 2048-bit RSA key (smaller than production 4096 for test speed).
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	jwk, err := jwkset.NewJWKFromKey(privateKey, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{KID: "test-key-1"},
	})
	if err != nil {
		t.Fatalf("create JWK: %v", err)
	}

	storage := jwkset.NewMemoryStorage()
	if err := storage.KeyWrite(ctx, jwk); err != nil {
		t.Fatalf("write JWK to storage: %v", err)
	}

	a := &app{
		baseURL:    ts.URL,
		jwks:       storage,
		oidcConfig: newOpenIDConfiguration(ts.URL, ts.URL),
		clients: map[string]client{
			testClientID: {
				ClientID:                 testClientID,
				RedirectURIs:             []string{testRedirectURI},
				DefaultResourceIndicator: testResourceIndicator,
			},
		},
		accountStore:    &memory.AccountStore{Data: make(map[string]account.Account)},
		authStore:       &memory.AuthStore{Data: make(map[string]auth.AuthData)},
		refreshStore:    &memory.RefreshStore{Data: make(map[string]refresh.Data)},
		privateKeyStore: &memory.PrivateKeyStore{},
	}

	mux.HandleFunc("GET /.well-known/openid-configuration", a.handleOpenIDConfiguration)
	mux.HandleFunc("GET /.well-known/jwks.json", a.handleKeys)
	mux.HandleFunc("GET /authorize", a.handleAuthorize)
	mux.HandleFunc("POST /authorize", a.handlePostAuthorize)
	mux.HandleFunc("POST /token", a.handleToken)

	return a, ts
}

// insertTestAccount creates an active account in the store and returns it.
func insertTestAccount(t *testing.T, a *app) *account.Account {
	t.Helper()
	acc := account.Account{
		ID:        "test-account-id",
		Email:     "test@example.com",
		Name:      "Test User",
		Status:    account.StatusActive,
		Roles:     []string{"user"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := a.accountStore.Put(context.Background(), acc); err != nil {
		t.Fatalf("insert test account: %v", err)
	}
	return &acc
}

// insertAuthCode pre-populates the auth store with an authorization code using S256 PKCE.
func insertAuthCode(t *testing.T, a *app, code, clientID, accountID, codeChallenge string, scopes []string) {
	t.Helper()
	data := auth.AuthData{
		ClientID:            clientID,
		Code:                code,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		GrantedScopes:       scopes,
		AccountID:           accountID,
	}
	if err := a.authStore.Put(context.Background(), data); err != nil {
		t.Fatalf("insert auth code: %v", err)
	}
}

// generatePKCE produces a random S256 PKCE verifier / challenge pair.
func generatePKCE(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate PKCE verifier: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

// doTokenExchange performs a token endpoint call using the authorization_code grant and returns the decoded response.
func doTokenExchange(t *testing.T, baseURL, clientID, code, codeVerifier string) tokenResponse {
	t.Helper()
	resp, err := http.PostForm(baseURL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"code_verifier": {codeVerifier},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return tr
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// TestDiscovery validates that the OpenID Connect Discovery document contains
// all fields required by the OIDC Core spec (Section 3 / RFC 8414).
func TestDiscovery(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET openid-configuration: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var cfg struct {
		Issuer                           string   `json:"issuer"`
		AuthorizationEndpoint            string   `json:"authorization_endpoint"`
		TokenEndpoint                    string   `json:"token_endpoint"`
		JwksURI                          string   `json:"jwks_uri"`
		ResponseTypesSupported           []string `json:"response_types_supported"`
		SubjectTypesSupported            []string `json:"subject_types_supported"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode discovery document: %v", err)
	}

	if cfg.Issuer != ts.URL {
		t.Errorf("issuer: got %q, want %q", cfg.Issuer, ts.URL)
	}
	if cfg.AuthorizationEndpoint == "" {
		t.Error("authorization_endpoint is missing")
	}
	if cfg.TokenEndpoint == "" {
		t.Error("token_endpoint is missing")
	}
	if cfg.JwksURI == "" {
		t.Error("jwks_uri is missing")
	}
	if len(cfg.ResponseTypesSupported) == 0 {
		t.Error("response_types_supported is empty")
	}
	if len(cfg.SubjectTypesSupported) == 0 {
		t.Error("subject_types_supported is empty")
	}
	if len(cfg.IDTokenSigningAlgValuesSupported) == 0 {
		t.Error("id_token_signing_alg_values_supported is empty")
	}
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

// TestJWKS validates that the JWKS endpoint returns a well-formed RSA key set.
func TestJWKS(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks.json: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			KTY string `json:"kty"`
			KID string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}

	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS contains no keys")
	}
	key := jwks.Keys[0]
	if key.KTY != "RSA" {
		t.Errorf("kty: got %q, want RSA", key.KTY)
	}
	if key.KID == "" {
		t.Error("kid is missing")
	}
	if key.N == "" {
		t.Error("n (modulus) is missing")
	}
	if key.E == "" {
		t.Error("e (exponent) is missing")
	}
}

// ---------------------------------------------------------------------------
// Authorize endpoint – error handling
// ---------------------------------------------------------------------------

func TestAuthorize_InvalidResponseType(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/authorize?response_type=token&client_id=" + testClientID + "&redirect_uri=" + url.QueryEscape(testRedirectURI))
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAuthorize_UnknownClient(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/authorize?response_type=code&client_id=unknown-client&redirect_uri=" + url.QueryEscape(testRedirectURI))
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAuthorize_InvalidRedirectURI(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.Get(ts.URL + "/authorize?response_type=code&client_id=" + testClientID + "&redirect_uri=" + url.QueryEscape("https://evil.example.com/callback"))
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Token endpoint – grant type
// ---------------------------------------------------------------------------

func TestToken_UnsupportedGrantType(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type": {"implicit"},
		"client_id":  {testClientID},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Token endpoint – authorization_code grant
// ---------------------------------------------------------------------------

func TestToken_AuthCode_HappyPath(t *testing.T) {
	a, ts := newTestServer(t)
	acc := insertTestAccount(t, a)
	verifier, challenge := generatePKCE(t)
	code := "authcode-happy"
	insertAuthCode(t, a, code, testClientID, acc.ID, challenge, []string{"openid", "email"})

	tr := doTokenExchange(t, ts.URL, testClientID, code, verifier)

	if tr.AccessToken == "" {
		t.Error("access_token is missing")
	}
	if tr.TokenType != "Bearer" {
		t.Errorf("token_type: got %q, want Bearer", tr.TokenType)
	}
	if tr.ExpiresIn <= 0 {
		t.Errorf("expires_in: got %d, want > 0", tr.ExpiresIn)
	}
	if tr.IDToken == "" {
		t.Error("id_token is missing")
	}
	if tr.RefreshToken != "" {
		t.Error("refresh_token must be absent when offline_access scope was not requested")
	}
}

func TestToken_AuthCode_WithOfflineAccess(t *testing.T) {
	a, ts := newTestServer(t)
	acc := insertTestAccount(t, a)
	verifier, challenge := generatePKCE(t)
	code := "authcode-offline"
	insertAuthCode(t, a, code, testClientID, acc.ID, challenge, []string{"openid", "offline_access"})

	tr := doTokenExchange(t, ts.URL, testClientID, code, verifier)

	if tr.RefreshToken == "" {
		t.Error("refresh_token is missing when offline_access scope was requested")
	}
}

func TestToken_AuthCode_WrongVerifier(t *testing.T) {
	a, ts := newTestServer(t)
	acc := insertTestAccount(t, a)
	_, challenge := generatePKCE(t)
	code := "authcode-wrong-verifier"
	insertAuthCode(t, a, code, testClientID, acc.ID, challenge, []string{"openid"})

	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {testClientID},
		"code":          {code},
		"code_verifier": {"this-is-the-wrong-verifier"},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestToken_AuthCode_UnknownCode(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {testClientID},
		"code":          {"code-that-does-not-exist"},
		"code_verifier": {"some-verifier"},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestToken_AuthCode_ClientMismatch(t *testing.T) {
	a, ts := newTestServer(t)
	acc := insertTestAccount(t, a)
	verifier, challenge := generatePKCE(t)
	code := "authcode-client-mismatch"
	insertAuthCode(t, a, code, testClientID, acc.ID, challenge, []string{"openid"})

	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"a-completely-different-client"},
		"code":          {code},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestToken_AuthCode_InactiveAccount(t *testing.T) {
	a, ts := newTestServer(t)

	suspended := account.Account{
		ID:     "suspended-account-id",
		Email:  "suspended@example.com",
		Status: account.StatusSuspended,
	}
	if err := a.accountStore.Put(context.Background(), suspended); err != nil {
		t.Fatalf("insert suspended account: %v", err)
	}

	verifier, challenge := generatePKCE(t)
	code := "authcode-inactive"
	insertAuthCode(t, a, code, testClientID, suspended.ID, challenge, []string{"openid"})

	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {testClientID},
		"code":          {code},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for suspended account, got %d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// ID token claims and signature
// ---------------------------------------------------------------------------

// TestToken_IDTokenClaims validates that the issued ID token contains all claims
// required by OIDC Core Section 2 (iss, sub, aud, exp, iat, auth_time, nbf)
// plus the profile claims emitted by this server.
func TestToken_IDTokenClaims(t *testing.T) {
	a, ts := newTestServer(t)
	acc := insertTestAccount(t, a)
	verifier, challenge := generatePKCE(t)
	code := "authcode-id-claims"
	insertAuthCode(t, a, code, testClientID, acc.ID, challenge, []string{"openid", "email"})

	tr := doTokenExchange(t, ts.URL, testClientID, code, verifier)

	// Parse without signature verification to inspect claims.
	parser := jwt.NewParser()
	var claims jwt.MapClaims
	_, _, err := parser.ParseUnverified(tr.IDToken, &claims)
	if err != nil {
		t.Fatalf("ParseUnverified ID token: %v", err)
	}

	required := []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nbf", "email", "email_verified"}
	for _, claim := range required {
		if _, ok := claims[claim]; !ok {
			t.Errorf("ID token missing required claim %q", claim)
		}
	}

	if iss, _ := claims["iss"].(string); iss != ts.URL {
		t.Errorf("iss: got %q, want %q", iss, ts.URL)
	}
	if sub, _ := claims["sub"].(string); sub != acc.ID {
		t.Errorf("sub: got %q, want %q", sub, acc.ID)
	}
	if aud, _ := claims["aud"].(string); aud != testClientID {
		t.Errorf("aud: got %q, want %q", aud, testClientID)
	}
	if email, _ := claims["email"].(string); email != acc.Email {
		t.Errorf("email: got %q, want %q", email, acc.Email)
	}
}

// TestToken_IDTokenSignature verifies that the ID token is cryptographically
// signed with the RSA key advertised in the server's JWKS endpoint.
func TestToken_IDTokenSignature(t *testing.T) {
	a, ts := newTestServer(t)
	acc := insertTestAccount(t, a)
	verifier, challenge := generatePKCE(t)
	code := "authcode-signature"
	insertAuthCode(t, a, code, testClientID, acc.ID, challenge, []string{"openid"})

	tr := doTokenExchange(t, ts.URL, testClientID, code, verifier)

	// Fetch the public key from the JWKS endpoint.
	jwksResp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks.json: %v", err)
	}
	defer jwksResp.Body.Close()

	var jwksBody struct {
		Keys []struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwksBody); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(jwksBody.Keys) == 0 {
		t.Fatal("JWKS contains no keys")
	}

	// Extract the RSA public key with the kid that the ID token references.
	parser := jwt.NewParser()
	var headerOnly jwt.MapClaims
	unverified, _, _ := parser.ParseUnverified(tr.IDToken, &headerOnly)
	targetKID, _ := unverified.Header["kid"].(string)

	var pubKey *rsa.PublicKey
	for _, k := range jwksBody.Keys {
		if k.KID != targetKID {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			t.Fatalf("decode RSA modulus: %v", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			t.Fatalf("decode RSA exponent: %v", err)
		}
		pubKey = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
		break
	}
	if pubKey == nil {
		t.Fatalf("no JWKS key found for kid %q", targetKID)
	}

	// Verify the signature.
	parsed, err := jwt.Parse(tr.IDToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("ID token signature verification failed: %v", err)
	}
	if !parsed.Valid {
		t.Error("ID token is not valid after signature verification")
	}
}

// ---------------------------------------------------------------------------
// Token endpoint – refresh_token grant
// ---------------------------------------------------------------------------

func TestToken_Refresh_HappyPath(t *testing.T) {
	a, ts := newTestServer(t)
	acc := insertTestAccount(t, a)

	rawToken := "raw-refresh-token-happy"
	tokenHash := hashToken(rawToken)
	if err := a.refreshStore.Put(context.Background(), refresh.Data{
		TokenHash:     tokenHash,
		ClientID:      testClientID,
		AccountID:     acc.ID,
		GrantedScopes: []string{"openid", "offline_access"},
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("insert refresh token: %v", err)
	}

	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {testClientID},
		"refresh_token": {rawToken},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	if tr.AccessToken == "" {
		t.Error("access_token is missing")
	}
	if tr.RefreshToken == "" {
		t.Error("new refresh_token is missing (offline_access scope was granted)")
	}
	if tr.RefreshToken == rawToken {
		t.Error("refresh token was not rotated (old value returned)")
	}

	// Old token must be deleted (rotation).
	stored, err := a.refreshStore.Get(context.Background(), tokenHash)
	if err != nil {
		t.Fatalf("lookup old refresh token hash: %v", err)
	}
	if stored != nil {
		t.Error("old refresh token was not deleted after rotation")
	}
}

func TestToken_Refresh_Unknown(t *testing.T) {
	_, ts := newTestServer(t)

	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {testClientID},
		"refresh_token": {"this-token-was-never-issued"},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestToken_Refresh_Expired(t *testing.T) {
	a, ts := newTestServer(t)
	acc := insertTestAccount(t, a)

	rawToken := "raw-refresh-token-expired"
	tokenHash := hashToken(rawToken)
	if err := a.refreshStore.Put(context.Background(), refresh.Data{
		TokenHash:     tokenHash,
		ClientID:      testClientID,
		AccountID:     acc.ID,
		GrantedScopes: []string{"openid", "offline_access"},
		CreatedAt:     time.Now().Add(-60 * 24 * time.Hour),
		ExpiresAt:     time.Now().Add(-1 * time.Hour), // already expired
	}); err != nil {
		t.Fatalf("insert expired refresh token: %v", err)
	}

	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {testClientID},
		"refresh_token": {rawToken},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}
