package main

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/MicahParks/jwkset"
	"github.com/joho/godotenv"
	"github.com/simonhege/nestor/account"
	"github.com/simonhege/nestor/auth"
	"github.com/simonhege/nestor/connector"
	"github.com/simonhege/nestor/privatekeys"
	"github.com/simonhege/nestor/refresh"
	"github.com/simonhege/nestor/stores/couchbase"
	"github.com/simonhege/nestor/stores/memory"
	"github.com/simonhege/server"
)

func main() {
	ctx := context.Background()

	slog.SetDefault(slog.New(server.Wrap(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelInfo,
	}))))

	if err := godotenv.Load(); err != nil {
		slog.InfoContext(ctx, "no .env file loaded", "err", err)
	}

	var accountStore account.Store
	var authStore auth.Store
	var refreshStore refresh.Store
	var privateKeyStore privatekeys.Store
	if os.Getenv("COUCHBASE_CONNECTION_STRING") != "" {
		scope, closeFunc, err := couchbase.Connect()
		if err != nil {
			slog.ErrorContext(ctx, "failed to connect to Couchbase", "error", err)
			return
		}
		defer func() {
			if err := closeFunc(); err != nil {
				slog.ErrorContext(ctx, "failed to close Couchbase connection", "error", err)
			}
		}()

		accountStore, err = couchbase.NewAccountStore(scope)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create Couchbase account store", "error", err)
			return
		}
		authStore, err = couchbase.NewAuthStore(scope)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create Couchbase auth store", "error", err)
			return
		}

		refreshStore, err = couchbase.NewRefreshStore(scope)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create Couchbase refresh store", "error", err)
			return
		}

		privateKeyStore, err = couchbase.NewPrivateKeyStore(scope)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create Couchbase private key store", "error", err)
			return
		}

	} else {
		slog.WarnContext(ctx, "Using an in-memory account store, all data will be lost on restart")
		accountStore = &memory.AccountStore{
			Data: make(map[string]account.Account),
		}
		authStore = &memory.AuthStore{
			Data: make(map[string]auth.AuthData),
		}
		refreshStore = &memory.RefreshStore{
			Data: make(map[string]refresh.Data),
		}
		privateKeyStore = &memory.PrivateKeyStore{}
	}

	baseURL := cmp.Or(os.Getenv("BASE_URL"), "http://localhost:9021")
	a := &app{
		baseURL:         baseURL,
		jwks:            jwkset.NewMemoryStorage(),
		oidcConfig:      newOpenIDConfiguration(os.Getenv("ISSUER"), baseURL),
		clients:         make(map[string]client),
		accountStore:    accountStore,
		authStore:       authStore,
		refreshStore:    refreshStore,
		privateKeyStore: privateKeyStore,
	}
	a.initConnectors()
	a.initClients(ctx)
	if err := a.initKeys(ctx); err != nil {
		slog.ErrorContext(ctx, "failed to initialize keys", "error", err)
		return
	}

	s := server.New(2, 10, true)
	// Standard OIDC endpoints
	s.HandleFunc("GET /.well-known/openid-configuration", a.handleOpenIDConfiguration)
	s.HandleFunc("GET /.well-known/jwks.json", a.handleKeys)
	s.HandleFunc("GET /authorize", a.handleAuthorize)
	s.HandleFunc("POST /authorize", a.handlePostAuthorize)
	s.HandleFunc("POST /token", a.handleToken)

	// Accounts management endpoints
	s.HandleFunc("DELETE /accounts/me", a.handleDeleteMyAccount)

	// Connectors endpoints
	s.HandleFunc("GET /{connector}/login", a.handleLogin)
	s.HandleFunc("GET /{connector}/callback", a.handleCallback)

	port := cmp.Or(os.Getenv("PORT"), "9021")
	address := ":" + port

	if err := s.Run(ctx, address); err != nil {
		slog.ErrorContext(ctx, "Server error", "error", err)
	}
}

func getenvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func (a *app) initConnectors() {
	a.connectors = connector.ReadConfig()
}

func (a *app) getConnector(connectorID string) *connector.C {
	for _, connector := range a.connectors {
		if connector.ID == connectorID {
			return &connector
		}
	}
	return nil
}

func (a *app) initClients(ctx context.Context) {
	// Legacy configuration for a single client, kept for backward compatibility
	clientID := os.Getenv("NESTOR_CLIENT_ID")
	if len(clientID) > 0 {
		a.clients = map[string]client{
			clientID: {
				ClientID:                 clientID,
				RedirectURIs:             strings.Split(os.Getenv("NESTOR_REDIRECT_URIS"), ","),
				DefaultResourceIndicator: os.Getenv("NESTOR_DEFAULT_RESOURCE_INDICATOR"),
				LoginPage: loginPage{
					Title:       getenvOrDefault("NESTOR_LABELS_LOGIN_TITLE", "Se connecter à "+clientID),
					Email:       getenvOrDefault("NESTOR_LABELS_LOGIN_EMAIL", "Email"),
					Password:    getenvOrDefault("NESTOR_LABELS_LOGIN_PASSWORD", "Mot de passe"),
					Submit:      getenvOrDefault("NESTOR_LABELS_LOGIN_SUBMIT", "Se connecter"),
					ConnectWith: getenvOrDefault("NESTOR_LABELS_LOGIN_CONNECT_WITH", "Se connecter avec"),
				},
			},
		}
	}
	// New configuration for multiple clients, using suffixes for environment variables
	clientIDs := strings.Split(os.Getenv("NESTOR_CLIENT_IDS"), ",")
	for i, clientID := range clientIDs {
		suffix := fmt.Sprintf("_%d", i)
		a.clients[clientID] = client{
			ClientID:                 clientID,
			RedirectURIs:             strings.Split(getEnv("NESTOR_REDIRECT_URIS", suffix, ""), ","),
			DefaultResourceIndicator: getEnv("NESTOR_DEFAULT_RESOURCE_INDICATOR", suffix, ""),
			LoginPage: loginPage{
				Title:       getEnv("NESTOR_LABELS_LOGIN_TITLE", suffix, "Se connecter à "+clientID),
				Email:       getEnv("NESTOR_LABELS_LOGIN_EMAIL", suffix, "Email"),
				Password:    getEnv("NESTOR_LABELS_LOGIN_PASSWORD", suffix, "Mot de passe"),
				Submit:      getEnv("NESTOR_LABELS_LOGIN_SUBMIT", suffix, "Se connecter"),
				ConnectWith: getEnv("NESTOR_LABELS_LOGIN_CONNECT_WITH", suffix, "Se connecter avec"),
			},
		}
	}

	for clientID, client := range a.clients {
		slog.InfoContext(ctx, "Client registered", "clientId", clientID, "redirectURIs", client.RedirectURIs, "defaultResourceIndicator", client.DefaultResourceIndicator)
	}
}

func getEnv(key, suffix, defaultValue string) string {
	value := os.Getenv(key + suffix)
	if value == "" {
		value = os.Getenv(key)
	}
	if value == "" {
		return defaultValue
	}
	return value
}
