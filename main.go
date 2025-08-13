package main

import (
	"cmp"
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/MicahParks/jwkset"
	"github.com/joho/godotenv"
	"github.com/simonhege/nestor/account"
	"github.com/simonhege/nestor/connector"
	"github.com/simonhege/nestor/privatekeys"
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
	var privateKeyStore privatekeys.Store
	if os.Getenv("COUCHBASE_CONNECTION_STRING") != "" {
		scope, closeFunc, err := couchbase.Connect()
		if err != nil {
			slog.ErrorContext(ctx, "failed to connect to Couchbase", "error", err)
			return
		}
		defer closeFunc()

		accountStore, err = couchbase.NewAccountStore(scope)
		if err != nil {
			slog.ErrorContext(ctx, "failed to create Couchbase account store", "error", err)
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
		privateKeyStore = &memory.PrivateKeyStore{}
	}

	baseURL := cmp.Or(os.Getenv("BASE_URL"), "http://localhost:9021")
	a := &app{
		baseURL:         baseURL,
		jwks:            jwkset.NewMemoryStorage(),
		oidcConfig:      NewOpenIDConfiguration(os.Getenv("ISSUER"), baseURL),
		clients:         make(map[string]Client),
		accountStore:    accountStore,
		privateKeyStore: privateKeyStore,
	}
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

	// Connectors endpoints
	s.HandleFunc("GET /{connector}/login", a.handleLogin)
	s.HandleFunc("GET /{connector}/callback", a.handleCallback)

	port := cmp.Or(os.Getenv("PORT"), "9021")
	address := ":" + port

	if err := s.Run(ctx, address); err != nil {
		slog.ErrorContext(ctx, "Server error", "error", err)
	}
}

func GetenvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func (a *app) initClients(ctx context.Context) {
	// TODO: allow multiple clients
	clientId := os.Getenv("NESTOR_CLIENT_ID")
	a.clients = map[string]Client{
		clientId: {
			ClientID:                 clientId,
			RedirectURIs:             strings.Split(os.Getenv("NESTOR_REDIRECT_URIS"), ","),
			DefaultResourceIndicator: os.Getenv("NESTOR_DEFAULT_RESOURCE_INDICATOR"),
			Connectors:               connector.ReadConfig(),
			LoginPage: LoginPage{
				Title:       GetenvOrDefault("NESTOR_LABELS_LOGIN_TITLE", "Se connecter à "+clientId),
				Email:       GetenvOrDefault("NESTOR_LABELS_LOGIN_EMAIL", "Email"),
				Password:    GetenvOrDefault("NESTOR_LABELS_LOGIN_PASSWORD", "Mot de passe"),
				Submit:      GetenvOrDefault("NESTOR_LABELS_LOGIN_SUBMIT", "Se connecter"),
				ConnectWith: GetenvOrDefault("NESTOR_LABELS_LOGIN_CONNECT_WITH", "Se connecter avec"),
			},
		},
	}
}
