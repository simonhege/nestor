package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/MicahParks/jwkset"
	"github.com/simonhege/nestor/privatekeys"
	"github.com/simonhege/server"
)

func (a *app) initKeys(ctx context.Context) error {

	keys, err := a.privateKeyStore.All()
	if err != nil {
		return fmt.Errorf("failed to get private keys: %w", err)
	}

	if len(keys) == 0 {
		slog.InfoContext(ctx, "No private keys found, generating a new RSA key")
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}
		k := privatekeys.PrivateKey{
			KID: rand.Text(),
			PrivateKey: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			}),
		}
		if err := a.privateKeyStore.Put(ctx, k); err != nil {
			return fmt.Errorf("failed to save RSA key: %w", err)
		}
		keys = append(keys, k)
	}

	// TODO automate key rotation with expiry date
	for _, k := range keys {
		slog.InfoContext(ctx, "Using JWK", "kid", k.KID)
		block, _ := pem.Decode(k.PrivateKey)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return fmt.Errorf("invalid PEM block")
		}
		// Parse key
		priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PEM block: %w", err)
		}

		jwk, err := jwkset.NewJWKFromKey(priv, jwkset.JWKOptions{
			Metadata: jwkset.JWKMetadataOptions{
				KID: k.KID,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to init JWK: %w", err)
		}
		if err = a.jwks.KeyWrite(ctx, jwk); err != nil {
			return fmt.Errorf("failed to store JWK: %w", err)
		}
	}
	return nil
}

func (a *app) handleKeys(w http.ResponseWriter, req *http.Request) {

	raw, err := a.jwks.JSONPublic(req.Context())
	if err != nil {
		slog.ErrorContext(req.Context(), "Failed to get JWKs", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	server.RenderJSON(w, raw)
}
