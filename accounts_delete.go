package main

import (
	"context"
	"log/slog"
	"net/http"
)

func (a *app) handleDeleteMyAccount(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Decode JWT
	token, err := a.getTokenFromRequest(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Handle account deletion logic here
	sub, err := token.Claims.GetSubject()
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := a.accountStore.Delete(ctx, sub); err != nil {
		http.Error(w, "Failed to delete account", http.StatusInternalServerError)
		return
	}

	slog.InfoContext(ctx, "Account deleted successfully", "account_id", sub)

	// Account deleted successfully
	w.WriteHeader(http.StatusNoContent)
}
