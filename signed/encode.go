package signed

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

func Encode(data any) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write(jsonData)
	signature := mac.Sum(nil)

	payload := append(jsonData, signature...)
	return base64.URLEncoding.EncodeToString(payload), nil
}

func SetCookie(ctx context.Context, w http.ResponseWriter, name string, data any) {
	encodedParams, err := Encode(data)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to encode cookie", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:     "__Host-" + name,
		Value:    encodedParams,
		Path:     "/",                     // Make accessible on all paths
		HttpOnly: true,                    // Not accessible via JavaScript
		Secure:   true,                    // Only sent over HTTPS
		SameSite: http.SameSiteStrictMode, // CSRF protection
		Expires:  time.Now().Add(15 * time.Minute),
	}
	http.SetCookie(w, cookie)
}

func DeleteCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:     "__Host-" + name,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0), // Set expiration to the past
		MaxAge:   -1,              // Also set MaxAge to -1 to delete
	}
	http.SetCookie(w, cookie)
}

func SetCrossSiteCookie(ctx context.Context, w http.ResponseWriter, name string, data any) {
	encodedParams, err := Encode(data)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to encode cookie", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:     "__Host-" + name,
		Value:    encodedParams,
		Path:     "/",                  // Make accessible on all paths
		HttpOnly: true,                 // Not accessible via JavaScript
		Secure:   true,                 // Only sent over HTTPS
		SameSite: http.SameSiteLaxMode, // No CSRF protection
		Expires:  time.Now().Add(15 * time.Minute),
	}
	http.SetCookie(w, cookie)
}

func DeleteCrossSiteCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:     "__Host-" + name,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0), // Set expiration to the past
		MaxAge:   -1,              // Also set MaxAge to -1 to delete
	}
	http.SetCookie(w, cookie)
}
