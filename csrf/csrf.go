package csrf

import (
	"crypto/rand"
	"net/http"
	"time"
)

func NewToken() string {
	return rand.Text()
}

func SetCookie(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",                     // Make accessible on all paths
		HttpOnly: true,                    // Not accessible via JavaScript
		Secure:   true,                    // Only sent over HTTPS
		SameSite: http.SameSiteStrictMode, // CSRF protection
		Expires:  time.Now().Add(15 * time.Minute),
	}
	http.SetCookie(w, cookie)
}

func ValidateToken(r *http.Request) bool {
	formToken := r.FormValue("csrf_token")
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return false
	}
	return formToken == cookie.Value
}
