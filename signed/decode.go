package signed

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
)

var hmacSecret, _ = base64.StdEncoding.DecodeString(os.Getenv("HMAC_SECRET"))

func Decode(value string, data any) error {
	b, err := base64.URLEncoding.DecodeString(value)
	if err != nil || len(b) < sha256.Size {
		return errors.New("invalid format")
	}

	message := b[:len(b)-sha256.Size]
	sig := b[len(b)-sha256.Size:]

	mac := hmac.New(sha256.New, hmacSecret)
	mac.Write(message)
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(sig, expectedSig) {
		return errors.New("invalid signature")
	}

	return json.Unmarshal(message, data)
}

func ReadCookie(req *http.Request, name string, data any) error {
	cookie, err := req.Cookie("__Host-" + name)
	if err != nil {
		return err
	}

	if cookie.Value == "" {
		return errors.New("cookie value is empty")
	}

	return Decode(cookie.Value, data)
}
