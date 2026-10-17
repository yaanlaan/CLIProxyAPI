package management

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// AdminJWTClaims represents the payload claims in a management JWT.
type AdminJWTClaims struct {
	Username string `json:"sub"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
}

// GenerateManagementJWT issues an HMAC-SHA256 signed JWT for an authenticated admin/operator.
func GenerateManagementJWT(username, role, secret string, duration time.Duration) (string, error) {
	if secret == "" {
		secret = "cpa-default-jwt-secret-key-change-me"
	}
	headerJSON := []byte(`{"alg":"HS256","typ":"JWT"}`)
	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)

	now := time.Now()
	claims := AdminJWTClaims{
		Username: username,
		Role:     role,
		Exp:      now.Add(duration).Unix(),
		Iat:      now.Unix(),
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerEnc + "." + payloadEnc
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigEnc, nil
}

// ValidateManagementJWT verifies the HMAC signature and expiration of a management JWT.
func ValidateManagementJWT(tokenStr, secret string) (*AdminJWTClaims, error) {
	if secret == "" {
		secret = "cpa-default-jwt-secret-key-change-me"
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt format: expected 3 parts")
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return nil, errors.New("signature verification failed")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}

	var claims AdminJWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, errors.New("invalid payload json")
	}

	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

func looksLikeBcrypt(s string) bool {
	return strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$")
}
