package management

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func TestManagementJWTGenerationAndValidation(t *testing.T) {
	secret := "test-jwt-secret-12345"
	token, err := GenerateManagementJWT("alice", "admin", secret, time.Hour)
	if err != nil {
		t.Fatalf("GenerateManagementJWT failed: %v", err)
	}

	claims, err := ValidateManagementJWT(token, secret)
	if err != nil {
		t.Fatalf("ValidateManagementJWT failed: %v", err)
	}

	if claims.Username != "alice" {
		t.Errorf("expected username alice, got %s", claims.Username)
	}
	if claims.Role != "admin" {
		t.Errorf("expected role admin, got %s", claims.Role)
	}

	// Test invalid secret
	_, err = ValidateManagementJWT(token, "wrong-secret")
	if err == nil {
		t.Errorf("expected error with wrong secret, got nil")
	}

	// Test expired token
	expiredToken, err := GenerateManagementJWT("alice", "admin", secret, -time.Hour)
	if err != nil {
		t.Fatalf("GenerateManagementJWT expired failed: %v", err)
	}
	_, err = ValidateManagementJWT(expiredToken, secret)
	if err == nil {
		t.Errorf("expected error for expired token, got nil")
	}
}

func TestManagementLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	passHash, _ := bcrypt.GenerateFromPassword([]byte("supersecret"), bcrypt.DefaultCost)

	cfg := &config.Config{
		RemoteManagement: config.RemoteManagement{
			AllowRemote: true,
			JWTSecret:   "test-secret",
			Users: []config.ManagementUser{
				{
					Username: "operator",
					Password: string(passHash),
					Role:     "admin",
				},
			},
		},
	}

	h := &Handler{
		cfg:            cfg,
		failedAttempts: make(map[string]*attemptInfo),
	}

	engine := gin.New()
	engine.POST("/v0/auth/login", h.Login)

	// Test 1: Successful login
	body, _ := json.Marshal(map[string]string{
		"username": "operator",
		"password": "supersecret",
	})
	req := httptest.NewRequest(http.MethodPost, "/v0/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d, body: %s", w.Code, w.Body.String())
	}

	var res map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	token, ok := res["token"].(string)
	if !ok || token == "" {
		t.Fatalf("expected token in response, got %v", res)
	}

	// Validate token with middleware
	allowed, status, _ := h.AuthenticateManagementKey("127.0.0.1", true, token)
	if !allowed || status != 0 {
		t.Fatalf("AuthenticateManagementKey failed for issued token: allowed=%v, status=%d", allowed, status)
	}

	// Test 2: Wrong password
	wrongBody, _ := json.Marshal(map[string]string{
		"username": "operator",
		"password": "wrongpassword",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/v0/auth/login", bytes.NewReader(wrongBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	engine.ServeHTTP(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for wrong password, got %d", w2.Code)
	}
}
