package management

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// LoginRequest defines credentials for logging in to the management dashboard.
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login authenticates a user and returns an HMAC-SHA256 JWT.
func (h *Handler) Login(c *gin.Context) {
	clientIP := c.ClientIP()
	localClient := clientIP == "127.0.0.1" || clientIP == "::1"

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名和密码为必填项"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)

	// Rate limiting / IP ban check
	h.attemptsMu.Lock()
	ai := h.failedAttempts[clientIP]
	if ai != nil && !ai.blockedUntil.IsZero() {
		if time.Now().Before(ai.blockedUntil) {
			remaining := ai.blockedUntil.Sub(time.Now()).Round(time.Second)
			h.attemptsMu.Unlock()
			c.JSON(http.StatusForbidden, gin.H{
				"error": fmt.Sprintf("尝试失败次数过多，IP已被封禁。请在 %s 后重试", remaining),
			})
			return
		}
		ai.blockedUntil = time.Time{}
		ai.count = 0
	}
	h.attemptsMu.Unlock()

	fail := func() {
		h.attemptsMu.Lock()
		aip := h.failedAttempts[clientIP]
		if aip == nil {
			aip = &attemptInfo{}
			h.failedAttempts[clientIP] = aip
		}
		aip.count++
		aip.lastActivity = time.Now()
		if aip.count >= 5 {
			aip.blockedUntil = time.Now().Add(30 * time.Minute)
			aip.count = 0
		}
		h.attemptsMu.Unlock()
	}

	reset := func() {
		h.attemptsMu.Lock()
		if ai := h.failedAttempts[clientIP]; ai != nil {
			ai.count = 0
			ai.blockedUntil = time.Time{}
		}
		h.attemptsMu.Unlock()
	}

	cfg := h.cfg
	if cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "系统配置未就绪"})
		return
	}

	if !localClient && !cfg.RemoteManagement.AllowRemote && !h.allowRemoteOverride {
		c.JSON(http.StatusForbidden, gin.H{"error": "远程管理未开启 (remote management disabled)"})
		return
	}

	authenticated := false
	matchedRole := "admin"

	// 1. Check in configured users
	if len(cfg.RemoteManagement.Users) > 0 {
		for _, u := range cfg.RemoteManagement.Users {
			if u.Username == req.Username {
				if looksLikeBcrypt(u.Password) {
					if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(req.Password)) == nil {
						authenticated = true
						matchedRole = u.Role
						if matchedRole == "" {
							matchedRole = "admin"
						}
						break
					}
				} else {
					if subtle.ConstantTimeCompare([]byte(u.Password), []byte(req.Password)) == 1 {
						authenticated = true
						matchedRole = u.Role
						if matchedRole == "" {
							matchedRole = "admin"
						}
						break
					}
				}
			}
		}
	} else {
		// 2. Backward compatibility fallback: if no users defined, allow "admin" with secret-key
		secretHash := cfg.RemoteManagement.SecretKey
		envSecret := h.envSecret
		if req.Username == "admin" {
			if envSecret != "" && subtle.ConstantTimeCompare([]byte(req.Password), []byte(envSecret)) == 1 {
				authenticated = true
			} else if secretHash != "" {
				if looksLikeBcrypt(secretHash) {
					if bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(req.Password)) == nil {
						authenticated = true
					}
				} else if subtle.ConstantTimeCompare([]byte(secretHash), []byte(req.Password)) == 1 {
					authenticated = true
				}
			}
		}
	}

	if !authenticated {
		fail()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// Login succeeded!
	reset()
	jwtSecret := cfg.RemoteManagement.JWTSecret
	if jwtSecret == "" {
		jwtSecret = "cpa-default-jwt-secret-key-change-me"
	}
	token, err := GenerateManagementJWT(req.Username, matchedRole, jwtSecret, 7*24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成登录凭据失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"token":  token,
		"user": gin.H{
			"username": req.Username,
			"role":     matchedRole,
		},
		"expires_in": 7 * 24 * 3600,
	})
}

// GetCurrentUser returns the profile of the currently logged-in administrator.
func (h *Handler) GetCurrentUser(c *gin.Context) {
	username, _ := c.Get("mgmt_user")
	role, _ := c.Get("mgmt_role")
	c.JSON(http.StatusOK, gin.H{
		"username": username,
		"role":     role,
	})
}

// UpdateAccountRequest defines parameters for updating username and/or password.
type UpdateAccountRequest struct {
	NewUsername string `json:"new_username"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// UpdateAccount allows modifying the current administrator username and/or password.
func (h *Handler) UpdateAccount(c *gin.Context) {
	usernameVal, _ := c.Get("mgmt_user")
	currentUsername, _ := usernameVal.(string)
	if currentUsername == "" {
		currentUsername = "admin"
	}

	roleVal, _ := c.Get("mgmt_role")
	currentRole, _ := roleVal.(string)
	if currentRole == "" {
		currentRole = "admin"
	}

	var req UpdateAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数格式错误"})
		return
	}

	newUsername := strings.TrimSpace(req.NewUsername)
	oldPassword := strings.TrimSpace(req.OldPassword)
	newPassword := strings.TrimSpace(req.NewPassword)

	usernameChanging := newUsername != "" && newUsername != currentUsername
	passwordChanging := newPassword != ""

	if !usernameChanging && !passwordChanging {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": "信息无变化",
			"user": gin.H{
				"username": currentUsername,
				"role":     currentRole,
			},
		})
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	cfg := h.cfg
	if cfg == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "系统配置未就绪"})
		return
	}

	// 1. Check new username if changing
	if usernameChanging {
		if len(newUsername) < 3 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "新用户名长度至少需要 3 个字符"})
			return
		}
		for _, u := range cfg.RemoteManagement.Users {
			if u.Username == newUsername && u.Username != currentUsername {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("用户名 '%s' 已存在，请更换其他用户名", newUsername)})
				return
			}
		}
	}

	// 2. Check and hash new password if changing
	var newPasswordHash string
	if passwordChanging {
		if len(newPassword) < 4 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "新密码长度至少需要 4 位"})
			return
		}

		var currentStoredPassword string
		found := false
		for _, u := range cfg.RemoteManagement.Users {
			if u.Username == currentUsername {
				currentStoredPassword = u.Password
				found = true
				break
			}
		}
		if !found {
			currentStoredPassword = cfg.RemoteManagement.SecretKey
		}

		if currentStoredPassword != "" {
			if oldPassword == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "修改密码时必须输入当前原密码验证身份"})
				return
			}
			matched := false
			if looksLikeBcrypt(currentStoredPassword) {
				matched = (bcrypt.CompareHashAndPassword([]byte(currentStoredPassword), []byte(oldPassword)) == nil)
			} else {
				matched = (subtle.ConstantTimeCompare([]byte(currentStoredPassword), []byte(oldPassword)) == 1)
			}
			if !matched {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "当前原密码输入错误，身份验证失败"})
				return
			}
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "新密码加密处理失败"})
			return
		}
		newPasswordHash = string(hashed)
	}

	// 3. Apply updates
	targetUsername := currentUsername
	if usernameChanging {
		targetUsername = newUsername
	}

	targetRole := currentRole
	userFound := false
	for i := range cfg.RemoteManagement.Users {
		if cfg.RemoteManagement.Users[i].Username == currentUsername {
			if usernameChanging {
				cfg.RemoteManagement.Users[i].Username = targetUsername
			}
			if passwordChanging {
				cfg.RemoteManagement.Users[i].Password = newPasswordHash
			}
			if cfg.RemoteManagement.Users[i].Role != "" {
				targetRole = cfg.RemoteManagement.Users[i].Role
			}
			userFound = true
			break
		}
	}

	if !userFound {
		storedPass := cfg.RemoteManagement.SecretKey
		if passwordChanging {
			storedPass = newPasswordHash
		}
		cfg.RemoteManagement.Users = append(cfg.RemoteManagement.Users, config.ManagementUser{
			Username: targetUsername,
			Password: storedPass,
			Role:     targetRole,
		})
	}

	if passwordChanging && (currentUsername == "admin" || targetUsername == "admin") {
		cfg.RemoteManagement.SecretKey = newPasswordHash
	}

	// 4. Persist to config.yaml
	if err := config.SaveConfigPreserveComments(h.configFilePath, cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存配置文件失败: " + err.Error()})
		return
	}

	// 5. Generate fresh JWT token for the updated username
	jwtSecret := cfg.RemoteManagement.JWTSecret
	if jwtSecret == "" {
		jwtSecret = "cpa-default-jwt-secret-key-change-me"
	}
	newToken, err := GenerateManagementJWT(targetUsername, targetRole, jwtSecret, 7*24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "签发新会话凭据失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "账户信息修改成功",
		"token":   newToken,
		"user": gin.H{
			"username": targetUsername,
			"role":     targetRole,
		},
	})
}

// ChangePassword delegates to UpdateAccount for backward compatibility.
func (h *Handler) ChangePassword(c *gin.Context) {
	h.UpdateAccount(c)
}

// GetUsers returns the list of configured users without their passwords.
func (h *Handler) GetUsers(c *gin.Context) {
	cfg := h.cfg
	if cfg == nil {
		c.JSON(http.StatusOK, []gin.H{})
		return
	}

	type UserSummary struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	var res []UserSummary
	for _, u := range cfg.RemoteManagement.Users {
		res = append(res, UserSummary{
			Username: u.Username,
			Role:     u.Role,
		})
	}
	if len(res) == 0 {
		res = append(res, UserSummary{
			Username: "admin",
			Role:     "admin",
		})
	}
	c.JSON(http.StatusOK, res)
}

// GetAuthInfo returns public authentication metadata such as the primary administrator username.
func (h *Handler) GetAuthInfo(c *gin.Context) {
	cfg := h.cfg
	adminUser := "admin"
	if cfg != nil && len(cfg.RemoteManagement.Users) > 0 {
		adminUser = cfg.RemoteManagement.Users[0].Username
	}
	c.JSON(http.StatusOK, gin.H{
		"admin_username": adminUser,
		"allow_remote":   cfg != nil && cfg.RemoteManagement.AllowRemote,
		"has_users":      cfg != nil && len(cfg.RemoteManagement.Users) > 0,
	})
}
