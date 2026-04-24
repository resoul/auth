package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/resoul/api/internal/transport/http/utils"
	"github.com/supabase-community/auth-go"
	"net/http"
)

const ContextKeyUser = "user"

// Auth validates the Bearer token from the Authorization header using Supabase Auth.
// On success it injects *auth.User into the Gin context under ContextKeyUser.
// On failure it aborts with 401 Unauthorized.
func Auth(authClient auth.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := bearerToken(c)
		if !ok {
			utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "Missing or malformed Authorization header")
			c.Abort()
			return
		}

		user, err := authClient.WithToken(token).GetUser()
		if err != nil {
			utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			c.Abort()
			return
		}

		c.Set(ContextKeyUser, user)
		c.Next()
	}
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
// Returns the token and true on success, empty string and false otherwise.
func bearerToken(c *gin.Context) (string, bool) {
	header := c.GetHeader("Authorization")
	if header == "" {
		return "", false
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", false
	}

	return token, true
}
