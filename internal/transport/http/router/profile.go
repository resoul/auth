package router

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/resoul/api/internal/transport/http/utils"
	"github.com/supabase-community/auth-go"
)

func ProfileHandler(authClient auth.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "Missing Authorization header")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "Invalid Authorization header format")
			return
		}

		token := parts[1]

		// Using the token to get user data from the auth service.
		// This also verifies the token implicitly.
		user, err := authClient.WithToken(token).GetUser()
		if err != nil {
			utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			return
		}

		// Map to a response that matches what we had before or what the frontend expects
		utils.RespondOK(c, gin.H{
			"id":         user.ID,
			"email":      user.Email,
			"role":       user.Role,
			"last_login": user.LastSignInAt,
			"created_at": user.CreatedAt,
		})
	}
}
