package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/resoul/api/internal/transport/http/utils"
)

const ContextKeyUser = "user"

type AuthUser struct {
	ID    string
	Email string
	Role  string
}

func Auth(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := bearerToken(c)
		if !ok {
			utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "Missing or malformed Authorization header")
			c.Abort()
			return
		}

		parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !parsed.Valid {
			utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			c.Abort()
			return
		}

		claims, ok := parsed.Claims.(jwt.MapClaims)
		if !ok {
			utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "Invalid token claims")
			c.Abort()
			return
		}

		user := &AuthUser{
			ID:    claims["sub"].(string),
			Email: claims["email"].(string),
			Role:  claims["role"].(string),
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
