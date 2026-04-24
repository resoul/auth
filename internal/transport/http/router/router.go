package router

import (
	"github.com/gin-gonic/gin"
	"github.com/resoul/api/internal/config"
	"github.com/resoul/api/internal/transport/http/utils"
	"github.com/supabase-community/auth-go"
	"gorm.io/gorm"
)

func New(cfg *config.Config, db *gorm.DB, authClient auth.Client) *gin.Engine {
	r := gin.Default()

	api := r.Group("/api/v1")
	{
		api.GET("/health", func(c *gin.Context) {
			utils.RespondOK(c, gin.H{"status": "ok"})
		})
		api.GET("/profile", ProfileHandler(authClient))
	}

	return r
}
