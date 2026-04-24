package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/resoul/api/internal/transport/http/middleware"
	"github.com/resoul/api/internal/transport/http/utils"
	"github.com/supabase-community/auth-go/types"
)

// ProfileResponse is the typed response payload for profile endpoints.
// Replaces the previous gin.H raw map.
type ProfileResponse struct {
	ID          string  `json:"id"`
	Email       string  `json:"email"`
	Phone       string  `json:"phone,omitempty"`
	Role        string  `json:"role"`
	LastSignInAt *string `json:"last_sign_in_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

type ProfileHandler struct{}

func NewProfileHandler() *ProfileHandler {
	return &ProfileHandler{}
}

// GetMe returns the authenticated user's profile.
// Requires Auth middleware to be applied on the route group.
//
// GET /api/v1/user/me
func (h *ProfileHandler) GetMe(c *gin.Context) {
	user, ok := contextUser(c)
	if !ok {
		// Should never happen when middleware is correctly applied,
		// but guard defensively.
		utils.RespondError(c, 401, "unauthorized", "unauthenticated request")
		return
	}

	utils.RespondOK(c, toProfileResponse(user))
}

// contextUser retrieves the *types.User injected by the Auth middleware.
func contextUser(c *gin.Context) (*types.User, bool) {
	raw, exists := c.Get(middleware.ContextKeyUser)
	if !exists {
		return nil, false
	}

	user, ok := raw.(*types.User)
	return user, ok
}

func toProfileResponse(u *types.User) ProfileResponse {
	resp := ProfileResponse{
		ID:        u.ID.String(),
		Email:     u.Email,
		Phone:     u.Phone,
		Role:      u.Role,
		CreatedAt: u.CreatedAt.String(),
	}

	if u.LastSignInAt != nil {
		s := u.LastSignInAt.String()
		resp.LastSignInAt = &s
	}

	return resp
}
