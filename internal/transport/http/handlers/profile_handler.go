package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/resoul/api/internal/domain"
	"github.com/resoul/api/internal/middleware"
	"github.com/resoul/api/internal/transport/http/utils"
)

// ProfileResponse is the typed response payload for profile endpoints.
// Merges auth identity fields with application-level profile data.
type ProfileResponse struct {
	ID           string  `json:"id"`
	UserID       string  `json:"user_id"`
	Email        string  `json:"email"`
	Phone        string  `json:"phone,omitempty"`
	Role         string  `json:"role"`
	DisplayName  string  `json:"display_name"`
	AvatarURL    string  `json:"avatar_url,omitempty"`
	Bio          string  `json:"bio,omitempty"`
	LastSignInAt *string `json:"last_sign_in_at,omitempty"`
	CreatedAt    string  `json:"created_at"`
}

// ProfileHandler handles profile-related HTTP routes.
type ProfileHandler struct {
	svc domain.ProfileService
}

// NewProfileHandler returns a ProfileHandler backed by the given service.
func NewProfileHandler(svc domain.ProfileService) *ProfileHandler {
	return &ProfileHandler{svc: svc}
}

// GetMe returns the authenticated user's merged auth + profile data.
// Creates an empty profile on first call (idempotent).
//
// GET /api/v1/user/me
func (h *ProfileHandler) GetMe(c *gin.Context) {
	authUser, ok := contextUser(c)
	if !ok {
		utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "unauthenticated request")
		return
	}

	profile, err := h.svc.GetOrCreate(c.Request.Context(), authUser.ID)
	if err != nil {
		utils.RespondMapped(c, err)
		return
	}

	utils.RespondOK(c, toProfileResponse(authUser, profile))
}

// UpdateProfile applies a partial update to the authenticated user's profile.
// All fields are optional — only non-null fields in the JSON body are updated.
//
// PATCH /api/v1/user/profile
func (h *ProfileHandler) UpdateProfile(c *gin.Context) {
	authUser, ok := contextUser(c)
	if !ok {
		utils.RespondError(c, http.StatusUnauthorized, "unauthorized", "unauthenticated request")
		return
	}

	var inp domain.UpdateProfileInput
	if err := c.ShouldBindJSON(&inp); err != nil {
		utils.RespondError(c, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}

	profile, err := h.svc.Update(c.Request.Context(), authUser.ID, inp)
	if err != nil {
		utils.RespondMapped(c, err)
		return
	}

	utils.RespondOK(c, toProfileResponse(authUser, profile))
}

func contextUser(c *gin.Context) (*middleware.AuthUser, bool) {
	raw, exists := c.Get(middleware.ContextKeyUser)
	if !exists {
		return nil, false
	}
	user, ok := raw.(*middleware.AuthUser)
	return user, ok
}

func toProfileResponse(u *middleware.AuthUser, p *domain.Profile) ProfileResponse {
	return ProfileResponse{
		ID:          p.ID,
		UserID:      p.UserID,
		Email:       u.Email,
		Role:        u.Role,
		DisplayName: p.DisplayName,
		AvatarURL:   p.AvatarURL,
		Bio:         p.Bio,
		CreatedAt:   p.CreatedAt.String(),
	}
}
