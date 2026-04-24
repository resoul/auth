package domain

import (
	"context"
	"time"
)

// Profile is the application-level user profile.
// It is distinct from auth.users — it stores product data owned by this service.
type Profile struct {
	ID          string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	UserID      string    `gorm:"type:uuid;uniqueIndex;not null"`
	DisplayName string    `gorm:"type:text"`
	AvatarURL   string    `gorm:"type:text"`
	Bio         string    `gorm:"type:text"`
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

// UpdateProfileInput carries the fields a user may change on their profile.
// Pointer fields allow partial updates — nil means "not provided, do not overwrite".
type UpdateProfileInput struct {
	DisplayName *string `json:"display_name" binding:"omitempty,max=100"`
	AvatarURL   *string `json:"avatar_url"   binding:"omitempty,url,max=2048"`
	Bio         *string `json:"bio"          binding:"omitempty,max=500"`
}

// ProfileRepository is the persistence port for Profile.
// Implementations live in internal/infrastructure/db/.
type ProfileRepository interface {
	// FindByUserID returns the profile for the given auth user ID.
	// Returns ErrNotFound when no profile exists yet.
	FindByUserID(ctx context.Context, userID string) (*Profile, error)

	// Upsert creates the profile if it does not exist, otherwise updates it.
	Upsert(ctx context.Context, profile *Profile) (*Profile, error)
}

// ProfileService is the business-logic port for profile operations.
// Implementations live in internal/service/.
type ProfileService interface {
	// GetOrCreate returns the existing profile for userID, or creates a new empty one.
	GetOrCreate(ctx context.Context, userID string) (*Profile, error)

	// Update applies inp to the profile owned by userID and persists the result.
	// Returns ErrInvalidInput if inp carries no changes.
	Update(ctx context.Context, userID string, inp UpdateProfileInput) (*Profile, error)
}
