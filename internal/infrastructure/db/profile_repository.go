package db

import (
	"context"
	"errors"

	"github.com/resoul/api/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type profileRepository struct {
	db *gorm.DB
}

// NewProfileRepository returns a GORM-backed ProfileRepository.
func NewProfileRepository(db *gorm.DB) domain.ProfileRepository {
	return &profileRepository{db: db}
}

// FindByUserID returns the profile for the given auth user ID.
// Returns domain.ErrNotFound when no profile exists yet.
func (r *profileRepository) FindByUserID(ctx context.Context, userID string) (*domain.Profile, error) {
	var p domain.Profile

	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		First(&p).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}

	return &p, nil
}

// Upsert inserts a new profile or updates the existing one matched by user_id.
// Only non-zero fields from profile are written on conflict.
func (r *profileRepository) Upsert(ctx context.Context, profile *domain.Profile) (*domain.Profile, error) {
	err := r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"display_name",
				"avatar_url",
				"bio",
				"updated_at",
			}),
		}).
		Create(profile).Error

	if err != nil {
		return nil, err
	}

	return profile, nil
}
