package service

import (
	"context"

	"github.com/resoul/api/internal/domain"
)

type profileService struct {
	repo domain.ProfileRepository
}

// NewProfileService returns a ProfileService backed by the given repository.
func NewProfileService(repo domain.ProfileRepository) domain.ProfileService {
	return &profileService{repo: repo}
}

// GetOrCreate returns the existing profile for userID.
// If no profile exists yet it creates and persists an empty one.
func (s *profileService) GetOrCreate(ctx context.Context, userID string) (*domain.Profile, error) {
	profile, err := s.repo.FindByUserID(ctx, userID)
	if err == nil {
		return profile, nil
	}

	if err != domain.ErrNotFound {
		return nil, err
	}

	// No profile yet — create an empty one.
	blank := &domain.Profile{UserID: userID}
	return s.repo.Upsert(ctx, blank)
}

// Update applies non-nil fields from inp to the profile owned by userID.
// Returns domain.ErrInvalidInput when inp carries no changes.
// Returns domain.ErrNotFound when no profile exists for userID.
func (s *profileService) Update(ctx context.Context, userID string, inp domain.UpdateProfileInput) (*domain.Profile, error) {
	if inp.DisplayName == nil && inp.AvatarURL == nil && inp.Bio == nil {
		return nil, domain.ErrInvalidInput
	}

	profile, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err // propagates ErrNotFound as-is
	}

	if inp.DisplayName != nil {
		profile.DisplayName = *inp.DisplayName
	}

	if inp.AvatarURL != nil {
		profile.AvatarURL = *inp.AvatarURL
	}

	if inp.Bio != nil {
		profile.Bio = *inp.Bio
	}

	return s.repo.Upsert(ctx, profile)
}
