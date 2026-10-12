package memory

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
)

type recognized struct{ tx *state }

func pairKey(userID identity.UserID, binding identity.BindingHash) string {
	return userID.String() + "|" + hex.EncodeToString(binding.Bytes())
}

func (r *recognized) load(key string) (*identity.RecognizedClient, bool, error) {
	rec, ok := r.tx.recognized[key]
	if !ok {
		return nil, false, nil
	}
	c, err := identity.RestoreRecognizedClient(rec)
	if err != nil {
		return nil, false, fmt.Errorf("restore recognized client: %w", err)
	}
	return c, true, nil
}

func (r *recognized) Register(_ context.Context, candidate *identity.RecognizedClient) (*identity.RecognizedClient, error) {
	key := pairKey(candidate.UserID(), candidate.Binding())
	existing, ok, err := r.load(key)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.tx.recognized[key] = candidate.Record()
		return candidate, nil
	}
	existing.Renew(candidate.VerifiedAt())
	r.tx.recognized[key] = existing.Record()
	return existing, nil
}

func (r *recognized) FindActive(_ context.Context, email identity.Email, binding identity.BindingHash, now time.Time) (*identity.RecognizedClient, error) {
	for _, rec := range r.tx.recognized {
		if rec.Email != email || !rec.Binding.Equal(binding) {
			continue
		}
		c, err := identity.RestoreRecognizedClient(rec)
		if err != nil {
			return nil, fmt.Errorf("restore recognized client: %w", err)
		}
		if c.Active(now) {
			return c, nil
		}
	}
	return nil, port.ErrNotFound
}

func (r *recognized) Extend(_ context.Context, userID identity.UserID, binding identity.BindingHash, now time.Time) error {
	key := pairKey(userID, binding)
	c, ok, err := r.load(key)
	if err != nil {
		return err
	}
	if !ok {
		return port.ErrNotFound
	}
	if err := c.Extend(now); err != nil {
		return port.ErrNotFound // revoked or expired: nothing active to extend
	}
	r.tx.recognized[key] = c.Record()
	return nil
}

func (r *recognized) Revoke(_ context.Context, userID identity.UserID, binding identity.BindingHash, now time.Time) error {
	key := pairKey(userID, binding)
	c, ok, err := r.load(key)
	if err != nil || !ok {
		return err
	}
	c.Revoke(now)
	r.tx.recognized[key] = c.Record()
	return nil
}

func (r *recognized) RevokeAll(_ context.Context, userID identity.UserID, now time.Time) error {
	for key, rec := range r.tx.recognized {
		if rec.UserID != userID {
			continue
		}
		c, err := identity.RestoreRecognizedClient(rec)
		if err != nil {
			return fmt.Errorf("restore recognized client: %w", err)
		}
		c.Revoke(now)
		r.tx.recognized[key] = c.Record()
	}
	return nil
}
