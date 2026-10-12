package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
)

type users struct{ tx *state }

func (r *users) Get(_ context.Context, id identity.UserID) (*identity.User, error) {
	for _, rec := range r.tx.users {
		if rec.ID != id {
			continue
		}
		u, err := identity.RestoreUser(rec)
		if err != nil {
			return nil, fmt.Errorf("restore user: %w", err)
		}
		return u, nil
	}
	return nil, port.ErrNotFound
}

// GetForShare is Get: transactions of the memory store run one at a time.
func (r *users) GetForShare(ctx context.Context, id identity.UserID) (*identity.User, error) {
	return r.Get(ctx, id)
}

// GetForUpdate is Get: transactions of the memory store run one at a time.
func (r *users) GetForUpdate(ctx context.Context, id identity.UserID) (*identity.User, error) {
	return r.Get(ctx, id)
}

func (r *users) Ensure(_ context.Context, candidate *identity.User) (*identity.User, bool, error) {
	key := candidate.Email().String()
	if rec, ok := r.tx.users[key]; ok {
		existing, err := identity.RestoreUser(rec)
		if err != nil {
			return nil, false, fmt.Errorf("restore user: %w", err)
		}
		return existing, false, nil
	}
	r.tx.users[key] = candidate.Record()
	return candidate, true, nil
}

func (r *users) ChangeEmail(_ context.Context, u *identity.User) error {
	rec := u.Record()
	oldKey := ""
	for key, stored := range r.tx.users {
		switch {
		case stored.ID == rec.ID:
			oldKey = key
		case stored.Email == rec.Email:
			return port.ErrEmailTaken
		}
	}
	if oldKey == "" {
		return port.ErrNotFound
	}
	delete(r.tx.users, oldKey)
	r.tx.users[rec.Email.String()] = rec
	return nil
}

func (r *users) Delete(ctx context.Context, id identity.UserID) error {
	user, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	removedSessions := map[string]bool{}
	for key, rec := range r.tx.sessions {
		if rec.UserID == id {
			removedSessions[key] = true
			delete(r.tx.sessions, key)
		}
	}
	for key, rec := range r.tx.tokens {
		if removedSessions[rec.SessionID.String()] {
			delete(r.tx.tokens, key)
		}
	}
	removedClients := map[string]bool{}
	for key, rec := range r.tx.recognized {
		if rec.UserID == id {
			removedClients[rec.ID.String()] = true
			delete(r.tx.recognized, key)
		}
	}
	for key, rec := range r.tx.credentials {
		if rec.UserID == id {
			delete(r.tx.credentials, key)
		}
	}
	for key, rec := range r.tx.challenges {
		if rec.UserID == id {
			delete(r.tx.challenges, key)
		}
	}
	for key, rec := range r.tx.tickets {
		if rec.UserID == id {
			delete(r.tx.tickets, key)
		}
	}
	for key, rec := range r.tx.recovery {
		if rec.UserID == id {
			delete(r.tx.recovery, key)
		}
	}
	for key, rec := range r.tx.devices {
		if rec.UserID == id {
			delete(r.tx.devices, key)
		}
	}
	removedFlows := map[string]bool{}
	for key, rec := range r.tx.flows {
		if rec.UserID == id || rec.Email == user.Email() || removedClients[rec.RecognizedClientID.String()] {
			removedFlows[key] = true
			delete(r.tx.flows, key)
		}
	}
	r.tx.outbox = slices.DeleteFunc(r.tx.outbox, func(rec mailRecord) bool {
		return removedFlows[rec.job.FlowID.String()] || (!rec.job.UserID.IsZero() && rec.job.UserID == id)
	})
	for i := range r.tx.audit {
		if r.tx.audit[i].UserID == id {
			r.tx.audit[i].UserID = identity.UserID{}
		}
		if removedSessions[r.tx.audit[i].SessionID.String()] {
			r.tx.audit[i].SessionID = session.ID{}
		}
	}
	delete(r.tx.users, user.Email().String())
	return nil
}

func (r *users) FindByEmail(_ context.Context, email identity.Email) (*identity.User, error) {
	rec, ok := r.tx.users[email.String()]
	if !ok {
		return nil, port.ErrNotFound
	}
	u, err := identity.RestoreUser(rec)
	if err != nil {
		return nil, fmt.Errorf("restore user: %w", err)
	}
	return u, nil
}

func (r *users) SetBlocked(_ context.Context, u *identity.User) error {
	key := u.Email().String()
	rec, ok := r.tx.users[key]
	if !ok || rec.ID != u.ID() {
		return port.ErrNotFound
	}
	rec.BlockedAt, rec.UpdatedAt = u.BlockedAt(), u.UpdatedAt()
	r.tx.users[key] = rec
	return nil
}

func (r *users) List(_ context.Context, q port.UserQuery) ([]*identity.User, error) {
	var emails []string
	for email := range r.tx.users {
		if strings.HasPrefix(email, q.EmailPrefix) && email > q.After {
			emails = append(emails, email)
		}
	}
	slices.Sort(emails)
	if len(emails) > q.Limit {
		emails = emails[:q.Limit]
	}
	out := make([]*identity.User, 0, len(emails))
	for _, email := range emails {
		u, err := identity.RestoreUser(r.tx.users[email])
		if err != nil {
			return nil, fmt.Errorf("restore user: %w", err)
		}
		out = append(out, u)
	}
	return out, nil
}
