package memory

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
)

type credentials struct{ tx *state }

func credentialKey(credentialID []byte) string { return hex.EncodeToString(credentialID) }

func (r *credentials) Create(_ context.Context, c *passkey.Credential) error {
	key := credentialKey(c.CredentialID())
	if _, ok := r.tx.credentials[key]; ok {
		return port.ErrCredentialConflict
	}

	r.tx.credentials[key] = c.Record()

	return nil
}

func (r *credentials) ListByUser(_ context.Context, userID identity.UserID) ([]*passkey.Credential, error) {
	var recs []passkey.CredentialRecord

	for _, rec := range r.tx.credentials {
		if rec.UserID == userID {
			recs = append(recs, rec)
		}
	}

	slices.SortFunc(recs, func(a, b passkey.CredentialRecord) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}

		return bytes.Compare([]byte(a.ID.String()), []byte(b.ID.String()))
	})

	out := make([]*passkey.Credential, 0, len(recs))
	for _, rec := range recs {
		c, err := passkey.RestoreCredential(rec)
		if err != nil {
			return nil, fmt.Errorf("restore credential: %w", err)
		}

		out = append(out, c)
	}

	return out, nil
}

func (r *credentials) GetForUpdate(_ context.Context, credentialID []byte) (*passkey.Credential, error) {
	rec, ok := r.tx.credentials[credentialKey(credentialID)]
	if !ok {
		return nil, port.ErrNotFound
	}

	c, err := passkey.RestoreCredential(rec)
	if err != nil {
		return nil, fmt.Errorf("restore credential: %w", err)
	}

	return c, nil
}

func (r *credentials) Save(_ context.Context, c *passkey.Credential) error {
	key := credentialKey(c.CredentialID())
	if _, ok := r.tx.credentials[key]; !ok {
		return port.ErrNotFound
	}

	r.tx.credentials[key] = c.Record()

	return nil
}

func (r *credentials) DeleteAllForUser(_ context.Context, userID identity.UserID) (int, error) {
	n := 0

	for key, rec := range r.tx.credentials {
		if rec.UserID == userID {
			delete(r.tx.credentials, key)

			n++
		}
	}

	return n, nil
}

func (r *credentials) Delete(_ context.Context, userID identity.UserID, id passkey.ID) error {
	var found string

	owned := 0

	for key, rec := range r.tx.credentials {
		if rec.UserID != userID {
			continue
		}

		owned++

		if rec.ID == id {
			found = key
		}
	}

	switch {
	case found == "":
		return port.ErrNotFound
	case owned == 1:
		return port.ErrLastCredential
	}

	delete(r.tx.credentials, found)

	return nil
}

// challenges keeps the ceremonies of one table: users and operators each have their own.
type challenges struct {
	m map[string]passkey.ChallengeRecord
}

func (r *challenges) Create(_ context.Context, c *passkey.Challenge) error {
	if _, ok := r.m[c.ID().String()]; ok {
		return fmt.Errorf("challenge %s already exists", c.ID())
	}

	r.m[c.ID().String()] = c.Record()

	return nil
}

func (r *challenges) GetForUpdate(_ context.Context, id passkey.ID) (*passkey.Challenge, error) {
	rec, ok := r.m[id.String()]
	if !ok {
		return nil, port.ErrNotFound
	}

	c, err := passkey.RestoreChallenge(rec)
	if err != nil {
		return nil, fmt.Errorf("restore challenge: %w", err)
	}

	return c, nil
}

func (r *challenges) Save(_ context.Context, c *passkey.Challenge) error {
	if _, ok := r.m[c.ID().String()]; !ok {
		return port.ErrNotFound
	}

	r.m[c.ID().String()] = c.Record()

	return nil
}

type tickets struct{ tx *state }

func (r *tickets) Create(_ context.Context, t *passkey.Ticket) error {
	rec := t.Record()
	for _, other := range r.tx.tickets {
		if other.SecretHash == rec.SecretHash {
			return port.ErrTicketConflict
		}
	}

	if _, ok := r.tx.tickets[t.ID().String()]; ok {
		return fmt.Errorf("ticket %s already exists", t.ID())
	}

	r.tx.tickets[t.ID().String()] = rec

	return nil
}

func (r *tickets) GetByHashForUpdate(_ context.Context, hash passkey.SecretHash) (*passkey.Ticket, error) {
	for _, rec := range r.tx.tickets {
		if rec.SecretHash == hash {
			return restoreTicket(rec)
		}
	}

	return nil, port.ErrNotFound
}

func (r *tickets) GetForUpdate(_ context.Context, id passkey.ID) (*passkey.Ticket, error) {
	rec, ok := r.tx.tickets[id.String()]
	if !ok {
		return nil, port.ErrNotFound
	}

	return restoreTicket(rec)
}

func restoreTicket(rec passkey.TicketRecord) (*passkey.Ticket, error) {
	t, err := passkey.RestoreTicket(rec)
	if err != nil {
		return nil, fmt.Errorf("restore ticket: %w", err)
	}

	return t, nil
}

func (r *tickets) Save(_ context.Context, t *passkey.Ticket) error {
	if _, ok := r.tx.tickets[t.ID().String()]; !ok {
		return port.ErrNotFound
	}

	r.tx.tickets[t.ID().String()] = t.Record()

	return nil
}

type recovery struct{ tx *state }

func (r *recovery) Replace(_ context.Context, userID identity.UserID, codes []*passkey.RecoveryCode) error {
	next := map[string]passkey.RecoveryCodeRecord{}

	for key, rec := range r.tx.recovery {
		if rec.UserID != userID {
			next[key] = rec
		}
	}

	for _, c := range codes {
		rec := c.Record()
		if rec.UserID != userID {
			return fmt.Errorf("recovery code %s belongs to another user", rec.ID)
		}

		for _, other := range next {
			if other.Hash == rec.Hash {
				return port.ErrTicketConflict
			}
		}

		next[rec.ID.String()] = rec
	}

	r.tx.recovery = next

	return nil
}

func (r *recovery) GetByHashForUpdate(_ context.Context, hash passkey.SecretHash) (*passkey.RecoveryCode, error) {
	for _, rec := range r.tx.recovery {
		if rec.Hash == hash {
			c, err := passkey.RestoreRecoveryCode(rec)
			if err != nil {
				return nil, fmt.Errorf("restore recovery code: %w", err)
			}

			return c, nil
		}
	}

	return nil, port.ErrNotFound
}

func (r *recovery) Save(_ context.Context, c *passkey.RecoveryCode) error {
	if _, ok := r.tx.recovery[c.ID().String()]; !ok {
		return port.ErrNotFound
	}

	r.tx.recovery[c.ID().String()] = c.Record()

	return nil
}

func (r *recovery) CountUnused(_ context.Context, userID identity.UserID) (int, error) {
	n := 0

	for _, rec := range r.tx.recovery {
		if rec.UserID == userID && rec.UsedAt.IsZero() {
			n++
		}
	}

	return n, nil
}
