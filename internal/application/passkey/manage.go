package passkey

import (
	"fmt"
	"time"

	"airlance.org/auth/internal/application/port"
	dpasskey "airlance.org/auth/internal/domain/passkey"
)

// CredentialSummary is what a signed-in user sees of a passkey: nothing that helps use it.
type CredentialSummary struct {
	ID             string
	Name           string
	CreatedAt      time.Time
	LastUsedAt     time.Time
	BackupEligible bool
	BackupState    bool
	Transports     []string
}

func summarize(c *dpasskey.Credential) CredentialSummary {
	return CredentialSummary{
		ID: c.ID().String(), Name: c.Name(), CreatedAt: c.CreatedAt(), LastUsedAt: c.LastUsedAt(),
		BackupEligible: c.BackupEligible(), BackupState: c.BackupState(), Transports: c.Transports(),
	}
}

// ManageDeps are the dependencies shared by the use cases that manage the passkeys of the
// signed-in user.
type ManageDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
}

func (d ManageDeps) validate(name string) error {
	if d.UnitOfWork == nil || d.Clock == nil {
		return fmt.Errorf("new %s: all dependencies are required", name)
	}
	return nil
}
