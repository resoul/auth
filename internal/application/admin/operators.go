package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/operator"
)

// OperatorsDeps are the dependencies of Operators.
type OperatorsDeps struct {
	UnitOfWork  port.UnitOfWork
	Clock       port.Clock
	OperatorIDs port.OperatorIDGenerator
	PasskeyIDs  port.PasskeyIDGenerator
	Secrets     port.TicketSecrets
}

// Operators manages the operators themselves. Only the command line on the server calls it: access to
// the server is the root of trust, so nothing here is reachable through the admin API.
type Operators struct{ OperatorsDeps }

// NewOperators checks the dependencies once, at assembly time.
func NewOperators(d OperatorsDeps) (*Operators, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.OperatorIDs == nil || d.PasskeyIDs == nil || d.Secrets == nil {
		return nil, errors.New("new operators: all dependencies are required")
	}
	return &Operators{d}, nil
}

// ErrNoOperator reports an address that names no operator.
var ErrNoOperator = errors.New("no such operator")

// Enrollment is a one-time code with the time it stops working.
type Enrollment struct {
	// Code is shown once; the store keeps its hash.
	Code      string
	ExpiresAt time.Time
}

func recordChange(ctx context.Context, st port.Stores, now time.Time, id operator.ID, operation string) error {
	return st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditOperatorChanged, Result: port.AuditSuccess, OperatorID: id, At: now, Fields: map[string]string{"operation": operation},
	})
}

func (o *Operators) issue(ctx context.Context, st port.Stores, now time.Time, id operator.ID) (Enrollment, error) {
	code, hash, err := o.Secrets.NewTicketSecret()
	if err != nil {
		return Enrollment{}, fmt.Errorf("new enrollment code: %w", err)
	}
	rowID, err := o.PasskeyIDs.NewPasskeyID()
	if err != nil {
		return Enrollment{}, fmt.Errorf("enrollment id: %w", err)
	}
	e, err := operator.NewEnrollment(rowID, id, hash, now)
	if err != nil {
		return Enrollment{}, err
	}
	if err := st.Operators.CreateEnrollment(ctx, e); err != nil {
		return Enrollment{}, fmt.Errorf("store enrollment: %w", err)
	}
	return Enrollment{Code: code, ExpiresAt: e.ExpiresAt()}, nil
}

// Create registers an operator and issues the code that enrolls the first key. An address that is taken
// is port.ErrOperatorExists.
func (o *Operators) Create(ctx context.Context, rawEmail string) (*operator.Operator, Enrollment, error) {
	email, err := identity.ParseEmail(rawEmail)
	if err != nil {
		return nil, Enrollment{}, invalid("the address is not valid")
	}
	id, err := o.OperatorIDs.NewOperatorID()
	if err != nil {
		return nil, Enrollment{}, fmt.Errorf("create operator: %w", err)
	}
	now := o.Clock.Now()
	op, err := operator.New(id, email, now)
	if err != nil {
		return nil, Enrollment{}, fmt.Errorf("create operator: %w", err)
	}
	var enrollment Enrollment
	err = o.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if err := st.Operators.Create(ctx, op); err != nil {
			return err
		}
		if enrollment, err = o.issue(ctx, st, now, op.ID()); err != nil {
			return err
		}
		return recordChange(ctx, st, now, op.ID(), "create")
	})
	if err != nil {
		return nil, Enrollment{}, fmt.Errorf("create operator: %w", err)
	}
	return op, enrollment, nil
}

// Enroll issues a code that adds a key to an existing operator. It is also how access comes back
// after every key was lost.
func (o *Operators) Enroll(ctx context.Context, rawEmail string) (*operator.Operator, Enrollment, error) {
	email, err := identity.ParseEmail(rawEmail)
	if err != nil {
		return nil, Enrollment{}, invalid("the address is not valid")
	}
	now := o.Clock.Now()
	var (
		op         *operator.Operator
		enrollment Enrollment
	)
	err = o.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		var err error
		if op, err = st.Operators.FindByEmail(ctx, email); errors.Is(err, port.ErrNotFound) {
			return ErrNoOperator
		} else if err != nil {
			return err
		}
		if op.Disabled() {
			return invalid("the operator is disabled: enable it first")
		}
		if enrollment, err = o.issue(ctx, st, now, op.ID()); err != nil {
			return err
		}
		return recordChange(ctx, st, now, op.ID(), "enroll")
	})
	if err != nil {
		return nil, Enrollment{}, fmt.Errorf("enroll operator: %w", err)
	}
	return op, enrollment, nil
}

// SetDisabled disables or enables an operator. Disabling ends every session of theirs in the same
// transaction.
func (o *Operators) SetDisabled(ctx context.Context, rawEmail string, disabled bool) (*operator.Operator, error) {
	email, err := identity.ParseEmail(rawEmail)
	if err != nil {
		return nil, invalid("the address is not valid")
	}
	now := o.Clock.Now()
	var op *operator.Operator
	err = o.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		var err error
		if op, err = st.Operators.FindByEmail(ctx, email); errors.Is(err, port.ErrNotFound) {
			return ErrNoOperator
		} else if err != nil {
			return err
		}
		operation := "enable"
		if disabled {
			operation = "disable"
			if err := op.Disable(now); err != nil {
				return err
			}
		} else {
			op.Enable()
		}
		if err := st.Operators.Save(ctx, op); err != nil {
			return err
		}
		if disabled {
			if err := st.OperatorSessions.RevokeAllForOperator(ctx, op.ID(), now); err != nil {
				return err
			}
		}
		return recordChange(ctx, st, now, op.ID(), operation)
	})
	if err != nil {
		return nil, fmt.Errorf("set operator disabled: %w", err)
	}
	return op, nil
}

// OperatorInfo is a line of the operator list.
type OperatorInfo struct {
	Operator *operator.Operator
	Keys     int
}

// List returns every operator with the number of keys each has.
func (o *Operators) List(ctx context.Context) ([]OperatorInfo, error) {
	var out []OperatorInfo
	err := o.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		ops, err := st.Operators.List(ctx)
		if err != nil {
			return err
		}
		for _, op := range ops {
			keys, err := st.Operators.ListCredentials(ctx, op.ID())
			if err != nil {
				return err
			}
			out = append(out, OperatorInfo{Operator: op, Keys: len(keys)})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list operators: %w", err)
	}
	return out, nil
}
