package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"airlance.org/auth/internal/adapter/clock"
	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/id"
	appadmin "airlance.org/auth/internal/application/admin"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/config"
)

// OperatorAction selects what the operator command does.
type OperatorAction string

// Operator actions.
const (
	OperatorCreate  OperatorAction = "create"
	OperatorEnroll  OperatorAction = "enroll"
	OperatorList    OperatorAction = "list"
	OperatorDisable OperatorAction = "disable"
	OperatorEnable  OperatorAction = "enable"
)

// OperatorRequest is the input of Operator. Email is used by every action but list.
type OperatorRequest struct {
	Action OperatorAction
	Email  string
}

// Operator manages the operators of the admin API against the configured database and reports to out.
// It runs on the server: access to the server is what lets a person become, or become again, an operator,
// so none of this is reachable through the admin API itself.
func Operator(ctx context.Context, cfg config.Config, req OperatorRequest, out io.Writer) error {
	if !cfg.Database.URL.IsSet() {
		return fmt.Errorf("%s is required for operator", config.EnvDatabaseURL)
	}
	store, err := openStore(ctx, cfg, 2)
	if err != nil {
		return err
	}
	defer store.Close()
	operators, err := appadmin.NewOperators(appadmin.OperatorsDeps{
		UnitOfWork: store, Clock: clock.System{}, OperatorIDs: id.Generator{}, PasskeyIDs: id.Generator{}, Secrets: crypto.Ticket{},
	})
	if err != nil {
		return err
	}
	if !cfg.Admin.Enabled() {
		if _, err := fmt.Fprintf(out, "note: %s is not set, so the admin API is off; operators have nowhere to sign in until it is\n", config.EnvAdminAddr); err != nil {
			return err
		}
	}

	switch req.Action {
	case OperatorCreate, OperatorEnroll:
		var enrollment appadmin.Enrollment
		var email string
		if req.Action == OperatorCreate {
			op, e, err := operators.Create(ctx, req.Email)
			if errors.Is(err, port.ErrOperatorExists) {
				return fmt.Errorf("operator: %s is already an operator: use enroll to add a key", req.Email)
			}
			if err != nil {
				return fmt.Errorf("operator: %w", err)
			}
			enrollment, email = e, op.Email().String()
		} else {
			op, e, err := operators.Enroll(ctx, req.Email)
			if errors.Is(err, appadmin.ErrNoOperator) {
				return fmt.Errorf("operator: no operator %s: use create first", req.Email)
			}
			if err != nil {
				return fmt.Errorf("operator: %w", err)
			}
			enrollment, email = e, op.Email().String()
		}
		_, err := fmt.Fprintf(out, "operator %s\nenrollment code (shown once, valid until %s):\n\n    %s\n\nOpen the admin page, choose \"Register a key\" and enter the code.\n",
			email, enrollment.ExpiresAt.UTC().Format(time.RFC3339), enrollment.Code)
		return err
	case OperatorDisable, OperatorEnable:
		op, err := operators.SetDisabled(ctx, req.Email, req.Action == OperatorDisable)
		if errors.Is(err, appadmin.ErrNoOperator) {
			return fmt.Errorf("operator: no operator %s", req.Email)
		}
		if err != nil {
			return fmt.Errorf("operator: %w", err)
		}
		if req.Action == OperatorDisable {
			_, err = fmt.Fprintf(out, "disabled %s: every session of theirs is ended\n", op.Email())
		} else {
			_, err = fmt.Fprintf(out, "enabled %s\n", op.Email())
		}
		return err
	case OperatorList:
		list, err := operators.List(ctx)
		if err != nil {
			return fmt.Errorf("operator: %w", err)
		}
		if len(list) == 0 {
			_, err = fmt.Fprintln(out, "no operators: create one with `operator create EMAIL`")
			return err
		}
		for _, info := range list {
			state := "active"
			if info.Operator.Disabled() {
				state = "disabled"
			}
			if _, err := fmt.Fprintf(out, "%s\t%s\t%d keys\tcreated %s\n", info.Operator.Email(), state, info.Keys,
				info.Operator.CreatedAt().UTC().Format(time.RFC3339)); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("operator: unknown action %q", req.Action)
}
