package admin_test

import (
	"context"
	"errors"
	"testing"

	"go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
)

func TestOperatorsAreCreatedOnceAndEnrolledByCode(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	op, enrollment, err := e.operators.Create(ctx, " Ops@Example.test ")
	must(t, err)

	if op.Email().String() != "ops@example.test" || enrollment.Code == "" || !enrollment.ExpiresAt.After(t0) {
		t.Fatalf("Create = %+v, %+v", op, enrollment)
	}

	if _, _, err := e.operators.Create(ctx, "ops@example.test"); !errors.Is(err, port.ErrOperatorExists) {
		t.Errorf("a second Create = %v, want ErrOperatorExists", err)
	}

	if _, _, err := e.operators.Create(ctx, "no address"); !errors.Is(err, admin.ErrInvalidInput) {
		t.Errorf("a bad address = %v, want ErrInvalidInput", err)
	}

	_, again, err := e.operators.Enroll(ctx, "ops@example.test")
	must(t, err)

	if again.Code == enrollment.Code {
		t.Error("two enrollments share a code")
	}

	if _, _, err := e.operators.Enroll(ctx, "ghost@example.test"); !errors.Is(err, admin.ErrNoOperator) {
		t.Errorf("Enroll of an unknown operator = %v, want ErrNoOperator", err)
	}

	changes := e.auditOf(port.AuditOperatorChanged)
	ops := map[string]int{}

	for _, c := range changes {
		if c.OperatorID != op.ID() {
			t.Errorf("a change names %v, want %v", c.OperatorID, op.ID())
		}

		ops[c.Fields["operation"]]++
	}

	if ops["create"] != 1 || ops["enroll"] != 1 || len(changes) != 2 {
		t.Errorf("changes = %v", ops)
	}
}

func TestDisablingAnUnknownOperatorFailsAndDisablingIsRepeatable(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enrolled("ops@example.test")

	if _, err := e.operators.SetDisabled(ctx, "ghost@example.test", true); !errors.Is(err, admin.ErrNoOperator) {
		t.Errorf("disable of an unknown operator = %v", err)
	}

	for i := 0; i < 2; i++ {
		op, err := e.operators.SetDisabled(ctx, "ops@example.test", true)
		must(t, err)

		if !op.Disabled() {
			t.Fatal("not disabled")
		}
	}

	op, err := e.operators.SetDisabled(ctx, "ops@example.test", false)
	must(t, err)

	if op.Disabled() {
		t.Error("still disabled")
	}
}

func TestOperatorListCountsKeys(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enrolled("a@example.test")
	_, _, err := e.operators.Create(ctx, "b@example.test")
	must(t, err)
	list, err := e.operators.List(ctx)
	must(t, err)

	if len(list) != 2 || list[0].Operator.Email().String() != "a@example.test" || list[0].Keys != 1 || list[1].Keys != 0 {
		t.Errorf("List = %+v", list)
	}
}
