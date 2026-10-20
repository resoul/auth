package session_test

import (
	"context"
	"errors"
	"testing"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

func TestIssueCreatesSessionAndRootToken(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")

	sess := e.session(issued.Session.ID())
	if sess.UserID() != user.ID() || !sess.Active(t0) || sess.DeviceName() != "laptop" {
		t.Errorf("session = %+v", sess.Record())
	}

	tokens := e.tokens(sess.ID())
	if len(tokens) != 1 {
		t.Fatalf("%d tokens stored, want the root only", len(tokens))
	}

	root := tokens[0]
	if !root.ParentID().IsZero() || !root.ExpiresAt().Equal(issued.RefreshExpiresAt) || !root.ExpiresAt().Equal(t0.Add(30*day)) {
		t.Errorf("root = %+v", root.Record())
	}

	hash, err := e.secrets.HashRefreshSecret(issued.RefreshSecret)
	if err != nil || hash != root.Hash() {
		t.Errorf("the returned secret does not match the stored hash (%v)", err)
	}
}

func TestIssueGivesIndependentSessionsAndFamilies(t *testing.T) {
	e := newEnv(t)
	first, user := e.login("alice@example.test")
	second := e.loginAgain(user)

	if first.Session.ID() == second.Session.ID() || first.RefreshSecret == second.RefreshSecret {
		t.Error("two devices share a session or a secret")
	}

	a, b := e.tokens(first.Session.ID())[0], e.tokens(second.Session.ID())[0]
	if a.FamilyID() == b.FamilyID() {
		t.Error("two devices share a token family")
	}
}

func TestIssueIsPartOfTheCallersTransaction(t *testing.T) {
	e := newEnv(t)
	user := e.factory.User(testutil.UserSpec{})

	err := e.faults.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		st.Tokens = failingTokenCreate{st.Tokens}
		_, err := e.issuer.Issue(ctx, st, t0, appsession.IssueParams{
			UserID: user.ID(), Binding: testutil.BindingHash("b"), AMR: []string{"otp"}, AuthTime: t0,
		})

		return err
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}

	if e.store.UserCount() != 0 {
		t.Error("the user survived a failed issue")
	}

	if e.store.SessionCount() != 0 || e.store.TokenCount() != 0 {
		t.Error("the session survived a failed token insert")
	}
}

func TestIssueRejectsInvalidParams(t *testing.T) {
	e := newEnv(t)
	user := e.factory.User(testutil.UserSpec{})

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, err := e.issuer.Issue(ctx, st, t0, appsession.IssueParams{UserID: user.ID(), Binding: testutil.BindingHash("b"), AuthTime: t0})
		return err
	})
	if err == nil {
		t.Error("Issue accepted a session without authentication methods")
	}
}

func TestNewIssuerRequiresDependencies(t *testing.T) {
	e := newEnv(t)

	good := appsession.IssuerDeps{SessionIDs: e.ids, TokenIDs: e.ids, Secrets: e.secrets, Policy: policy}
	for name, mutate := range map[string]func(*appsession.IssuerDeps){
		"session ids": func(d *appsession.IssuerDeps) { d.SessionIDs = nil },
		"token ids":   func(d *appsession.IssuerDeps) { d.TokenIDs = nil },
		"secrets":     func(d *appsession.IssuerDeps) { d.Secrets = nil },
		"policy":      func(d *appsession.IssuerDeps) { d.Policy = session.Policy{} },
	} {
		d := good
		mutate(&d)

		if _, err := appsession.NewIssuer(d); err == nil {
			t.Errorf("NewIssuer accepted a missing %s", name)
		}
	}
}
