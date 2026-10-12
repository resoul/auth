//go:build integration

package oidc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/postgres"
	appoidc "airlance.org/auth/internal/application/oidc"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	dsession "airlance.org/auth/internal/domain/session"
)

// A sign-out everywhere that wins the user while the sign-in page is being completed must not be undone by the proof the
// page holds: the proof is read again under the lock.
func TestAProofRevokedWhileTheLoginCompletesOpensNothing(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	asked := e.authorizeWith(e.newFlow(app).command(""))
	proof := e.signIn(alice)

	inside, release := make(chan struct{}), make(chan struct{})
	revoked := make(chan error, 1)
	go func() {
		revoked <- e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
			if err := appsession.RevokeEverything(ctx, st, alice.user.ID(), e.clock.Now()); err != nil {
				return err
			}
			close(inside)
			<-release // committed only after the login has had its chance to read the session
			return nil
		})
	}()
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	<-inside

	type outcome struct {
		got appoidc.CompleteLoginResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		got, err := e.login.Execute(context.Background(), appoidc.CompleteLoginCommand{RequestSecret: asked.RequestID, BindingSecret: asked.BindingSecret, AccessToken: proof})
		done <- outcome{got, err}
	}()
	time.Sleep(300 * time.Millisecond) // long enough for the login to reach its first read of the user
	close(release)
	must(t, <-revoked)
	out := <-done
	must(t, out.err)
	if out.got.Failure == nil || out.got.SSOSecret != "" {
		t.Fatalf("a proof revoked while the login completed opened a sign-in: %+v", out.got)
	}
}

// Deleting a key or moving the address cuts off the other devices, and what they opened with the provider goes with them;
// the device that made the change keeps its own.
func TestCuttingOffOtherDevicesEndsTheirSharedSignInsToo(t *testing.T) {
	e := newEnv(t)
	mine := e.registerWithLogout("panels-web", appCallback, appLogoutReturn, appBackchannel)
	alice := e.newPerson()
	keptTokens, keptSSO := e.tokens(e.newFlow(mine), alice)
	lostTokens, lostSSO := e.tokens(e.newFlow(mine), alice)
	keep := e.opSessionOf(keptSSO).DeviceSessionID
	if keep == "" || keep == e.opSessionOf(lostSSO).DeviceSessionID {
		t.Fatal("the two sign-ins do not come from two device sessions")
	}
	if got := e.queued(); len(got) != 0 {
		t.Fatalf("notices exist before anything ended: %v", got)
	}

	keepID, err := dsession.ParseID(keep)
	must(t, err)
	e.do(func(ctx context.Context, st port.Stores) error {
		return appsession.RevokeOthers(ctx, st, alice.user.ID(), keepID, e.clock.Now(), "key_deleted")
	})

	if !e.userinfoOK(keptTokens.AccessToken) || e.refresh(mine, keptTokens.RefreshToken).Response == nil {
		t.Error("the sign-in of the device that made the change was ended")
	}
	if e.userinfoOK(lostTokens.AccessToken) {
		t.Error("the access token of another device survived the cut-off")
	}
	if e.refresh(mine, lostTokens.RefreshToken).Response != nil {
		t.Error("the refresh token of another device survived the cut-off")
	}
	if !e.opSessionOf(lostSSO).RevokedAt.After(time.Time{}) || !e.opSessionOf(keptSSO).RevokedAt.IsZero() {
		t.Error("the shared sign-ins were not split between the devices")
	}
	if got := e.queued(); got["panels-web"] != 1 {
		t.Errorf("notices = %v, want one for the sign-in that ended", got)
	}
}

// max_age=0 is a demand for a fresh login, not an age of zero that no login can meet.
func TestMaxAgeZeroAcceptsALoginMadeForIt(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	e.clock.Advance(300 * time.Millisecond) // not on a whole second, as a token's time is

	cmd := e.newFlow(app).command("")
	cmd.MaxAge = "0"
	asked := e.authorizeWith(cmd)
	proof := e.signIn(alice)
	e.clock.Advance(250 * time.Millisecond)
	got, err := e.login.Execute(context.Background(), appoidc.CompleteLoginCommand{RequestSecret: asked.RequestID, BindingSecret: asked.BindingSecret, AccessToken: proof})
	must(t, err)
	if got.Failure != nil || got.SSOSecret == "" {
		t.Fatalf("a login made for max_age=0 = %+v", got)
	}

	// A login from before the request is still refused: that is what max_age=0 asks.
	old := e.signIn(alice)
	e.clock.Advance(time.Second)
	asked = e.authorizeWith(cmd)
	got, err = e.login.Execute(context.Background(), appoidc.CompleteLoginCommand{RequestSecret: asked.RequestID, BindingSecret: asked.BindingSecret, AccessToken: old})
	must(t, err)
	if got.Failure == nil || got.Failure.Code != appoidc.ErrLoginRequired {
		t.Errorf("an old login for max_age=0 = %+v", got)
	}
}

// A copy of a code shown after the code expired still ends the grant that was issued from it.
func TestAReplayedCodeEndsItsGrantAfterTheCodeExpired(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	f := e.newFlow(app)
	code, _ := e.signedIn(f, e.newPerson())
	won := e.exchange(f, code)
	if won.Response == nil {
		t.Fatalf("exchange = %+v", won.Failure)
	}
	e.clock.Advance(5 * time.Minute) // far past the life of a code
	if got := e.exchange(f, code); got.Response != nil || !got.Replay {
		t.Fatalf("a late replay = %+v, want a refusal that ends the grant", got)
	}
	if e.refresh(app, won.Response.RefreshToken).Response != nil {
		t.Error("the refresh token survived a late replay of its code")
	}
	if e.userinfoOK(won.Response.AccessToken) {
		t.Error("the access token survived a late replay of its code")
	}
}

// Cleanup keeps a spent code while its grant can still hold tokens, so a copy shown after the history of codes would
// otherwise be gone still ends the grant. A code nobody exchanged goes by the ordinary policy.
func TestCleanupKeepsASpentCodeWhileItsGrantLives(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	f := e.newFlow(app)
	code, sso := e.signedIn(f, alice)
	won := e.exchange(f, code)
	if won.Response == nil {
		t.Fatalf("exchange = %+v", won.Failure)
	}
	unused := e.newFlow(app)
	unusedCode, _ := e.signedIn(unused, alice)

	e.clock.Advance(23 * time.Hour)
	next := e.refresh(app, won.Response.RefreshToken)
	if next.Response == nil {
		t.Fatalf("refresh = %+v", next.Failure)
	}
	e.clock.Advance(2 * time.Hour)
	if _, err := e.store.Cleanup(context.Background(), e.clock.Now(), postgres.DefaultCleanupPolicy()); err != nil {
		t.Fatal(err)
	}
	_ = sso
	hash, err := e.secrets.HashOIDCSecret(unusedCode)
	must(t, err)
	e.do(func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.OIDCCodes.GetByHashForUpdate(ctx, hash); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("an unused expired code survived: %v", err)
		}
		return nil
	})

	if got := e.exchange(f, code); got.Response != nil || !got.Replay {
		t.Fatalf("a replay after cleanup = %+v, want a refusal that ends the grant", got)
	}
	if e.refresh(app, next.Response.RefreshToken).Response != nil || e.userinfoOK(next.Response.AccessToken) {
		t.Error("the tokens survived a replay shown after cleanup")
	}
}
