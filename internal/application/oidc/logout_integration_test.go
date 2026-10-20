//go:build integration

package oidc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	appoidc "go.airlance.org/auth/internal/application/oidc"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
)

const (
	appLogoutReturn = "https://app.example.test/signed-out"
	appBackchannel  = "https://app.example.test/auth/backchannel-logout"
)

// logoutOnce confirms a logout and returns the result.
func (e *env) logoutOnce(cmd appoidc.LogoutCommand) appoidc.LogoutResult {
	e.t.Helper()

	if cmd.Confirm && cmd.ConfirmToken == "" {
		// What the person's browser does: the page that asks carries the token back.
		ask := cmd

		ask.Confirm = false
		if asked, err := e.logout.Execute(context.Background(), ask); err == nil {
			cmd.ConfirmToken = asked.ConfirmToken
		}
	}

	got, err := e.logout.Execute(context.Background(), cmd)
	must(e.t, err)

	return got
}

// queued counts the logout notices waiting for delivery, per client.
func (e *env) queued() map[string]int {
	e.t.Helper()

	out := map[string]int{}

	for {
		var n *port.ClaimedLogout

		e.do(func(ctx context.Context, st port.Stores) error {
			var err error

			n, err = st.OIDCLogout.Claim(ctx, e.clock.Now(), e.clock.Now().Add(time.Hour))
			if err != nil && err.Error() != port.ErrNotFound.Error() {
				return err
			}

			return nil
		})

		if n == nil {
			return out
		}

		out[n.ClientID]++
	}
}

func TestLoggingOutEndsTheSharedSignInAndEverythingOnIt(t *testing.T) {
	e := newEnv(t)
	panels := e.registerWithLogout("panels-web", appCallback, appLogoutReturn, appBackchannel)
	video := e.register("video-web", appTwo, "openid", "email") // no endpoint: it is told nothing
	alice := e.newPerson()
	first, sso := e.tokens(e.newFlow(panels), alice)
	second, _ := func() (*appoidc.TokenResponse, string) {
		f := e.newFlow(video)
		got := e.authorizeWith(f.command(sso))

		return e.exchange(f, e.codeOf(f, got.Location)).Response, sso
	}()

	op := e.opSessionOf(sso)
	if op.DeviceSessionID == "" {
		t.Fatal("the shared sign-in does not remember the device session it grew from")
	}

	// The first request only asks. Nothing changes.
	asked := e.logoutOnce(appoidc.LogoutCommand{IDTokenHint: first.IDToken, PostLogoutRedirectURI: appLogoutReturn, State: "xyz", SSOSecret: sso})
	if asked.Kind != appoidc.LogoutConfirm || asked.SignedOut {
		t.Fatalf("logout without confirmation = %+v, want only a question", asked)
	}

	if !e.userinfoOK(first.AccessToken) || e.refresh(panels, first.RefreshToken).Response == nil {
		t.Fatal("asking to log out ended something")
	}

	done := e.logoutOnce(appoidc.LogoutCommand{IDTokenHint: first.IDToken, PostLogoutRedirectURI: appLogoutReturn, State: "xyz", SSOSecret: sso, Confirm: true})
	if done.Kind != appoidc.LogoutDone || !done.SignedOut || done.Location != appLogoutReturn+"?state=xyz" {
		t.Fatalf("confirmed logout = %+v", done)
	}

	// Every application is out: tokens, refresh tokens and the shared sign-in.
	for name, token := range map[string]string{"first": first.AccessToken, "second": second.AccessToken} {
		if e.userinfoOK(token) {
			t.Errorf("the %s access token still works after logout", name)
		}
	}

	if e.refresh(panels, first.RefreshToken).Response != nil || e.refresh(video, second.RefreshToken).Response != nil {
		t.Error("a refresh token survived the logout")
	}

	if got := e.authorizeWith(e.newFlow(panels).command(sso)); got.Kind != appoidc.AuthorizeLogin {
		t.Errorf("the cookie still opens a code after logout: %+v", got)
	}
	// The device session of the sign-in page went with it.
	e.do(func(ctx context.Context, st port.Stores) error {
		sess, err := appsessionByID(ctx, st, op.DeviceSessionID)
		if err != nil {
			return err
		}

		if sess.Active(e.clock.Now()) {
			t.Error("the device session the sign-in grew from is still live")
		}

		return nil
	})
	// Only the application with an endpoint is told, once.
	if got := e.queued(); len(got) != 1 || got["panels-web"] != 1 {
		t.Errorf("notices = %v, want one for panels-web and none for video-web", got)
	}

	// Doing it again is harmless, and queues nothing.
	again := e.logoutOnce(appoidc.LogoutCommand{SSOSecret: sso, Confirm: true})
	if again.Kind != appoidc.LogoutDone || again.SignedOut {
		t.Errorf("a second logout = %+v", again)
	}

	if got := e.queued(); len(got) != 0 {
		t.Errorf("a second logout queued %v", got)
	}
}

func TestLogoutRequestsAreCheckedBeforeAnythingElse(t *testing.T) {
	e := newEnv(t)
	panels := e.registerWithLogout("panels-web", appCallback, appLogoutReturn, "")
	video := e.registerWithLogout("video-web", appTwo, "https://video.example.test/out", "")
	alice := e.newPerson()
	tokens, sso := e.tokens(e.newFlow(panels), alice)
	other, _ := e.tokens(e.newFlow(video), e.newPerson())

	refuse := func(name string, cmd appoidc.LogoutCommand) {
		t.Helper()

		cmd.SSOSecret = sso
		for _, confirm := range []bool{false, true} {
			cmd.Confirm = confirm
			if got := e.logoutOnce(cmd); got.Kind != appoidc.LogoutFailure || got.Location != "" {
				t.Errorf("%s (confirm=%v): %+v, want an error page and no redirect", name, confirm, got)
			}
		}
	}
	refuse("an access token as the hint", appoidc.LogoutCommand{IDTokenHint: tokens.AccessToken})
	refuse("garbage as the hint", appoidc.LogoutCommand{IDTokenHint: "a.b.c"})
	refuse("a hint of one client with the id of another", appoidc.LogoutCommand{IDTokenHint: tokens.IDToken, ClientID: "video-web"})
	refuse("an unregistered return address", appoidc.LogoutCommand{IDTokenHint: tokens.IDToken, PostLogoutRedirectURI: "https://evil.example.test/"})
	refuse("another client's return address", appoidc.LogoutCommand{IDTokenHint: tokens.IDToken, PostLogoutRedirectURI: "https://video.example.test/out"})
	refuse("a return address with a suffix", appoidc.LogoutCommand{IDTokenHint: tokens.IDToken, PostLogoutRedirectURI: appLogoutReturn + "/"})
	refuse("a return address and nobody to vouch for it", appoidc.LogoutCommand{PostLogoutRedirectURI: appLogoutReturn})
	refuse("a return address of an unknown client", appoidc.LogoutCommand{ClientID: "nobody", PostLogoutRedirectURI: appLogoutReturn})
	refuse("an endless state", appoidc.LogoutCommand{IDTokenHint: tokens.IDToken, PostLogoutRedirectURI: appLogoutReturn, State: string(make([]byte, 600))})

	if !e.userinfoOK(tokens.AccessToken) || !e.userinfoOK(other.AccessToken) {
		t.Fatal("refused requests ended a sign-in")
	}

	// A hint that has expired still names the sign-in: that is its use.
	e.clock.Advance(time.Hour)

	if got := e.logoutOnce(appoidc.LogoutCommand{IDTokenHint: tokens.IDToken, PostLogoutRedirectURI: appLogoutReturn, State: "s"}); got.Kind != appoidc.LogoutConfirm {
		t.Errorf("an expired hint = %+v, want the question", got)
	}
	// The client alone, without a hint, may name its own return address.
	if got := e.logoutOnce(appoidc.LogoutCommand{ClientID: "panels-web", PostLogoutRedirectURI: appLogoutReturn, SSOSecret: sso, Confirm: true}); got.Location != appLogoutReturn {
		t.Errorf("client id alone = %+v", got)
	}
	// Without a return address nothing redirects.
	if got := e.logoutOnce(appoidc.LogoutCommand{SSOSecret: sso, Confirm: true}); got.Kind != appoidc.LogoutDone || got.Location != "" {
		t.Errorf("no return address = %+v", got)
	}
}

func TestLoggingOutEndsTheSignInOfTheCookieOnly(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	aliceTokens, aliceSSO := e.tokens(e.newFlow(app), e.newPerson())
	bobTokens, bobSSO := e.tokens(e.newFlow(app), e.newPerson())

	if got := e.logoutOnce(appoidc.LogoutCommand{SSOSecret: aliceSSO, Confirm: true}); !got.SignedOut {
		t.Fatalf("logout = %+v", got)
	}

	if e.userinfoOK(aliceTokens.AccessToken) {
		t.Error("alice's token survived her logout")
	}

	if !e.userinfoOK(bobTokens.AccessToken) || e.authorizeWith(e.newFlow(app).command(bobSSO)).Kind != appoidc.AuthorizeRedirect {
		t.Error("alice's logout ended bob's sign-in")
	}
	// A cookie that is not a secret, or that nobody holds, ends nothing and still succeeds.
	for _, sso := range []string{"", "junk", aliceSSO} {
		if got := e.logoutOnce(appoidc.LogoutCommand{SSOSecret: sso, Confirm: true}); got.Kind != appoidc.LogoutDone || got.SignedOut {
			t.Errorf("cookie %q = %+v", sso, got)
		}
	}
}

func TestSigningOutEverywhereTellsTheApplications(t *testing.T) {
	e := newEnv(t)
	a := e.registerWithLogout("app-one", appCallback, "", appBackchannel)
	b := e.registerWithLogout("app-two", appTwo, "", "https://other.example.test/bc")
	alice := e.newPerson()
	_, sso := e.tokens(e.newFlow(a), alice)
	f := e.newFlow(b)
	e.exchange(f, e.codeOf(f, e.authorizeWith(f.command(sso)).Location))

	revoke := func() {
		e.do(func(ctx context.Context, st port.Stores) error {
			return appsession.RevokeEverything(ctx, st, alice.user.ID(), e.clock.Now())
		})
	}
	revoke()

	if got := e.queued(); got["app-one"] != 1 || got["app-two"] != 1 || len(got) != 2 {
		t.Errorf("notices after sign out everywhere = %v, want one each", got)
	}

	revoke() // a recovery after it, or a block: the grants are gone, so nobody is told twice

	if got := e.queued(); len(got) != 0 {
		t.Errorf("a second revocation queued %v", got)
	}
}

func TestRevokingATokenEndsItsGrantButOnlyForItsOwnClient(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	other := e.register("other-app", appTwo, "openid", "email")
	alice := e.newPerson()
	revoke := func(c client, token string) appoidc.RevokeResult {
		t.Helper()

		got, err := e.revoke.Execute(context.Background(), appoidc.RevokeCommand{ClientID: c.id, ClientSecret: c.secret, Token: token})
		must(t, err)

		return got
	}

	t.Run("a refresh token ends the grant and every token of it", func(t *testing.T) {
		tokens, sso := e.tokens(e.newFlow(app), alice)
		if got := revoke(app, tokens.RefreshToken); got.Failure != nil {
			t.Fatalf("revoke = %+v", got.Failure)
		}

		if e.refresh(app, tokens.RefreshToken).Response != nil || e.userinfoOK(tokens.AccessToken) {
			t.Error("a token of the revoked grant still works")
		}
		// Only that application's grant: the shared sign-in lives, and a new code is issued without a screen.
		if got := e.authorizeWith(e.newFlow(app).command(sso)); got.Kind != appoidc.AuthorizeRedirect {
			t.Errorf("the shared sign-in ended with a single grant: %+v", got)
		}
	})

	t.Run("an access token does the same", func(t *testing.T) {
		tokens, _ := e.tokens(e.newFlow(app), alice)
		if got := revoke(app, tokens.AccessToken); got.Failure != nil {
			t.Fatalf("revoke = %+v", got.Failure)
		}

		if e.refresh(app, tokens.RefreshToken).Response != nil || e.userinfoOK(tokens.AccessToken) {
			t.Error("revoking an access token left its grant alive")
		}
	})

	t.Run("another client's token is not its to revoke, and it is not told so", func(t *testing.T) {
		tokens, _ := e.tokens(e.newFlow(app), alice)
		for name, token := range map[string]string{"refresh": tokens.RefreshToken, "access": tokens.AccessToken} {
			if got := revoke(other, token); got.Failure != nil {
				t.Errorf("%s: revoke = %+v, want the same empty success as for any token", name, got.Failure)
			}
		}

		if !e.userinfoOK(tokens.AccessToken) || e.refresh(app, tokens.RefreshToken).Response == nil {
			t.Error("a client revoked a grant that is not its own")
		}
	})

	t.Run("anything else is a success that does nothing", func(t *testing.T) {
		fake, _, _ := e.secrets.NewOIDCSecret()
		for _, token := range []string{"", "junk", fake, "a.b.c", e.signIn(alice)} {
			if got := revoke(app, token); got.Failure != nil {
				t.Errorf("token %q: %+v", token, got.Failure)
			}
		}
	})

	t.Run("the client must authenticate", func(t *testing.T) {
		tokens, _ := e.tokens(e.newFlow(app), alice)
		bad := app
		bad.secret, _, _ = e.secrets.NewOIDCSecret()
		got, err := e.revoke.Execute(context.Background(), appoidc.RevokeCommand{ClientID: bad.id, ClientSecret: bad.secret, Token: tokens.RefreshToken})
		must(t, err)

		if got.Failure == nil || got.Failure.Code != appoidc.ErrInvalidClient || !e.userinfoOK(tokens.AccessToken) {
			t.Errorf("revoke with a wrong secret = %+v", got)
		}
	})
}

func TestTheLogoutSettingsOfAClient(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")

	set := func(post []string, back string) error {
		return e.clients.SetLogout(context.Background(), app.id, post, back)
	}
	if err := set([]string{appLogoutReturn}, appBackchannel); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		post []string
		back string
	}{
		"http back-channel": {nil, "http://app.example.test/bc"},
		"a fragment":        {nil, "https://app.example.test/bc#x"},
		"credentials":       {nil, "https://u:p@app.example.test/bc"},
		"a wildcard return": {[]string{"https://*.example.test/out"}, ""},
		"a repeated return": {[]string{appLogoutReturn, appLogoutReturn}, ""},
		"eleven returns":    {make([]string, 11), ""},
	} {
		if err := set(tc.post, tc.back); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Replacing clears what is not given.
	if err := set(nil, ""); err != nil {
		t.Fatal(err)
	}

	if got := e.logoutOnce(appoidc.LogoutCommand{ClientID: "panels-web", PostLogoutRedirectURI: appLogoutReturn}); got.Kind != appoidc.LogoutFailure {
		t.Errorf("a cleared return address still works: %+v", got)
	}

	if err := e.clients.SetLogout(context.Background(), "nobody", nil, ""); err == nil {
		t.Error("settings were stored for a client that does not exist")
	}
}

// A confirmation that did not come from the page that asks ends nothing, even from a site the API trusts: the token is
// derived from the cookie, which another origin can neither read nor send.
func TestLogoutNeedsTheTokenOfTheConfirmationPage(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")

	_, sso := e.signedIn(e.newFlow(app), e.newPerson())
	for name, token := range map[string]string{"none": "", "guessed": "1", "another browser": "00" + strings.Repeat("a", 62)} {
		got, err := e.logout.Execute(context.Background(), appoidc.LogoutCommand{SSOSecret: sso, Confirm: true, ConfirmToken: token})
		must(t, err)

		if got.Kind != appoidc.LogoutFailure || got.SignedOut {
			t.Errorf("%s: %+v, want a refusal", name, got)
		}
	}

	if !e.opSessionOf(sso).RevokedAt.IsZero() {
		t.Fatal("a forged confirmation ended the sign-in")
	}

	if got := e.logoutOnce(appoidc.LogoutCommand{SSOSecret: sso, Confirm: true}); !got.SignedOut {
		t.Fatalf("the real confirmation = %+v", got)
	}
}
