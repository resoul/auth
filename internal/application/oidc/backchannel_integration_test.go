//go:build integration

package oidc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"go.airlance.org/auth/internal/adapter/oidclogout"
	appoidc "go.airlance.org/auth/internal/application/oidc"
	"go.airlance.org/auth/internal/application/port"
)

// receiver is a client's backend that takes logout notices.
type receiver struct {
	*httptest.Server
	mu     sync.Mutex
	tokens []string
	status int
	hits   int
}

func newReceiver(t *testing.T, status int) *receiver {
	t.Helper()

	r := &receiver{status: status}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()

		r.hits++

		_ = req.ParseForm()
		if req.Method == http.MethodPost && req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			r.tokens = append(r.tokens, req.PostForm.Get("logout_token"))
		}

		w.WriteHeader(r.status)
	}))
	t.Cleanup(r.Close)

	return r
}

func (r *receiver) set(status int) {
	r.mu.Lock()
	r.status = status
	r.mu.Unlock()
}

func (r *receiver) got() (hits int, tokens []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.hits, append([]string(nil), r.tokens...)
}

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

func (e *env) worker(allow []netip.Prefix) *oidclogout.Worker {
	e.t.Helper()
	w, err := oidclogout.NewWorker(oidclogout.Deps{
		UnitOfWork: e.store, Clock: e.clock, Signer: e.signer, HTTP: oidclogout.NewHTTPClient(allow, 3*time.Second),
		Logger: discardLogger(), Policy: oidclogout.DefaultPolicy(),
	})
	must(e.t, err)

	return w
}

// drain runs the worker until nothing is due and returns how many notices it handled.
func drain(t *testing.T, w *oidclogout.Worker) int {
	t.Helper()

	n := 0

	for range 50 {
		done, err := w.ProcessNext(context.Background())
		must(t, err)

		if !done {
			return n
		}

		n++
	}

	t.Fatal("the worker never ran out of notices")

	return n
}

// signedOutWith signs a person in to an application whose back-channel address is the receiver's, then ends the sign-in.
func (e *env) signedOutWith(r *receiver) (opID string) {
	e.t.Helper()
	app := e.registerWithLogout("panels-web", appCallback, "", r.URL)
	_, sso := e.tokens(e.newFlow(app), e.newPerson())

	opID = e.opSessionOf(sso).ID
	if got := e.logoutOnce(appoidc.LogoutCommand{SSOSecret: sso, Confirm: true}); !got.SignedOut {
		e.t.Fatalf("logout = %+v", got)
	}

	return opID
}

func TestALogoutNoticeIsDeliveredWithAProperLogoutToken(t *testing.T) {
	e := newEnv(t)
	r := newReceiver(t, http.StatusOK)
	opID := e.signedOutWith(r)

	if n := drain(t, e.worker(loopback)); n != 1 {
		t.Fatalf("the worker handled %d notices, want 1", n)
	}

	hits, tokens := r.got()
	if hits != 1 || len(tokens) != 1 {
		t.Fatalf("the client was called %d times with %d tokens, want once", hits, len(tokens))
	}

	parsed, err := josejwt.ParseSigned(tokens[0], []jose.SignatureAlgorithm{jose.RS256})
	must(t, err)

	if typ := parsed.Headers[0].ExtraHeaders[jose.HeaderType]; typ != "logout+jwt" {
		t.Errorf("typ = %v, want logout+jwt", typ)
	}

	var claims map[string]any
	must(t, parsed.Claims(e.oidcKeys.PublicKeys()["oidc-a"], &claims))

	events, _ := claims["events"].(map[string]any)
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok || len(events) != 1 {
		t.Errorf("events = %v", claims["events"])
	}

	if claims["iss"] != issuer || claims["aud"] != "panels-web" || claims["sid"] != opID || claims["sub"] == nil || claims["jti"] == nil {
		t.Errorf("logout token claims = %v", claims)
	}

	if _, ok := claims["nonce"]; ok {
		t.Error("a logout token has a nonce: it could pass for an ID token")
	}

	if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != 120 {
		t.Errorf("lifetime = %vs, want 120", exp-iat)
	}
	// It is not an access token or an ID token anywhere else.
	if _, err := e.signer.VerifyOIDCAccess(tokens[0], e.userInfoAudience()); err == nil {
		t.Error("a logout token passed for an access token")
	}

	if _, err := e.signer.VerifyIDTokenHint(tokens[0]); err == nil {
		t.Error("a logout token passed for an ID token hint")
	}
	// Delivered means done: nothing is queued any more.
	e.clock.Advance(24 * time.Hour)

	if n := drain(t, e.worker(loopback)); n != 0 {
		t.Errorf("a delivered notice was handled again (%d)", n)
	}
}

func (e *env) userInfoAudience() string {
	return issuer + "/oauth2/userinfo"
}

func TestANoticeThatFailsIsRetriedWithTheSameIdentifier(t *testing.T) {
	e := newEnv(t)
	r := newReceiver(t, http.StatusServiceUnavailable)
	e.signedOutWith(r)
	w := e.worker(loopback)

	if n := drain(t, w); n != 1 {
		t.Fatalf("first run handled %d", n)
	}
	// Not due again at once; due after the first backoff.
	if n := drain(t, w); n != 0 {
		t.Errorf("a failed notice was retried at once (%d)", n)
	}

	e.clock.Advance(59 * time.Second)

	if n := drain(t, w); n != 0 {
		t.Errorf("a failed notice was retried before its backoff (%d)", n)
	}

	e.clock.Advance(2 * time.Second)
	r.set(http.StatusNoContent) // the client is back

	if n := drain(t, w); n != 1 {
		t.Fatalf("after the backoff handled %d", n)
	}

	hits, tokens := r.got()
	if hits != 2 || len(tokens) != 2 {
		t.Fatalf("calls = %d, tokens = %d, want 2", hits, len(tokens))
	}

	jti := func(token string) any {
		parsed, _ := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})

		var c map[string]any

		_ = parsed.Claims(e.oidcKeys.PublicKeys()["oidc-a"], &c)

		return c["jti"]
	}
	if jti(tokens[0]) != jti(tokens[1]) {
		t.Error("the two deliveries of one notice carry different jti: the client cannot tell they are the same")
	}

	if tokens[0] == tokens[1] {
		t.Error("a retry reused the same token (and its expiry)")
	}

	e.clock.Advance(24 * time.Hour)

	if n := drain(t, w); n != 0 {
		t.Errorf("a delivered notice was handled again (%d)", n)
	}
}

func TestANoticeIsGivenUpWhenTheClientRefusesItOrNeverAnswers(t *testing.T) {
	t.Run("the client says 400", func(t *testing.T) {
		e := newEnv(t)
		r := newReceiver(t, http.StatusBadRequest)
		e.signedOutWith(r)
		w := e.worker(loopback)
		drain(t, w)
		e.clock.Advance(7 * time.Hour)
		drain(t, w)

		if hits, _ := r.got(); hits != 1 {
			t.Errorf("a refused notice was sent %d times, want once", hits)
		}
	})

	t.Run("the client never answers", func(t *testing.T) {
		e := newEnv(t)
		r := newReceiver(t, http.StatusInternalServerError)
		e.signedOutWith(r)
		w := e.worker(loopback)
		attempts := 0

		for range 40 {
			drain(t, w)

			hits, _ := r.got()
			attempts = hits

			e.clock.Advance(3 * time.Hour)
		}

		if attempts < 4 || attempts > 12 {
			t.Errorf("%d attempts over a day and more, want a handful", attempts)
		}

		before, _ := r.got()

		e.clock.Advance(24 * time.Hour)
		drain(t, w)

		if after, _ := r.got(); after != before {
			t.Error("the worker went on after the notice expired")
		}
	})

	t.Run("a redirect is not followed", func(t *testing.T) {
		e := newEnv(t)
		elsewhere := newReceiver(t, http.StatusOK)
		redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, elsewhere.URL, http.StatusTemporaryRedirect)
		}))
		t.Cleanup(redirecting.Close)
		app := e.registerWithLogout("panels-web", appCallback, "", redirecting.URL)
		_, sso := e.tokens(e.newFlow(app), e.newPerson())
		e.logoutOnce(appoidc.LogoutCommand{SSOSecret: sso, Confirm: true})
		drain(t, e.worker(loopback))

		if hits, _ := elsewhere.got(); hits != 0 {
			t.Error("the notice followed a redirect to an address nobody checked")
		}
	})
}

func TestNoticesDoNotReachInternalAddressesUnlessTheOperatorAllowedThem(t *testing.T) {
	e := newEnv(t)
	r := newReceiver(t, http.StatusOK) // on 127.0.0.1
	e.signedOutWith(r)

	drain(t, e.worker(nil)) // no allowed networks

	if hits, _ := r.got(); hits != 0 {
		t.Fatal("a notice was sent to the loopback address with nothing allowed")
	}
	// It was given up for good, not left to retry: allowing the network later does not revive an old notice.
	e.clock.Advance(24 * time.Hour)
	drain(t, e.worker(loopback))

	if hits, _ := r.got(); hits != 0 {
		t.Error("a notice that was refused as blocked was delivered later")
	}

	// A network the operator did not list does not help.
	e2 := newEnv(t)
	r2 := newReceiver(t, http.StatusOK)
	e2.signedOutWith(r2)
	drain(t, e2.worker([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}))

	if hits, _ := r2.got(); hits != 0 {
		t.Error("an unrelated allowed network let a notice through")
	}
}

func TestADisabledClientIsNotTold(t *testing.T) {
	e := newEnv(t)
	r := newReceiver(t, http.StatusOK)
	app := e.registerWithLogout("panels-web", appCallback, "", r.URL)
	_, sso := e.tokens(e.newFlow(app), e.newPerson())
	e.logoutOnce(appoidc.LogoutCommand{SSOSecret: sso, Confirm: true})
	must(t, e.clients.SetActive(context.Background(), app.id, false))

	drain(t, e.worker(loopback))

	if hits, _ := r.got(); hits != 0 {
		t.Error("a disabled client was told about a logout")
	}

	// Nor when its endpoint was removed after the notice was queued.
	e2 := newEnv(t)
	r2 := newReceiver(t, http.StatusOK)
	app2 := e2.registerWithLogout("panels-web", appCallback, "", r2.URL)
	_, sso2 := e2.tokens(e2.newFlow(app2), e2.newPerson())
	e2.logoutOnce(appoidc.LogoutCommand{SSOSecret: sso2, Confirm: true})
	must(t, e2.clients.SetLogout(context.Background(), app2.id, nil, ""))
	drain(t, e2.worker(loopback))

	if hits, _ := r2.got(); hits != 0 {
		t.Error("a notice was sent to an endpoint the client no longer has")
	}
}

func TestTwoWorkersNeverTakeTheSameNotice(t *testing.T) {
	e := newEnv(t)
	r := newReceiver(t, http.StatusOK)

	app := e.registerWithLogout("panels-web", appCallback, "", r.URL)
	for range 6 {
		_, sso := e.tokens(e.newFlow(app), e.newPerson())
		e.logoutOnce(appoidc.LogoutCommand{SSOSecret: sso, Confirm: true})
	}

	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			drain(t, e.worker(loopback))
		}()
	}

	wg.Wait()

	if hits, _ := r.got(); hits != 6 {
		t.Errorf("the client was told %d times for 6 sign-ins ended: a notice was lost or sent twice", hits)
	}
}

var _ = port.ErrNotFound
