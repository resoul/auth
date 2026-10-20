package oidc_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/oidc"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func TestPKCE(t *testing.T) {
	verifier := strings.Repeat("a", 43)

	challenge := oidc.Challenge(verifier)
	if !oidc.ValidChallenge(challenge) || len(challenge) != 43 {
		t.Fatalf("challenge %q", challenge)
	}
	// RFC 7636 appendix B.
	if got := oidc.Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("the RFC's example gives %q", got)
	}

	if !oidc.VerifyPKCE(challenge, verifier) {
		t.Error("the right verifier was refused")
	}

	for name, v := range map[string]string{
		"empty": "", "too short": strings.Repeat("a", 42), "too long": strings.Repeat("a", 129), "bad characters": strings.Repeat("a", 42) + "!",
		"the challenge itself": challenge, "another": strings.Repeat("b", 43),
	} {
		if oidc.VerifyPKCE(challenge, v) {
			t.Errorf("%s verifier accepted", name)
		}
	}

	for _, bad := range []string{"", "short", strings.Repeat("a", 44), strings.Repeat("=", 43), strings.Repeat("a", 42) + "+"} {
		if oidc.ValidChallenge(bad) || oidc.VerifyPKCE(bad, verifier) {
			t.Errorf("challenge %q accepted", bad)
		}
	}
}

func TestScopes(t *testing.T) {
	for raw, want := range map[string]string{"openid": "openid", "openid email": "openid email", "email openid": "email openid"} {
		got, err := oidc.ParseScopes(raw)
		if err != nil || strings.Join(got, " ") != want {
			t.Errorf("%q = %v, %v", raw, got, err)
		}
	}

	for _, bad := range []string{"", " ", "email", "openid ", " openid", "openid  email", "openid openid", "openid profile", "openid offline_access", "openid\temail", "OPENID"} {
		if _, err := oidc.ParseScopes(bad); !errors.Is(err, oidc.ErrInvalidScope) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

func TestClientRegistration(t *testing.T) {
	ok := oidc.NewClientParams{ID: "panels-web", Name: "Panels", RedirectURIs: []string{"https://panels.example.com/cb"}, Trusted: true}

	c, err := oidc.NewClient(ok, now)
	if err != nil || c.PolicyVersion != 1 || !c.Active() || strings.Join(c.AllowedScopes, " ") != "openid email" {
		t.Fatalf("client = %+v, %v", c, err)
	}

	if !c.AllowsRedirect("https://panels.example.com/cb") {
		t.Error("the registered address is refused")
	}

	for _, other := range []string{"https://panels.example.com/cb/", "https://panels.example.com/CB", "https://panels.example.com/cb?x=1", "https://panels.example.com", "http://panels.example.com/cb", "https://panels.example.com.evil/cb", ""} {
		if c.AllowsRedirect(other) {
			t.Errorf("%q matched: comparison must be exact", other)
		}
	}

	for name, mutate := range map[string]func(*oidc.NewClientParams){
		"not trusted":      func(p *oidc.NewClientParams) { p.Trusted = false },
		"upper-case id":    func(p *oidc.NewClientParams) { p.ID = "Panels" },
		"a short id":       func(p *oidc.NewClientParams) { p.ID = "ab" },
		"a dot in the id":  func(p *oidc.NewClientParams) { p.ID = "panels.web" },
		"no name":          func(p *oidc.NewClientParams) { p.Name = "" },
		"no redirect":      func(p *oidc.NewClientParams) { p.RedirectURIs = nil },
		"eleven redirects": func(p *oidc.NewClientParams) { p.RedirectURIs = make([]string, 11) },
		"a repeated redirect": func(p *oidc.NewClientParams) {
			p.RedirectURIs = []string{"https://a.example.com/cb", "https://a.example.com/cb"}
		},
		"http":             func(p *oidc.NewClientParams) { p.RedirectURIs = []string{"http://a.example.com/cb"} },
		"a wildcard":       func(p *oidc.NewClientParams) { p.RedirectURIs = []string{"https://*.example.com/cb"} },
		"a fragment":       func(p *oidc.NewClientParams) { p.RedirectURIs = []string{"https://a.example.com/cb#x"} },
		"credentials":      func(p *oidc.NewClientParams) { p.RedirectURIs = []string{"https://u:p@a.example.com/cb"} },
		"relative":         func(p *oidc.NewClientParams) { p.RedirectURIs = []string{"/cb"} },
		"a custom scheme":  func(p *oidc.NewClientParams) { p.RedirectURIs = []string{"app://cb"} },
		"a space":          func(p *oidc.NewClientParams) { p.RedirectURIs = []string{"https://a.example.com/c b"} },
		"a backslash":      func(p *oidc.NewClientParams) { p.RedirectURIs = []string{`https://a.example.com\@evil/cb`} },
		"an unknown scope": func(p *oidc.NewClientParams) { p.AllowedScopes = []string{"openid", "admin"} },
		"no openid":        func(p *oidc.NewClientParams) { p.AllowedScopes = []string{"email"} },
		"a repeated scope": func(p *oidc.NewClientParams) { p.AllowedScopes = []string{"openid", "openid"} },
	} {
		p := ok
		p.RedirectURIs = append([]string(nil), ok.RedirectURIs...)
		mutate(&p)

		if _, err := oidc.NewClient(p, now); err == nil {
			t.Errorf("%s: registered", name)
		}
	}

	for _, local := range []string{"http://localhost:3000/cb", "http://127.0.0.1:8080/cb", "http://[::1]:8080/cb"} {
		p := ok

		p.RedirectURIs = []string{local}
		if _, err := oidc.NewClient(p, now); err != nil {
			t.Errorf("%s: %v", local, err)
		}
	}
}

func TestGrantableScopes(t *testing.T) {
	c, _ := oidc.NewClient(oidc.NewClientParams{ID: "narrow-app", Name: "n", RedirectURIs: []string{"https://a.example.com/cb"}, AllowedScopes: []string{"openid"}, Trusted: true}, now)
	if _, err := c.Grantable([]string{"openid"}); err != nil {
		t.Error(err)
	}

	if _, err := c.Grantable([]string{"openid", "email"}); !errors.Is(err, oidc.ErrInvalidScope) {
		t.Errorf("a scope the client was not given: %v", err)
	}
}

func TestAuthorizationCodeExchange(t *testing.T) {
	verifier := strings.Repeat("v", 43)

	fresh := func() *oidc.AuthorizationCode {
		return &oidc.AuthorizationCode{RedirectURI: "https://a.example.com/cb", CodeChallenge: oidc.Challenge(verifier), ExpiresAt: now.Add(time.Minute)}
	}
	if c := fresh(); c.Exchange(now, "https://a.example.com/cb", verifier) != nil || c.ConsumedAt.IsZero() {
		t.Error("a good exchange did not consume the code")
	}

	for name, tc := range map[string]struct {
		redirect, verifier string
		at                 time.Time
		want               error
	}{
		"another redirect": {"https://a.example.com/other", verifier, now, oidc.ErrRedirectMismatch},
		"a wrong verifier": {"https://a.example.com/cb", strings.Repeat("w", 43), now, oidc.ErrPKCE},
		"no verifier":      {"https://a.example.com/cb", "", now, oidc.ErrPKCE},
		"expired":          {"https://a.example.com/cb", verifier, now.Add(time.Minute), oidc.ErrCodeExpired},
		"long expired":     {"https://a.example.com/cb", verifier, now.Add(time.Hour), oidc.ErrCodeExpired},
	} {
		c := fresh()
		if err := c.Exchange(tc.at, tc.redirect, tc.verifier); !errors.Is(err, tc.want) || !c.ConsumedAt.IsZero() {
			t.Errorf("%s: %v, consumed %v; want %v and the code untouched", name, err, c.ConsumedAt, tc.want)
		}
	}

	c := fresh()

	_ = c.Exchange(now, "https://a.example.com/cb", verifier)
	if err := c.Exchange(now, "https://a.example.com/cb", verifier); !errors.Is(err, oidc.ErrCodeReplayed) {
		t.Errorf("a second exchange: %v", err)
	}
}

func TestRefreshTokenExchange(t *testing.T) {
	fresh := func() *oidc.RefreshToken { return &oidc.RefreshToken{ExpiresAt: now.Add(time.Hour)} }
	if tok := fresh(); tok.Exchange(now) != nil || tok.UsedAt.IsZero() {
		t.Error("a good exchange did not mark the token used")
	}

	tok := fresh()

	_ = tok.Exchange(now)
	if err := tok.Exchange(now); !errors.Is(err, oidc.ErrRefreshReplayed) {
		t.Errorf("a second exchange: %v", err)
	}

	if err := (&oidc.RefreshToken{ExpiresAt: now}).Exchange(now); !errors.Is(err, oidc.ErrRefreshExpired) {
		t.Errorf("an expired token: %v", err)
	}
	// Revoked wins over used: a revoked token is not a replay.
	revoked := &oidc.RefreshToken{ExpiresAt: now.Add(time.Hour), RevokedAt: now, UsedAt: now}
	if err := revoked.Exchange(now); !errors.Is(err, oidc.ErrRefreshRevoked) {
		t.Errorf("a revoked token: %v", err)
	}
}

func TestAnAuthenticationMustMeetTheRequest(t *testing.T) {
	req := func(fresh bool, maxAge *int) *oidc.AuthorizationRequest {
		return &oidc.AuthorizationRequest{CreatedAt: now, FreshLogin: fresh, MaxAge: maxAge}
	}
	secs := func(n int) *int { return &n }

	before, long := now.Add(-time.Minute), now.Add(-time.Hour)
	for name, tc := range map[string]struct {
		r    *oidc.AuthorizationRequest
		auth time.Time
		want bool
	}{
		"nothing asked":              {req(false, nil), long, true},
		"fresh asked, old proof":     {req(true, nil), before, false},
		"fresh asked, new proof":     {req(true, nil), now, true},
		"max_age 0 is a fresh login": {req(false, secs(0)), before, false},
		"max_age met":                {req(false, secs(7200)), long, true},
		"max_age exceeded":           {req(false, secs(60)), long, false},
		"max_age on the edge":        {req(false, secs(60)), now.Add(-time.Minute), true},
	} {
		if got := tc.r.Satisfied(tc.auth, now); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

func TestRequestUsability(t *testing.T) {
	var mine, other oidc.SecretHash

	mine[0], other[0] = 1, 2

	r := &oidc.AuthorizationRequest{Binding: mine, ExpiresAt: now.Add(time.Minute)}
	if !r.Usable(now, mine) {
		t.Error("the owner cannot use its request")
	}

	if r.Usable(now, other) || r.Usable(now.Add(time.Minute), mine) {
		t.Error("another browser, or an expired request, can use it")
	}

	r.CompletedAt = now
	if r.Usable(now, mine) {
		t.Error("a completed request can be used again")
	}
}

func TestSessionAndGrantLifetimes(t *testing.T) {
	p := oidc.DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	bad := p

	bad.OPSessionIdle = p.OPSessionAbsolute + time.Hour
	if bad.Validate() == nil {
		t.Error("an idle time past the absolute one was accepted")
	}

	bad = p

	bad.CodeTTL = 0
	if bad.Validate() == nil {
		t.Error("a zero lifetime was accepted")
	}

	s := &oidc.OPSession{LastSeenAt: now, ExpiresAt: now.Add(p.OPSessionAbsolute)}
	if !s.Active(now, p) || s.Active(now.Add(p.OPSessionIdle), p) || s.Active(s.ExpiresAt, p) {
		t.Error("session activity does not follow the idle and absolute times")
	}

	s.RevokedAt = now
	if s.Active(now, p) {
		t.Error("a revoked session is active")
	}

	// A grant never outlives its sign-in, and a refresh token never outlives its grant.
	short := &oidc.OPSession{ExpiresAt: now.Add(time.Hour)}
	if end := oidc.GrantExpiry(now, p, short); !end.Equal(now.Add(time.Hour)) {
		t.Errorf("grant expiry = %v, want the end of the sign-in", end)
	}

	long := &oidc.OPSession{ExpiresAt: now.Add(1000 * time.Hour * 24)}
	if end := oidc.GrantExpiry(now, p, long); !end.Equal(now.Add(p.RefreshAbsolute)) {
		t.Errorf("grant expiry = %v, want the absolute refresh time", end)
	}

	g := &oidc.Grant{ExpiresAt: now.Add(2 * time.Hour)}
	if end := oidc.RefreshExpiry(now, p, g); !end.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("refresh expiry = %v, want the end of the grant", end)
	}

	if end := oidc.RefreshExpiry(now, p, &oidc.Grant{ExpiresAt: now.Add(1000 * time.Hour * 24)}); !end.Equal(now.Add(p.RefreshIdle)) {
		t.Errorf("refresh expiry = %v, want the idle time", end)
	}
}

func TestSecretHashes(t *testing.T) {
	var h oidc.SecretHash
	if !h.IsZero() {
		t.Error("the zero hash is not zero")
	}

	h[3] = 9

	back, err := oidc.SecretHashFrom(h.Bytes())
	if err != nil || back != h {
		t.Errorf("round trip = %v, %v", back, err)
	}

	if _, err := oidc.SecretHashFrom([]byte("short")); err == nil {
		t.Error("a short hash was accepted")
	}
}

func TestLogoutSettingsFollowTheRulesOfRedirectAddresses(t *testing.T) {
	c, err := oidc.NewClient(oidc.NewClientParams{
		ID: "panels-web", Name: "Panels", RedirectURIs: []string{"https://a.example.com/cb"}, Trusted: true,
		PostLogoutRedirectURIs: []string{"https://a.example.com/out"}, BackchannelLogoutURI: "https://a.example.com/bc",
	}, now)
	if err != nil || !c.AllowsPostLogoutRedirect("https://a.example.com/out") || c.AllowsPostLogoutRedirect("https://a.example.com/out/") || c.AllowsPostLogoutRedirect("https://a.example.com/cb") {
		t.Fatalf("client = %+v, %v", c, err)
	}

	for name, tc := range map[string]struct {
		post []string
		back string
	}{
		"http back-channel": {nil, "http://a.example.com/bc"}, "a wildcard": {[]string{"https://*.example.com/out"}, ""}, "a fragment": {[]string{"https://a.example.com/o#x"}, ""},
		"credentials": {nil, "https://u:p@a.example.com/bc"}, "a repeat": {[]string{"https://a.example.com/o", "https://a.example.com/o"}, ""}, "eleven": {make([]string, 11), ""},
		"relative": {nil, "/bc"},
	} {
		if err := c.SetLogout(tc.post, tc.back, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if !c.AllowsPostLogoutRedirect("https://a.example.com/out") || c.BackchannelLogoutURI != "https://a.example.com/bc" {
		t.Error("a refused change altered the client")
	}

	if err := c.SetLogout(nil, "", now); err != nil || c.AllowsPostLogoutRedirect("https://a.example.com/out") || c.BackchannelLogoutURI != "" {
		t.Errorf("clearing = %v, %+v", err, c)
	}

	for _, local := range []string{"http://localhost:3000/bc", "http://127.0.0.1:3000/bc"} {
		if err := c.SetLogout(nil, local, now); err != nil {
			t.Errorf("%s: %v", local, err)
		}
	}
}

func TestAServiceIdentityHasANameAndNothingToSignInWith(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

	c, err := oidc.NewClient(oidc.NewClientParams{ID: "billing-worker", Name: "Billing", Trusted: true, Service: true}, now)
	if err != nil {
		t.Fatal(err)
	}

	if !c.Service() || c.Kind != oidc.ClientService || !c.Active() || len(c.RedirectURIs) != 0 || len(c.AllowedScopes) != 0 {
		t.Errorf("service = %+v", c)
	}

	for name, p := range map[string]oidc.NewClientParams{
		"redirect addresses": {ID: "billing-worker", Name: "B", Trusted: true, Service: true, RedirectURIs: []string{"https://a.example.test/cb"}},
		"scopes":             {ID: "billing-worker", Name: "B", Trusted: true, Service: true, AllowedScopes: []string{oidc.ScopeOpenID}},
		"logout settings":    {ID: "billing-worker", Name: "B", Trusted: true, Service: true, BackchannelLogoutURI: "https://a.example.test/bc"},
		"a third party":      {ID: "billing-worker", Name: "B", Service: true},
		"no name":            {ID: "billing-worker", Trusted: true, Service: true},
	} {
		if _, err := oidc.NewClient(p, now); err == nil {
			t.Errorf("a service with %s was registered", name)
		}
	}

	app, err := oidc.NewClient(oidc.NewClientParams{ID: "panels-web", Name: "Panels", Trusted: true, RedirectURIs: []string{"https://a.example.test/cb"}}, now)
	if err != nil || app.Service() || app.Kind != oidc.ClientApplication {
		t.Errorf("application = %+v, %v", app, err)
	}
}
