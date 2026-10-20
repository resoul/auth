package bff_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The fake provider below is only for the cases a real one cannot be made to produce: a token with the wrong nonce, a key
// the set does not publish, a refresh that hangs. The sign-in, the SSO and the logout of the real service, with the same
// application, are run against the real provider in internal/bootstrap (TestBFFOnTheRealService).

var (
	keyOnce sync.Once
	keys    []*rsa.PrivateKey
)

func testKey(i int) *rsa.PrivateKey {
	keyOnce.Do(func() {
		for range 3 {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}

			keys = append(keys, k)
		}
	})

	return keys[i]
}

const (
	clientID     = "panels-web"
	clientSecret = "s3cr3t-of-the-client-0123456789abcdef"
	platformURI  = "https://api.example.test/platform"
	videoURI     = "https://video.example.test/api"
)

type grant struct {
	sub, sid string
	// token is the refresh token that is live; used are the ones that were spent.
	token string
	used  map[string]bool
	dead  bool
}

type provider struct {
	t   *testing.T
	srv *httptest.Server
	now func() time.Time

	mu       sync.Mutex
	kids     map[string]int // kid → index of the key; the first one signs
	signKID  string
	jwksHits int
	jwksDown bool
	jwksBig  bool
	jwksHost string // when set, the discovery document names a key set on this host

	codes    map[string]*codeInfo
	grants   map[string]*grant // by current refresh token and by every spent one
	access   map[string]string // access token → resource URI
	n        int
	nonceFor string // when set, the ID token carries this nonce instead of the request's
	audience string // when set, the ID token is for this audience
	expired  bool
	subject  string

	refreshHits   int
	replays       int
	refreshStatus int  // when non-zero, the refresh answers with it
	refreshLost   int  // when non-zero, the refresh rotates the token and the answer is replaced by this status on the way
	refreshHang   bool // the refresh closes the connection without an answer
	refreshes     []string
	revoked       []string
	issParam      bool
	onExchange    func(sid string)
	fixedSID      string // when set, every sign-in carries it: the provider's session survived
}

type codeInfo struct {
	challenge, redirect, nonce string
	used                       bool
}

func newProvider(t *testing.T, now func() time.Time) *provider {
	p := &provider{
		t: t, now: now, kids: map[string]int{"k1": 0}, signKID: "k1", codes: map[string]*codeInfo{}, grants: map[string]*grant{},
		access: map[string]string{}, subject: "0198f3a2-0000-7000-8000-000000000001", issParam: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /oauth2/jwks", p.jwks)
	mux.HandleFunc("POST /oauth2/token", p.token)
	mux.HandleFunc("POST /oauth2/revoke", p.revoke)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)

	return p
}

func (p *provider) issuer() string {
	return p.srv.URL
}

func (p *provider) discovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	jwks := p.srv.URL + "/oauth2/jwks"
	if p.jwksHost != "" {
		jwks = p.jwksHost + "/oauth2/jwks"
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/oauth2/authorize", "token_endpoint": p.srv.URL + "/oauth2/token",
		"jwks_uri": jwks, "end_session_endpoint": p.srv.URL + "/oauth2/logout", "revocation_endpoint": p.srv.URL + "/oauth2/revoke",
		"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "authorization_response_iss_parameter_supported": p.issParam,
	})
}

func (p *provider) jwks(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.jwksHits++
	if p.jwksDown {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	if p.jwksBig {
		_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("a", 200<<10) + `"}`))
		return
	}

	var set jose.JSONWebKeySet
	for kid, i := range p.kids {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: &testKey(i).PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"})
	}

	_ = json.NewEncoder(w).Encode(set)
}

func (p *provider) setKeys(kids map[string]int, signKID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.kids, p.signKID = kids, signKID
}

func (p *provider) hits() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.jwksHits
}

func (p *provider) random(prefix string) string {
	p.n++
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)

	return prefix + strconv.Itoa(p.n) + "-" + base64.RawURLEncoding.EncodeToString(raw)
}

// issue makes the code a provider would put in the address of the browser's return.
func (p *provider) issue(authorizeURL string) (code string) {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		p.t.Fatal(err)
	}

	q := u.Query()

	p.mu.Lock()
	defer p.mu.Unlock()

	code = p.random("code-")
	p.codes[code] = &codeInfo{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), nonce: q.Get("nonce")}

	return code
}

// sign makes a token of the given type with the claims, signed under kid (the provider's own, if empty).
func (p *provider) sign(typ, kid string, claims map[string]any, key *rsa.PrivateKey) string {
	if kid == "" {
		kid = p.signKID
	}

	if key == nil {
		key = testKey(p.kids[kid])
	}

	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		p.t.Fatal(err)
	}

	out, err := jwt.Signed(s).Claims(claims).Serialize()
	if err != nil {
		p.t.Fatal(err)
	}

	return out
}

func (p *provider) idToken(nonce, sid string) string {
	now := p.now()

	exp := now.Add(5 * time.Minute)
	if p.expired {
		exp = now.Add(-time.Hour)
	}

	aud := clientID
	if p.audience != "" {
		aud = p.audience
	}

	if p.nonceFor != "" {
		nonce = p.nonceFor
	}

	return p.sign("JWT", "", map[string]any{
		"iss": p.srv.URL, "sub": p.subject, "aud": aud, "exp": exp.Unix(), "iat": now.Unix(), "nonce": nonce, "sid": sid, "auth_time": now.Unix(),
	}, nil)
}

// logoutToken is the notice of a sign-in that ended, with every field the test may spoil.
func (p *provider) logoutToken(mutate func(c map[string]any, header *string)) string {
	now := p.now()
	c := map[string]any{
		"iss": p.srv.URL, "sub": p.subject, "aud": clientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": p.random("jti-"),
		"sid": "sid-1", "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}

	typ := "logout+jwt"
	if mutate != nil {
		mutate(c, &typ)
	}

	return p.sign(typ, "", c, nil)
}

func (p *provider) basicOK(r *http.Request) bool {
	id, secret, ok := r.BasicAuth()
	if !ok {
		return false
	}

	id, _ = url.QueryUnescape(id)
	secret, _ = url.QueryUnescape(secret)

	return id == clientID && secret == clientSecret
}

func oauthErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (p *provider) token(w http.ResponseWriter, r *http.Request) {
	if !p.basicOK(r) {
		oauthErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	_ = r.ParseForm()

	p.mu.Lock()
	defer p.mu.Unlock()

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		info := p.codes[r.PostForm.Get("code")]

		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if info == nil || info.used || info.redirect != r.PostForm.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != info.challenge {
			oauthErr(w, http.StatusBadRequest, "invalid_grant")
			return
		}

		info.used = true
		g := &grant{sub: p.subject, sid: p.newSID(), token: p.random("refresh-"), used: map[string]bool{}}
		p.grants[g.token] = g
		access := p.random("access-")
		p.access[access] = ""

		hook := p.onExchange
		defer func() {
			if hook != nil {
				// Before the application has stored anything: the notice for this sign-in overtakes the answer.
				p.mu.Unlock()
				hook(g.sid)
				p.mu.Lock()
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": access, "token_type": "Bearer", "expires_in": 300, "refresh_token": g.token, "id_token": p.idToken(info.nonce, g.sid),
		})
	case "refresh_token":
		p.refreshHits++
		if p.refreshHang {
			// The provider acts and the answer is lost on the way back.
			if g := p.grants[r.PostForm.Get("refresh_token")]; g != nil && !g.used[g.token] && g.token == r.PostForm.Get("refresh_token") {
				g.used[g.token] = true
				g.token = p.random("refresh-")
				p.grants[g.token] = g
			}

			hj, ok := w.(http.Hijacker)
			if !ok {
				return
			}

			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}

			return
		}

		if p.refreshLost != 0 {
			if g := p.grants[r.PostForm.Get("refresh_token")]; g != nil && !g.used[g.token] && g.token == r.PostForm.Get("refresh_token") {
				g.used[g.token] = true
				g.token = p.random("refresh-")
				p.grants[g.token] = g
			}

			w.WriteHeader(p.refreshLost)

			return
		}

		if p.refreshStatus != 0 {
			w.WriteHeader(p.refreshStatus)
			return
		}

		presented := r.PostForm.Get("refresh_token")

		g := p.grants[presented]
		if g == nil || g.dead {
			oauthErr(w, http.StatusBadRequest, "invalid_grant")
			return
		}

		if g.used[presented] || g.token != presented {
			p.replays++
			g.dead = true

			oauthErr(w, http.StatusBadRequest, "invalid_grant")

			return
		}

		resource := r.PostForm.Get("resource")
		if resource != platformURI && resource != videoURI {
			oauthErr(w, http.StatusBadRequest, "invalid_target")
			return
		}

		g.used[presented] = true
		g.token = p.random("refresh-")
		p.grants[g.token] = g
		access := p.random("access-")
		p.access[access] = resource
		p.refreshes = append(p.refreshes, resource)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300, "refresh_token": g.token})
	default:
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (p *provider) revoke(w http.ResponseWriter, r *http.Request) {
	if !p.basicOK(r) {
		oauthErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	_ = r.ParseForm()

	p.mu.Lock()
	defer p.mu.Unlock()

	p.revoked = append(p.revoked, r.PostForm.Get("token"))
	if g := p.grants[r.PostForm.Get("token")]; g != nil {
		g.dead = true
	}
}

// endGrants ends every grant, as the provider does when a sign-in ends.
func (p *provider) endGrants() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, g := range p.grants {
		g.dead = true
	}
}

func (p *provider) refreshCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.refreshHits
}

func (p *provider) replayCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.replays
}

// resourceOf tells which API an access token was issued for.
func (p *provider) resourceOf(token string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	r, ok := p.access[token]

	return r, ok
}

func (p *provider) newSID() string {
	if p.fixedSID != "" {
		return p.fixedSID
	}

	return p.random("sid-")
}
