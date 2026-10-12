package oidc_test

import (
	"errors"
	"strings"
	"testing"

	"airlance.org/auth/internal/domain/oidc"
)

func platform(t *testing.T) *oidc.Resource {
	t.Helper()
	r, err := oidc.NewResource(oidc.NewResourceParams{
		ID: "platform-api", Name: "Platform", URI: "https://api.example.com/platform", Audience: "platform-api",
		Scopes: []string{"messages:read", "messages:send", "video:read", "video:upload"},
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResourceRegistration(t *testing.T) {
	r := platform(t)
	if r.PolicyVersion != 1 || !r.Active() || !r.Defines("video:upload") || r.Defines("video") {
		t.Fatalf("resource = %+v", r)
	}
	ok := oidc.NewResourceParams{ID: "messenger-api", Name: "Messenger", URI: "https://api.example.com/messenger", Audience: "messenger-api", Scopes: []string{"messages:send"}}
	bad := map[string]func(p *oidc.NewResourceParams){
		"short id":         func(p *oidc.NewResourceParams) { p.ID = "ab" },
		"upper id":         func(p *oidc.NewResourceParams) { p.ID = "Messenger" },
		"no name":          func(p *oidc.NewResourceParams) { p.Name = "" },
		"relative uri":     func(p *oidc.NewResourceParams) { p.URI = "/messenger" },
		"fragment":         func(p *oidc.NewResourceParams) { p.URI = "https://api.example.com/m#x" },
		"query":            func(p *oidc.NewResourceParams) { p.URI = "https://api.example.com/m?a=b" },
		"empty query":      func(p *oidc.NewResourceParams) { p.URI = "https://api.example.com/m?" },
		"plain http":       func(p *oidc.NewResourceParams) { p.URI = "http://api.example.com/m" },
		"credentials":      func(p *oidc.NewResourceParams) { p.URI = "https://u:p@api.example.com/m" },
		"audience spaces":  func(p *oidc.NewResourceParams) { p.Audience = "two words" },
		"audience empty":   func(p *oidc.NewResourceParams) { p.Audience = "" },
		"audience long":    func(p *oidc.NewResourceParams) { p.Audience = strings.Repeat("a", 257) },
		"audience hash":    func(p *oidc.NewResourceParams) { p.Audience = "api#x" },
		"no scopes":        func(p *oidc.NewResourceParams) { p.Scopes = nil },
		"protocol scope":   func(p *oidc.NewResourceParams) { p.Scopes = []string{"openid"} },
		"no namespace":     func(p *oidc.NewResourceParams) { p.Scopes = []string{"send"} },
		"comma separated":  func(p *oidc.NewResourceParams) { p.Scopes = []string{"messages:read,messages:send"} },
		"upper case scope": func(p *oidc.NewResourceParams) { p.Scopes = []string{"Messages:send"} },
		"repeated scope":   func(p *oidc.NewResourceParams) { p.Scopes = []string{"messages:send", "messages:send"} },
		"too many scopes": func(p *oidc.NewResourceParams) {
			p.Scopes = nil
			for i := range 33 {
				p.Scopes = append(p.Scopes, "messages:s"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26)))
			}
		},
	}
	if _, err := oidc.NewResource(ok, now); err != nil {
		t.Fatalf("a valid registration was refused: %v", err)
	}
	for name, mutate := range bad {
		p := ok
		mutate(&p)
		if _, err := oidc.NewResource(p, now); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	local := ok
	local.URI = "http://localhost:8081/messenger"
	if _, err := oidc.NewResource(local, now); err != nil {
		t.Errorf("a localhost resource was refused: %v", err)
	}
}

func TestSetScopesReportsWhatWasTakenAway(t *testing.T) {
	r := platform(t)
	removed, err := r.SetScopes([]string{"messages:read", "video:read", "calendar:read"}, now)
	if err != nil || strings.Join(removed, " ") != "messages:send video:upload" || r.Defines("messages:send") || !r.Defines("calendar:read") {
		t.Fatalf("removed = %v, %v, scopes = %v", removed, err, r.Scopes)
	}
	if _, err := r.SetScopes(nil, now); err == nil {
		t.Error("an empty catalog was accepted")
	}
}

func TestScopeRequest(t *testing.T) {
	got, err := oidc.ParseScopeRequest("openid messages:send email video:read")
	if err != nil || strings.Join(got.Protocol, " ") != "openid email" || strings.Join(got.API, " ") != "messages:send video:read" {
		t.Fatalf("got %+v, %v", got, err)
	}
	for _, bad := range []string{
		"", " ", "messages:send", "openid ", " openid", "openid  email", "openid openid", "openid messages:send messages:send",
		"openid,messages:send", "openid messages:send,messages:read", "openid MESSAGES:SEND", "openid profile", "openid offline_access",
		"openid\tmessages:send", "openid messages:", "openid :send", strings.Repeat("openid ", 200),
	} {
		if _, err := oidc.ParseScopeRequest(bad); !errors.Is(err, oidc.ErrInvalidScope) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	// Scopes are compared as whole elements: a longer scope is not the shorter one.
	if scopes, err := oidc.ParseAPIScopes("messages:send:any"); err != nil || oidc.Intersect(scopes, []string{"messages:send"}) != nil {
		t.Errorf("messages:send:any counted as messages:send: %v, %v", scopes, err)
	}
	if _, err := oidc.ParseAPIScopes("openid"); err == nil {
		t.Error("a protocol scope was accepted for a resource token")
	}
}

func TestResourceURIs(t *testing.T) {
	if got, err := oidc.ParseResourceURIs([]string{"https://a.example.com/x", "https://b.example.com/y"}); err != nil || len(got) != 2 {
		t.Fatalf("%v, %v", got, err)
	}
	for name, raw := range map[string][]string{
		"repeated":  {"https://a.example.com/x", "https://a.example.com/x"},
		"not a uri": {"api"},
		"query":     {"https://a.example.com/x?y=1"},
		"too many":  {"https://a.example.com/1", "https://a.example.com/2", "https://a.example.com/3", "https://a.example.com/4", "https://a.example.com/5", "https://a.example.com/6"},
	} {
		if _, err := oidc.ParseResourceURIs(raw); !errors.Is(err, oidc.ErrInvalidTarget) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestAgreeScopes(t *testing.T) {
	platformAPI := platform(t)
	video, err := oidc.NewResource(oidc.NewResourceParams{ID: "video-api", Name: "Video", URI: "https://video.example.com/", Audience: "video-api", Scopes: []string{"video:read", "video:upload"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string][]string{"platform-api": {"messages:read", "messages:send"}, "video-api": {"video:read"}}

	got, err := oidc.AgreeScopes([]*oidc.Resource{platformAPI, video}, perms, []string{"messages:send", "video:read"})
	if err != nil || len(got) != 2 || strings.Join(got[0].Scopes, " ") != "messages:send" || strings.Join(got[1].Scopes, " ") != "video:read" {
		t.Fatalf("got %+v, %v", got, err)
	}

	for name, tc := range map[string]struct {
		resources []*oidc.Resource
		api       []string
		want      error
	}{
		"a scope the client was not allowed": {[]*oidc.Resource{platformAPI}, []string{"video:upload"}, oidc.ErrInvalidScope},
		"a scope of no requested resource":   {[]*oidc.Resource{video}, []string{"video:read", "messages:send"}, oidc.ErrInvalidScope},
		"a resource without a right":         {[]*oidc.Resource{platformAPI, video}, []string{"messages:send"}, oidc.ErrInvalidScope},
		"scopes without a resource":          {nil, []string{"messages:send"}, oidc.ErrInvalidScope},
		"a resource without scopes":          {[]*oidc.Resource{platformAPI}, nil, oidc.ErrInvalidScope},
		"a resource the client has no right": {[]*oidc.Resource{platformAPI, mustResource(t, "other-api", "other-api", "other:read")}, []string{"messages:send", "other:read"}, oidc.ErrInvalidTarget},
	} {
		if _, err := oidc.AgreeScopes(tc.resources, perms, tc.api); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// openid alone: nothing to agree.
	if got, err := oidc.AgreeScopes(nil, perms, nil); err != nil || got != nil {
		t.Errorf("no resources: %v, %v", got, err)
	}
	// A scope the resource no longer defines is not granted even if the client was allowed it.
	if _, err := platformAPI.SetScopes([]string{"messages:read", "video:read"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := oidc.AgreeScopes([]*oidc.Resource{platformAPI}, perms, []string{"messages:send"}); !errors.Is(err, oidc.ErrInvalidScope) {
		t.Errorf("a removed scope was agreed: %v", err)
	}
}

func mustResource(t *testing.T, id, audience string, scopes ...string) *oidc.Resource {
	t.Helper()
	r, err := oidc.NewResource(oidc.NewResourceParams{ID: id, Name: id, URI: "https://" + id + ".example.com/", Audience: audience, Scopes: scopes}, now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCoversResources(t *testing.T) {
	granted := []oidc.ResourceScopes{{ResourceID: "platform-api", Scopes: []string{"messages:read", "messages:send"}}}
	for name, tc := range map[string]struct {
		asked []oidc.ResourceScopes
		want  bool
	}{
		"nothing":        {nil, true},
		"a part":         {[]oidc.ResourceScopes{{ResourceID: "platform-api", Scopes: []string{"messages:send"}}}, true},
		"all":            {granted, true},
		"another scope":  {[]oidc.ResourceScopes{{ResourceID: "platform-api", Scopes: []string{"messages:send", "video:read"}}}, false},
		"another source": {[]oidc.ResourceScopes{{ResourceID: "video-api", Scopes: []string{"messages:send"}}}, false},
	} {
		if got := oidc.CoversResources(granted, tc.asked); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}
