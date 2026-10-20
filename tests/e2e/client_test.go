//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type client struct {
	t       *testing.T
	base    string
	cookies map[string]*http.Cookie
}

func newClient(s *stack) *client {
	return &client{t: s.t, base: s.base, cookies: map[string]*http.Cookie{}}
}

type reply struct {
	Status int
	Header http.Header
	Raw    string
	Body   map[string]any
}

func (r reply) str(key string) string {
	v, _ := r.Body[key].(string)
	return v
}

func (r reply) list(key string) []string {
	items, _ := r.Body[key].([]any)

	out := make([]string, 0, len(items))
	for _, item := range items {
		if v, ok := item.(string); ok {
			out = append(out, v)
		}
	}

	return out
}

func (r reply) options() []byte {
	data, err := json.Marshal(r.Body["options"])
	if err != nil {
		panic(err) // the reply was decoded from JSON a moment ago
	}

	return data
}

func (c *client) do(method, path string, body any, headers map[string]string) reply {
	c.t.Helper()

	var reader io.Reader

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}

		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		c.t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")

	for _, ck := range c.cookies {
		if strings.HasPrefix(path, ck.Path) {
			req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		}
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}

	for _, ck := range resp.Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}

	out := reply{Status: resp.StatusCode, Header: resp.Header, Raw: string(data), Body: map[string]any{}}
	_ = json.Unmarshal(data, &out.Body)

	return out
}

func (c *client) browser(method, path string, body any, token string) reply {
	c.t.Helper()

	headers := map[string]string{"Sec-Fetch-Site": "same-origin"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	return c.do(method, path, body, headers)
}

func (c *client) native(method, path string, body any, token string) reply {
	c.t.Helper()

	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}

	return c.do(method, path, body, headers)
}

func want(t *testing.T, r reply, status int, code string) {
	t.Helper()

	if r.Status != status {
		t.Fatalf("status = %d, want %d: %s", r.Status, status, r.Raw)
	}

	if code != "" && r.str("code") != code {
		t.Fatalf("code = %q, want %q: %s", r.str("code"), code, r.Raw)
	}
}
