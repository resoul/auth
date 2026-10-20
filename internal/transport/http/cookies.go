package http

import (
	"context"
	"net/http"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
)

// Cookie names carry the __Secure- prefix, so a browser refuses to set them without the
// Secure attribute. Paths are as narrow as the routes that read them need: the refresh
// cookie goes only to the token routes, the binding cookie only to the sign-in routes: the
// email flow, the passkey ceremonies and recovery all live under /v1/auth.
const (
	RefreshCookieName = "__Secure-px_refresh"
	BindingCookieName = "__Secure-px_binding"

	// DeviceCookieName holds the poll secret of a device sign-in request, only for the device routes.
	DeviceCookieName = "__Secure-px_device"
	deviceCookiePath = "/v1/auth/device"

	refreshCookiePath = "/v1/token"
	bindingCookiePath = "/v1/auth"
)

type cookieJarKey struct{}

// cookieJar carries the request's cookies in and the response's cookies out. Handlers
// built by the strict server cannot reach the ResponseWriter, so they add cookies here
// and withCookies writes them with the status line.
type cookieJar struct {
	req *http.Request
	set []*http.Cookie
}

func withCookies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jar := &cookieJar{req: r}
		ctx := context.WithValue(r.Context(), cookieJarKey{}, jar)
		next.ServeHTTP(&cookieWriter{ResponseWriter: w, jar: jar}, r.WithContext(ctx))
	})
}

// cookieWriter writes the collected Set-Cookie headers before the first byte of the response.
type cookieWriter struct {
	http.ResponseWriter
	jar     *cookieJar
	flushed bool
}

func (c *cookieWriter) flush() {
	if c.flushed {
		return
	}

	c.flushed = true
	for _, ck := range c.jar.set {
		http.SetCookie(c.ResponseWriter, ck)
	}
}

func (c *cookieWriter) WriteHeader(status int) {
	c.flush()
	c.ResponseWriter.WriteHeader(status)
}

func (c *cookieWriter) Write(b []byte) (int, error) {
	c.flush()
	return c.ResponseWriter.Write(b)
}

func (c *cookieWriter) Unwrap() http.ResponseWriter {
	return c.ResponseWriter
}

// requestCookie returns the value of the named request cookie, or "".
func requestCookie(ctx context.Context, name string) string {
	jar, _ := ctx.Value(cookieJarKey{}).(*cookieJar)
	if jar == nil {
		return ""
	}

	ck, err := jar.req.Cookie(name)
	if err != nil {
		return ""
	}

	return ck.Value
}

// requestHeaderValues returns the values of a request header.
func requestHeaderValues(ctx context.Context, name string) []string {
	jar, _ := ctx.Value(cookieJarKey{}).(*cookieJar)
	if jar == nil {
		return nil
	}

	return jar.req.Header.Values(name)
}

func setCookie(ctx context.Context, ck *http.Cookie) {
	if jar, _ := ctx.Value(cookieJarKey{}).(*cookieJar); jar != nil {
		jar.set = append(jar.set, ck)
	}
}

// cookies builds the browser profile's cookies. Secure is always on: the prefix demands it
// and a secret must never travel over plain HTTP. There is no Domain, so a cookie belongs to
// this host only.
type cookies struct{ sameSite http.SameSite }

func (c cookies) base(name, path, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: path, Secure: true, HttpOnly: true, SameSite: c.sameSite}
}

// refresh holds the refresh secret until the token's own expiry.
func (c cookies) refresh(secret string, expires time.Time) *http.Cookie {
	ck := c.base(RefreshCookieName, refreshCookiePath, secret)
	ck.Expires = expires.UTC()

	return ck
}

// binding holds the client binding for as long as recognition lasts after a proof.
func (c cookies) binding(secret string) *http.Cookie {
	ck := c.base(BindingCookieName, bindingCookiePath, secret)
	ck.MaxAge = int(identity.RecognitionTTL / time.Second)

	return ck
}

// device holds the poll secret of a device sign-in request for the life of the request.
func (c cookies) device(secret string, expires time.Time) *http.Cookie {
	ck := c.base(DeviceCookieName, deviceCookiePath, secret)
	ck.Expires = expires.UTC()

	return ck
}

func (c cookies) clearDevice() *http.Cookie {
	ck := c.base(DeviceCookieName, deviceCookiePath, "")
	ck.MaxAge = -1

	return ck
}

func (c cookies) clearBinding() *http.Cookie {
	ck := c.base(BindingCookieName, bindingCookiePath, "")
	ck.MaxAge = -1

	return ck
}

func (c cookies) clearRefresh() *http.Cookie {
	ck := c.base(RefreshCookieName, refreshCookiePath, "")
	ck.MaxAge = -1

	return ck
}
