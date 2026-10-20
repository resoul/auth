package http_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/domain/quota"
	httpapi "go.airlance.org/auth/internal/transport/http"
)

type deviceStart struct {
	RequestID     string    `json:"request_id"`
	PollSecret    string    `json:"poll_secret"`
	PairingCode   string    `json:"pairing_code"`
	ExpiresAt     time.Time `json:"expires_at"`
	ClientBinding string    `json:"client_binding"`
}

type deviceState struct {
	State string `json:"state"`
}

// phoneOf is the signed-in approving device of a profile: the passkey routes of manage, the device routes beside them.
func phoneOf(m manage) manage {
	if m.browser {
		m.base = "/v1/device"
	} else {
		m.base = "/v1/native/device"
	}

	return m
}

// stepUpOf runs the step-up on the profile's own /me routes.
func stepUpOf(m manage) string {
	me := m
	if m.browser {
		me.base = "/v1/me"
	} else {
		me.base = "/v1/native/me"
	}

	return me.stepUp(m.auth, "approve_device")
}

// newDevice is the new device of one profile: what it holds between the steps.
type newDevice struct {
	e       *env
	browser *browser
	// native holds what a native app keeps by itself.
	start deviceStart
}

func (d *newDevice) call(step string, body map[string]any) *httptest.ResponseRecorder {
	d.e.t.Helper()

	if d.browser != nil {
		return d.browser.post("/v1/auth/device/"+step, body)
	}

	b := map[string]any{"request_id": d.start.RequestID, "poll_secret": d.start.PollSecret, "client_binding": d.start.ClientBinding}
	for k, v := range body {
		b[k] = v
	}

	return d.e.post("/v1/native/auth/device/"+step, b)
}

func (d *newDevice) begin(name string) *httptest.ResponseRecorder {
	d.e.t.Helper()

	body := map[string]string{}
	if name != "" {
		body["device_name"] = name
	}

	var rec *httptest.ResponseRecorder
	if d.browser != nil {
		rec = d.browser.post("/v1/auth/device/start", body)
	} else {
		rec = d.e.post("/v1/native/auth/device/start", body)
	}

	if rec.Code == http.StatusOK {
		d.start = decode[deviceStart](d.e.t, rec, http.StatusOK)
	}

	return rec
}

func (d *newDevice) state() string {
	d.e.t.Helper()
	rec := d.call("status", map[string]any{"request_id": d.start.RequestID})

	return decode[deviceState](d.e.t, rec, http.StatusOK).State
}

func newDeviceOf(e *env, browserProfile bool) *newDevice {
	d := &newDevice{e: e}
	if browserProfile {
		d.browser = newBrowser(e)
	}

	return d
}

func profiles(t *testing.T, fn func(t *testing.T, e *env, build func(*env, string) manage, browserProfile bool)) {
	for name, build := range map[string]func(*testing.T, *env, string) manage{"native": nativeManage, "browser": browserManage} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			fn(t, e, func(e *env, email string) manage { return build(t, e, email) }, name == "browser")
		})
	}
}

func TestADeviceSignsInWithTheApprovalOfAPhoneInBothProfiles(t *testing.T) {
	profiles(t, func(t *testing.T, e *env, signedIn func(*env, string) manage, browserProfile bool) {
		phone := signedIn(e, "owner@example.test")
		device := newDeviceOf(e, browserProfile)

		rec := device.begin("Office laptop")
		if rec.Code != http.StatusOK {
			t.Fatalf("start = %d %s", rec.Code, rec.Body)
		}

		start := device.start
		if start.RequestID == "" || len(start.PairingCode) != 6 || start.ExpiresAt.IsZero() {
			t.Fatalf("start = %+v", start)
		}
		// The two profiles keep their secrets in different places, and never in both.
		if browserProfile {
			if start.PollSecret != "" || start.ClientBinding != "" || strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "binding") {
				t.Errorf("the browser body carries a secret: %s", rec.Body)
			}

			var device, binding *http.Cookie

			for _, c := range rec.Result().Cookies() {
				switch c.Name {
				case httpapi.DeviceCookieName:
					device = c
				case httpapi.BindingCookieName:
					binding = c
				}
			}

			if device == nil || binding == nil || device.Path != "/v1/auth/device" || !device.Secure || !device.HttpOnly || device.Value == "" || device.Expires.IsZero() {
				t.Errorf("cookies: device %+v, binding %+v", device, binding)
			}
		} else if start.PollSecret == "" || start.ClientBinding == "" {
			t.Errorf("the native body lacks its secrets: %s", rec.Body)
		}

		if got := device.state(); got != "pending" {
			t.Fatalf("state = %s", got)
		}

		pm := phoneOf(phone)

		view := decode[struct {
			DeviceName string    `json:"device_name"`
			ExpiresAt  time.Time `json:"expires_at"`
		}](t, pm.call(http.MethodGet, "/requests/"+start.RequestID, "", ""), http.StatusOK)
		if view.DeviceName != "Office laptop" {
			t.Errorf("view = %+v", view)
		}

		if body := pm.call(http.MethodGet, "/requests/"+start.RequestID, "", "").Body.String(); strings.Contains(body, start.PairingCode) {
			t.Errorf("the phone is told the pairing code: %s", body)
		}

		approve := func(code, stepUp string) *httptest.ResponseRecorder {
			return pm.json(http.MethodPost, "/requests/"+start.RequestID+"/approve", stepUp, map[string]string{"pairing_code": code})
		}
		wantProblem(t, approve(start.PairingCode, ""), http.StatusForbidden, "step_up_required")
		wantProblem(t, approve("000000", stepUpOf(phone)), http.StatusBadRequest, "invalid_proof")

		if rec := approve(start.PairingCode, stepUpOf(phone)); rec.Code != http.StatusNoContent {
			t.Fatalf("approve = %d %s", rec.Code, rec.Body)
		}

		if got := device.state(); got != "approved" {
			t.Fatalf("state after approval = %s", got)
		}

		redeemed := device.call("redeem", map[string]any{"request_id": start.RequestID})
		if redeemed.Code != http.StatusOK {
			t.Fatalf("redeem = %d %s", redeemed.Code, redeemed.Body)
		}

		signed := decode[tokenResponse](t, redeemed, http.StatusOK)
		if signed.AccessToken == "" || signed.User.Email != "owner@example.test" {
			t.Fatalf("session = %+v", signed)
		}

		if browserProfile {
			var refresh *http.Cookie

			for _, c := range redeemed.Result().Cookies() {
				if c.Name == httpapi.RefreshCookieName && c.Value != "" {
					refresh = c
				}

				if c.Name == httpapi.DeviceCookieName && c.MaxAge >= 0 {
					t.Errorf("the spent poll secret was not cleared: %+v", c)
				}
			}

			if refresh == nil || signed.RefreshToken != "" || strings.Contains(redeemed.Body.String(), "refresh") {
				t.Errorf("browser redeem: refresh cookie %+v, body %s", refresh, redeemed.Body)
			}
		} else if signed.RefreshToken == "" {
			t.Error("the native session has no refresh token")
		}
		// The new device is a session of its own: its token works and differs from the phone's.
		if signed.AccessToken == phone.token || e.meStatus(signed.AccessToken) != http.StatusOK {
			t.Errorf("the new session: same token as the phone %v, status %d", signed.AccessToken == phone.token, e.meStatus(signed.AccessToken))
		}

		if e.store.SessionCount() != 2 {
			t.Errorf("%d sessions, want the phone's and the new device's", e.store.SessionCount())
		}
		// Once.
		wantProblem(t, device.call("redeem", map[string]any{"request_id": start.RequestID}), http.StatusBadRequest, "invalid_proof")
	})
}

func TestEveryRefusalTheNewDeviceSeesIsTheSameInvalidProof(t *testing.T) {
	profiles(t, func(t *testing.T, e *env, signedIn func(*env, string) manage, browserProfile bool) {
		phone := signedIn(e, "owner@example.test")
		device := newDeviceOf(e, browserProfile)
		device.begin("laptop")

		other := newDeviceOf(e, browserProfile)
		other.begin("other")

		pm := phoneOf(phone)
		pm.json(http.MethodPost, "/requests/"+device.start.RequestID+"/approve", stepUpOf(phone), map[string]string{"pairing_code": device.start.PairingCode})

		body := func(rec *httptest.ResponseRecorder) string {
			s := rec.Body.String()
			if i := strings.Index(s, `"request_id"`); i >= 0 {
				s = s[:i]
			}

			return s
		}

		var bodies []string

		for _, step := range []string{"status", "redeem"} {
			for name, req := range map[string]string{"unknown id": "AAECAwQFBgcICQoLDA0ODw", "malformed id": "nope", "empty id": ""} {
				rec := device.call(step, map[string]any{"request_id": req})
				wantProblem(t, rec, http.StatusBadRequest, "invalid_proof")
				bodies = append(bodies, body(rec))
				_ = name
			}

			if !browserProfile {
				for name, secret := range map[string]string{"another's secret": other.start.PollSecret, "malformed secret": "x", "empty secret": ""} {
					rec := device.call(step, map[string]any{"request_id": device.start.RequestID, "poll_secret": secret})
					wantProblem(t, rec, http.StatusBadRequest, "invalid_proof")
					bodies = append(bodies, body(rec))
					_ = name
				}

				rec := device.call(step, map[string]any{"request_id": device.start.RequestID, "client_binding": other.start.ClientBinding})
				wantProblem(t, rec, http.StatusBadRequest, "invalid_proof")
				bodies = append(bodies, body(rec))
			} else {
				// A browser that never started the request has neither cookie.
				stranger := newDeviceOf(e, true)
				rec := stranger.call(step, map[string]any{"request_id": device.start.RequestID})
				wantProblem(t, rec, http.StatusBadRequest, "invalid_proof")
				bodies = append(bodies, body(rec))
				// Another browser's cookies do not open this request either.
				rec = other.call(step, map[string]any{"request_id": device.start.RequestID})
				wantProblem(t, rec, http.StatusBadRequest, "invalid_proof")
				bodies = append(bodies, body(rec))
			}
		}

		for _, b := range bodies {
			if b != bodies[0] {
				t.Errorf("a refusal differs: %q vs %q", b, bodies[0])
			}
		}
		// None of that spent the approval.
		if got := device.state(); got != "approved" {
			t.Errorf("state = %s", got)
		}
	})
}

func TestTheDeviceRoutesNeedASignedInUserForTheApprovingSide(t *testing.T) {
	e := newEnv(t)

	const id = "AAECAwQFBgcICQoLDA0ODw"
	for _, base := range []string{"/v1/native/device", "/v1/device"} {
		for _, r := range []struct{ method, path string }{
			{http.MethodGet, "/requests/" + id}, {http.MethodPost, "/requests/" + id + "/approve"}, {http.MethodPost, "/requests/" + id + "/deny"},
		} {
			for _, token := range []string{"", "x.y.z"} {
				req := httptest.NewRequest(r.method, base+r.path, strings.NewReader(`{"pairing_code":"123456"}`))
				req.Header.Set("Content-Type", "application/json")

				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}

				if base == "/v1/device" {
					req.Header.Set("Sec-Fetch-Site", "same-origin")
				}

				e.wantUnauthenticated(e.do(req))
			}
		}
	}
}

func TestAPhoneCanRefuseAndTheRefusalIsFinal(t *testing.T) {
	profiles(t, func(t *testing.T, e *env, signedIn func(*env, string) manage, browserProfile bool) {
		phone := signedIn(e, "owner@example.test")
		pm := phoneOf(phone)
		device := newDeviceOf(e, browserProfile)
		device.begin("laptop")

		if rec := pm.call(http.MethodPost, "/requests/"+device.start.RequestID+"/deny", "", ""); rec.Code != http.StatusNoContent {
			t.Fatalf("deny = %d %s", rec.Code, rec.Body)
		}

		if got := device.state(); got != "denied" {
			t.Errorf("state = %s", got)
		}

		wantProblem(t, pm.call(http.MethodPost, "/requests/"+device.start.RequestID+"/deny", "", ""), http.StatusNotFound, "not_found")
		wantProblem(t, pm.call(http.MethodGet, "/requests/"+device.start.RequestID, "", ""), http.StatusNotFound, "not_found")
		wantProblem(t, pm.json(http.MethodPost, "/requests/"+device.start.RequestID+"/approve", stepUpOf(phone), map[string]string{"pairing_code": device.start.PairingCode}), http.StatusNotFound, "not_found")
		wantProblem(t, device.call("redeem", map[string]any{"request_id": device.start.RequestID}), http.StatusBadRequest, "invalid_proof")

		for _, id := range []string{"AAECAwQFBgcICQoLDA0ODw", "nope"} {
			wantProblem(t, pm.call(http.MethodGet, "/requests/"+id, "", ""), http.StatusNotFound, "not_found")
			wantProblem(t, pm.call(http.MethodPost, "/requests/"+id+"/deny", "", ""), http.StatusNotFound, "not_found")
		}
	})
}

func TestThreeWrongCodesKillTheRequestOverHTTP(t *testing.T) {
	profiles(t, func(t *testing.T, e *env, signedIn func(*env, string) manage, browserProfile bool) {
		phone := signedIn(e, "owner@example.test")
		pm := phoneOf(phone)
		device := newDeviceOf(e, browserProfile)
		device.begin("laptop")

		wrong := "000000"
		if device.start.PairingCode == wrong {
			wrong = "111111"
		}

		proof := stepUpOf(phone)

		path := "/requests/" + device.start.RequestID + "/approve"
		for i := 0; i < 3; i++ {
			wantProblem(t, pm.json(http.MethodPost, path, proof, map[string]string{"pairing_code": wrong}), http.StatusBadRequest, "invalid_proof")
		}

		wantProblem(t, pm.json(http.MethodPost, path, proof, map[string]string{"pairing_code": device.start.PairingCode}), http.StatusNotFound, "not_found")

		if got := device.state(); got != "denied" {
			t.Errorf("state = %s", got)
		}
	})
}

func TestARequestExpiresAndTheDeviceMustStartAgain(t *testing.T) {
	profiles(t, func(t *testing.T, e *env, signedIn func(*env, string) manage, browserProfile bool) {
		device := newDeviceOf(e, browserProfile)
		device.begin("laptop")
		e.clock.Advance(5 * time.Minute)

		if got := device.state(); got != "expired" {
			t.Errorf("state = %s", got)
		}

		wantProblem(t, device.call("redeem", map[string]any{"request_id": device.start.RequestID}), http.StatusBadRequest, "invalid_proof")
	})
}

func TestStartRefusesABadNameAndTheNativeAndBrowserRoutesAreSeparate(t *testing.T) {
	e := newEnv(t)
	long := strings.Repeat("x", 65)
	wantProblem(t, e.post("/v1/native/auth/device/start", map[string]string{"device_name": long}), http.StatusBadRequest, "invalid_request")
	b := newBrowser(e)
	wantProblem(t, b.post("/v1/auth/device/start", map[string]string{"device_name": long}), http.StatusBadRequest, "invalid_request")
	wantProblem(t, e.postRaw("/v1/native/auth/device/start", `{"device_name": 5}`), http.StatusBadRequest, "invalid_request")

	if rec := e.postRaw("/v1/native/auth/device/start", `{}`); rec.Code != http.StatusOK {
		t.Errorf("an empty start = %d %s", rec.Code, rec.Body)
	}
	// A native start does not honour the cookies of a page, and a malformed binding cookie is replaced.
	b.cookies[httpapi.BindingCookieName] = &http.Cookie{Name: httpapi.BindingCookieName, Value: "garbage", Path: "/v1/auth"}
	if rec := b.post("/v1/auth/device/start", map[string]string{}); rec.Code != http.StatusOK {
		t.Errorf("a malformed binding cookie broke the start: %d %s", rec.Code, rec.Body)
	}
}

func TestDeviceStartsAreCountedAgainstTheAddressInBothProfiles(t *testing.T) {
	profile, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.DeviceIP: {{Limit: 2, Per: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}

	rec := &recorder{}
	e := newEnvWith(t, func(d *httpapi.Deps) { d.Requests = rec }, memory.WithQuota(profile))

	b := newBrowser(e)
	for i := 0; i < 2; i++ {
		if rec := e.postRaw("/v1/native/auth/device/start", `{}`); rec.Code != http.StatusOK {
			t.Fatalf("start %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	// One budget serves both profiles: the address is the same.
	wantProblem(t, e.postRaw("/v1/native/auth/device/start", `{}`), http.StatusTooManyRequests, "rate_limited")
	wantProblem(t, b.postRaw("/v1/auth/device/start", `{}`), http.StatusTooManyRequests, "rate_limited")

	if got := rec.denials("device_start", "quota"); got != 2 {
		t.Errorf("device_start/quota denials = %d (all: %+v)", got, rec.denied)
	}
}
