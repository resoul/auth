package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeletingAccountInBothProfilesEndsAccessAndForgetsCookies(t *testing.T) {
	for name, build := range map[string]func(*testing.T, *env, string) manage{"native": nativeManage, "browser": browserManage} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			m := build(t, e, name+"@example.test")
			wantProblem(t, m.call(http.MethodDelete, "", "", ""), http.StatusForbidden, "step_up_required")
			wrong := m.stepUp(m.auth, "change_email")
			wantProblem(t, m.call(http.MethodDelete, "", wrong, ""), http.StatusForbidden, "step_up_required")
			token := m.stepUp(m.auth, "delete_account")

			rec := m.call(http.MethodDelete, "", token, "")
			if rec.Code != http.StatusNoContent {
				t.Fatalf("delete = %d %s", rec.Code, rec.Body)
			}

			cookies := rec.Result().Cookies()
			if name == "browser" {
				if len(cookies) != 2 {
					t.Fatalf("cookies = %+v", cookies)
				}

				for _, cookie := range cookies {
					if cookie.MaxAge >= 0 || !cookie.Secure || !cookie.HttpOnly {
						t.Errorf("cookie not forgotten: %+v", cookie)
					}
				}
			} else if len(cookies) != 0 {
				t.Error("native response set cookies")
			}

			wantProblem(t, m.call(http.MethodGet, "", "", ""), http.StatusUnauthorized, "unauthenticated")
			wantProblem(t, m.call(http.MethodDelete, "", token, ""), http.StatusUnauthorized, "unauthenticated")

			if e.store.UserCount() != 0 || e.store.SessionCount() != 0 || e.store.TokenCount() != 0 {
				t.Error("account access survived")
			}
		})
	}
}

func TestBrowserAccountDeletionRefusesForeignOrigins(t *testing.T) {
	e := newEnv(t)
	m := browserManage(t, e, "delete@example.test")
	token := m.stepUp(m.auth, "delete_account")
	req := httptest.NewRequest(http.MethodDelete, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("X-Step-Up", token)
	req.Header.Set("Origin", "https://foreign.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	wantProblem(t, e.do(req), http.StatusForbidden, "permission_denied")

	if e.store.UserCount() != 1 {
		t.Error("foreign page deleted account")
	}
}
