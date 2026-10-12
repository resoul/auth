package metrics_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/metrics"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/testutil"
)

func scrape(t *testing.T, r *metrics.Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func hasLine(body, line string) bool {
	for _, l := range strings.Split(body, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

func TestSeriesExistFromTheFirstScrape(t *testing.T) {
	body := scrape(t, metrics.New())
	for _, line := range []string{
		`airlance_auth_mail_jobs_total{outcome="sent",quota_class="unknown"} 0`,
		`airlance_auth_mail_jobs_total{outcome="exhausted",quota_class="recognized"} 0`,
		`airlance_auth_mail_jobs_total{outcome="key_unavailable",quota_class="unknown"} 0`,
		`airlance_auth_refresh_reuse_total 0`,
	} {
		if !hasLine(body, line) {
			t.Errorf("missing %q", line)
		}
	}
}

func TestMailProcessedCountsOutcomesAndObservesTimes(t *testing.T) {
	r := metrics.New()
	r.MailProcessed(authflow.QuotaUnknown, port.MailSent, 3*time.Second, 400*time.Millisecond)
	r.MailProcessed(authflow.QuotaUnknown, port.MailSent, 1*time.Second, 100*time.Millisecond)
	r.MailProcessed(authflow.QuotaRecognized, port.MailRetried, 0, 2*time.Second)
	r.MailProcessed(authflow.QuotaUnknown, port.MailObsolete, 5*time.Second, 0)

	body := scrape(t, r)
	for _, line := range []string{
		`airlance_auth_mail_jobs_total{outcome="sent",quota_class="unknown"} 2`,
		`airlance_auth_mail_jobs_total{outcome="retried",quota_class="recognized"} 1`,
		`airlance_auth_mail_jobs_total{outcome="obsolete",quota_class="unknown"} 1`,
		`airlance_auth_mail_queue_delay_seconds_count{quota_class="unknown"} 3`,
		`airlance_auth_mail_queue_delay_seconds_count{quota_class="recognized"} 1`,
		`airlance_auth_mail_send_seconds_count{outcome="sent"} 2`,
		`airlance_auth_mail_send_seconds_count{outcome="retried"} 1`,
		// Nothing was sent for an obsolete job, so no send time is observed.
		`airlance_auth_mail_send_seconds_count{outcome="obsolete"} 0`,
	} {
		if !hasLine(body, line) {
			t.Errorf("missing %q in\n%s", line, body)
		}
	}
}

func TestRefreshReuseIsCounted(t *testing.T) {
	r := metrics.New()
	r.RefreshReuseDetected()
	r.RefreshReuseDetected()
	if !hasLine(scrape(t, r), "airlance_auth_refresh_reuse_total 2") {
		t.Error("the reuse counter is wrong")
	}
}

func TestQueueGaugesAreReadOnEveryScrape(t *testing.T) {
	r := metrics.New()
	clock := testutil.NewFakeClock(time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC))
	depth := 4
	err := r.RegisterQueue(func(context.Context, time.Time) (port.QueueStats, error) {
		return port.QueueStats{
			Queued:     map[authflow.QuotaClass]int{authflow.QuotaUnknown: depth, authflow.QuotaRecognized: 1},
			OldestWait: map[authflow.QuotaClass]time.Duration{authflow.QuotaUnknown: 90 * time.Second},
		}, nil
	}, clock)
	if err != nil {
		t.Fatal(err)
	}

	body := scrape(t, r)
	for _, line := range []string{
		`airlance_auth_mail_queue_depth{quota_class="unknown"} 4`,
		`airlance_auth_mail_queue_depth{quota_class="recognized"} 1`,
		`airlance_auth_mail_oldest_due_wait_seconds{quota_class="unknown"} 90`,
		`airlance_auth_mail_oldest_due_wait_seconds{quota_class="recognized"} 0`,
		`airlance_auth_mail_queue_stats_up 1`,
	} {
		if !hasLine(body, line) {
			t.Errorf("missing %q in\n%s", line, body)
		}
	}
	depth = 7
	if !hasLine(scrape(t, r), `airlance_auth_mail_queue_depth{quota_class="unknown"} 7`) {
		t.Error("the gauge did not follow the queue")
	}
}

func TestAFailedQueueReadIsReportedNotHidden(t *testing.T) {
	r := metrics.New()
	clock := testutil.NewFakeClock(time.Now())
	if err := r.RegisterQueue(func(context.Context, time.Time) (port.QueueStats, error) {
		return port.QueueStats{}, errors.New("database down")
	}, clock); err != nil {
		t.Fatal(err)
	}
	body := scrape(t, r)
	if !hasLine(body, "airlance_auth_mail_queue_stats_up 0") {
		t.Errorf("the failure was not reported:\n%s", body)
	}
	if strings.Contains(body, "airlance_auth_mail_queue_depth{") {
		t.Error("stale queue numbers were reported although the queue could not be read")
	}
}

func TestLabelsComeFromClosedSets(t *testing.T) {
	r := metrics.New()
	r.MailProcessed(authflow.QuotaRecognized, port.MailKeyUnavailable, time.Second, 0)
	body := scrape(t, r)
	for _, l := range strings.Split(body, "\n") {
		if !strings.HasPrefix(l, "airlance_auth_") || !strings.Contains(l, "{") {
			continue
		}
		labels := l[strings.Index(l, "{")+1 : strings.Index(l, "}")]
		for _, pair := range strings.Split(labels, ",") {
			name := strings.SplitN(pair, "=", 2)[0]
			if name != "outcome" && name != "quota_class" && name != "le" {
				t.Errorf("unexpected label %q in %q", name, l)
			}
		}
	}
	for _, forbidden := range []string{"@", "flow", "user", "session", "email"} {
		if strings.Contains(strings.ToLower(body), `"`+forbidden) {
			t.Errorf("the output has a label value starting with %q", forbidden)
		}
	}
}

func TestOnlyOurMetricsAreExposed(t *testing.T) {
	body := scrape(t, metrics.New())
	for _, l := range strings.Split(body, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "airlance_auth_") {
			t.Errorf("unexpected series %q: the registry must be private", l)
		}
	}
}

func TestRequestsAreCountedByRouteAndStatusClass(t *testing.T) {
	r := metrics.New()
	r.RequestServed("POST /v1/native/auth/email/verify", 200, 20*time.Millisecond)
	r.RequestServed("POST /v1/native/auth/email/verify", 400, 5*time.Millisecond)
	r.RequestServed("POST /v1/native/auth/email/verify", 400, 5*time.Millisecond)
	r.RequestServed("DELETE /v1/sessions/{id}", 503, time.Second)
	r.RequestServed("unmatched", 404, time.Millisecond)

	body := scrape(t, r)
	for _, line := range []string{
		`airlance_auth_http_requests_total{route="POST /v1/native/auth/email/verify",status_class="2xx"} 1`,
		`airlance_auth_http_requests_total{route="POST /v1/native/auth/email/verify",status_class="4xx"} 2`,
		`airlance_auth_http_requests_total{route="DELETE /v1/sessions/{id}",status_class="5xx"} 1`,
		`airlance_auth_http_requests_total{route="unmatched",status_class="4xx"} 1`,
		`airlance_auth_http_request_seconds_count{route="POST /v1/native/auth/email/verify"} 3`,
	} {
		if !hasLine(body, line) {
			t.Errorf("missing %q\n%s", line, body)
		}
	}
}

func TestStatusClassesCoverEveryCode(t *testing.T) {
	r := metrics.New()
	for _, status := range []int{101, 200, 204, 301, 404, 429, 500, 503, 0, 700} {
		r.RequestServed("GET /x", status, 0)
	}
	body := scrape(t, r)
	for class, n := range map[string]int{"2xx": 2, "3xx": 1, "4xx": 2, "5xx": 2, "other": 3} {
		line := fmt.Sprintf(`airlance_auth_http_requests_total{route="GET /x",status_class="%s"} %d`, class, n)
		if !hasLine(body, line) {
			t.Errorf("missing %q", line)
		}
	}
}

func TestDenialsAreCountedByOperationAndReason(t *testing.T) {
	r := metrics.New()
	r.AuthDenied("verify", "wrong_code")
	r.AuthDenied("verify", "wrong_code")
	r.AuthDenied("step_up", "clone_suspected")
	body := scrape(t, r)
	for _, line := range []string{
		`airlance_auth_denied_total{operation="verify",reason="wrong_code"} 2`,
		`airlance_auth_denied_total{operation="step_up",reason="clone_suspected"} 1`,
	} {
		if !hasLine(body, line) {
			t.Errorf("missing %q", line)
		}
	}
}

func TestLabelsThatAreNotCodesNeverBecomeSeries(t *testing.T) {
	r := metrics.New()
	for _, bad := range []string{"alice@example.test", "203.0.113.7", "Upper", "with space", "", "1digit", strings.Repeat("a", 60), "7f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"} {
		r.AuthDenied(bad, "ok_reason")
		r.AuthDenied("ok_operation", bad)
	}
	for _, bad := range []string{"GET /v1/sessions/7f1b7c0e", "GET /v1/me?x=alice@example.test", "get /v1/me", "/v1/me", "GET /v1/" + strings.Repeat("a", 130), ""} {
		r.RequestServed(bad, 200, 0)
	}
	body := scrape(t, r)
	for _, secret := range []string{"alice", "203.0.113.7", "7f1b7c0e", "example.test", "with space"} {
		if strings.Contains(body, secret) {
			t.Errorf("the scrape contains %q", secret)
		}
	}
	if !hasLine(body, `airlance_auth_denied_total{operation="other",reason="ok_reason"} 8`) ||
		!hasLine(body, `airlance_auth_denied_total{operation="ok_operation",reason="other"} 8`) {
		t.Errorf("rejected labels did not collapse into other:\n%s", body)
	}
	if !hasLine(body, `airlance_auth_http_requests_total{route="other",status_class="2xx"} 6`) {
		t.Errorf("rejected routes did not collapse into other")
	}
}

func TestDistinctValuesAreBoundedPerLabel(t *testing.T) {
	r := metrics.New()
	word := func(i int) string { // distinct words without digits: 500 values that all look legitimate
		return string(rune('a'+i/26/26%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i%26))
	}
	for i := 0; i < 500; i++ {
		r.RequestServed("GET /v1/route"+"-"+word(i), 200, 0)
		r.AuthDenied("op_"+word(i), "reason_"+word(i))
	}
	body := scrape(t, r)
	routes, denials := 0, 0
	for _, line := range strings.Split(body, "\n") {
		switch {
		case strings.HasPrefix(line, "airlance_auth_http_requests_total{"):
			routes++
		case strings.HasPrefix(line, "airlance_auth_denied_total{"):
			denials++
		}
	}
	if routes > 132 || denials > 64*64 || routes < 120 {
		t.Errorf("%d route series and %d denial series from 500 distinct values", routes, denials)
	}
	if !strings.Contains(body, `route="other"`) {
		t.Error("the overflow of routes is not in other")
	}
}

func TestResourceMetricsUseOnlyBoundedCodes(t *testing.T) {
	r := metrics.New()
	r.ResourceToken("platform-api", "issued")
	r.ResourceToken("platform-api", "issued")
	r.ResourceToken("platform-api", "invalid_scope")
	r.ResourceToken("unknown", "invalid_target")
	// A value that is not a short code, such as a URI or a person's identifier, never becomes a label.
	r.ResourceToken("https://api.example.test/platform", "invalid_target")
	r.ResourceToken("platform-api", "user 7 refused")
	r.PermissionChange("client_denied", 3)
	r.PermissionChange("resource_registered", 0)
	body := scrape(t, r)
	for _, line := range []string{
		`airlance_auth_oidc_resource_tokens_total{outcome="issued",resource="platform-api"} 2`,
		`airlance_auth_oidc_resource_tokens_total{outcome="invalid_scope",resource="platform-api"} 1`,
		`airlance_auth_oidc_resource_tokens_total{outcome="invalid_target",resource="unknown"} 1`,
		`airlance_auth_oidc_resource_tokens_total{outcome="invalid_target",resource="other"} 1`,
		`airlance_auth_oidc_resource_tokens_total{outcome="other",resource="platform-api"} 1`,
		`airlance_auth_oidc_permission_changes_total{change="client_denied"} 1`,
		`airlance_auth_oidc_grants_ended_total{change="client_denied"} 3`,
		`airlance_auth_oidc_permission_changes_total{change="resource_registered"} 1`,
	} {
		if !hasLine(body, line) {
			t.Errorf("missing %q in\n%s", line, body)
		}
	}
	if strings.Contains(body, "https://") || strings.Contains(body, "user 7") {
		t.Error("a value that is not a code became a label")
	}
}
