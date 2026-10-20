package metrics

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
)

var (
	_ port.Metrics        = (*Registry)(nil)
	_ port.RequestMetrics = (*Registry)(nil)
	_ port.OIDCMetrics    = (*Registry)(nil)
)

// classes and outcomes are the closed label sets. Counters are created for all of
// them up front, so a series exists from the first scrape and an unexpected value
// can never become a label.
var (
	classes  = []authflow.QuotaClass{authflow.QuotaUnknown, authflow.QuotaRecognized}
	outcomes = []port.MailOutcome{
		port.MailSent, port.MailRetried, port.MailRejected, port.MailObsolete, port.MailExhausted, port.MailKeyUnavailable,
	}
)

// Registry owns the collectors. It is separate from the default Prometheus registry,
// so nothing is exposed that was not added here on purpose.
type Registry struct {
	reg        *prometheus.Registry
	mailJobs   *prometheus.CounterVec
	queueDelay *prometheus.HistogramVec
	sendTime   *prometheus.HistogramVec
	reuse      prometheus.Counter
	requests   *prometheus.CounterVec
	duration   *prometheus.HistogramVec
	denied     *prometheus.CounterVec
	resTokens  *prometheus.CounterVec
	introspect *prometheus.CounterVec
	changes    *prometheus.CounterVec
	ended      *prometheus.CounterVec
	resources  *labelSet
	routes     *labelSet
	operations *labelSet
	reasons    *labelSet
}

// New creates the registry with every collector registered.
func New() *Registry {
	r := &Registry{
		reg: prometheus.NewRegistry(),
		mailJobs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "airlance_auth_mail_jobs_total",
			Help: "Delivery attempts of queued sign-in emails by outcome and quota class.",
		}, []string{"outcome", "quota_class"}),
		queueDelay: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "airlance_auth_mail_queue_delay_seconds",
			Help:    "How long a job waited between becoming due and being taken by the worker.",
			Buckets: []float64{0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600},
		}, []string{"quota_class"}),
		sendTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "airlance_auth_mail_send_seconds",
			Help:    "Duration of the SMTP delivery of one email by outcome.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
		}, []string{"outcome"}),
		reuse: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "airlance_auth_refresh_reuse_total",
			Help: "Sessions revoked because an already used refresh token was presented again.",
		}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "airlance_auth_http_requests_total",
			Help: "Answered HTTP requests by matched route pattern and status class.",
		}, []string{"route", "status_class"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "airlance_auth_http_request_seconds",
			Help:    "Time to answer a request by matched route pattern.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"route"}),
		denied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "airlance_auth_denied_total",
			Help: "Expected refusals of a proof or a quota by operation and reason code.",
		}, []string{"operation", "reason"}),
		resTokens: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "airlance_auth_oidc_resource_tokens_total",
			Help: "Token requests for an API resource by the resource and the outcome: issued, or the error code of the refusal.",
		}, []string{"resource", "outcome"}),
		introspect: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "airlance_auth_oidc_introspections_total",
			Help: "Answers to APIs that asked whether an access token is live, by resource and outcome: active, inactive or refused.",
		}, []string{"resource", "outcome"}),
		changes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "airlance_auth_oidc_permission_changes_total",
			Help: "Changes of the rights over API resources, and grants taken back by people, by kind of change.",
		}, []string{"change"}),
		ended: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "airlance_auth_oidc_grants_ended_total",
			Help: "Grants ended by a change of rights or by a person taking an application back, by kind of change.",
		}, []string{"change"}),
		resources:  newLabelSet(maxResources),
		routes:     newLabelSet(maxRoutes),
		operations: newLabelSet(maxOperations),
		reasons:    newLabelSet(maxReasons),
	}
	r.reg.MustRegister(r.mailJobs, r.queueDelay, r.sendTime, r.reuse, r.requests, r.duration, r.denied, r.resTokens, r.introspect, r.changes, r.ended)

	for _, class := range classes {
		r.queueDelay.WithLabelValues(string(class))

		for _, outcome := range outcomes {
			r.mailJobs.WithLabelValues(string(outcome), string(class))
		}
	}

	for _, outcome := range outcomes {
		r.sendTime.WithLabelValues(string(outcome))
	}

	return r
}

// Bounds on label values. The routes and codes come from fixed sets in the code, so these only matter
// if a bug lets a value through that is not one of them: it then lands in "other" instead of
// growing the series without limit.
const (
	maxRoutes     = 128
	maxOperations = 64
	maxReasons    = 48
	maxResources  = 64
	otherLabel    = "other"
)

var (
	codeLabel = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	// A resource identifier is lower-case letters, digits, '-' and '_'.
	resourceLabel = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	methodLabel   = regexp.MustCompile(`^[A-Z]{3,7}$`)
	// A segment of a pattern is a word, a version (v1) or a {parameter}: never something with digits in it,
	// which is what an identifier looks like.
	segmentLabel = regexp.MustCompile(`^(v[0-9]+|\{[a-z]+\}|[a-z][a-z._-]*)$`)
)

// labelSet admits a bounded number of distinct values.
type labelSet struct {
	mu   sync.Mutex
	max  int
	seen map[string]bool
}

func newLabelSet(max int) *labelSet {
	return &labelSet{max: max, seen: map[string]bool{}}
}

func (l *labelSet) admit(value string, valid func(string) bool) string {
	if !valid(value) {
		return otherLabel
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.seen[value] {
		return value
	}

	if len(l.seen) >= l.max {
		return otherLabel
	}

	l.seen[value] = true

	return value
}

// validRoute accepts the pattern of a mux ("POST /v1/native/me"), "unmatched", and nothing that looks
// like a path with an identifier in it: patterns carry {id}, never a value.
func validRoute(route string) bool {
	if route == "unmatched" {
		return true
	}

	method, path, ok := strings.Cut(route, " ")
	if !ok || len(route) > 120 || !methodLabel.MatchString(method) || !strings.HasPrefix(path, "/") {
		return false
	}

	for _, segment := range strings.Split(path[1:], "/") {
		if !segmentLabel.MatchString(segment) {
			return false
		}
	}

	return true
}

func statusClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	}

	return "other"
}

// RequestServed implements port.RequestMetrics.
func (r *Registry) RequestServed(route string, status int, took time.Duration) {
	route = r.routes.admit(route, validRoute)
	r.requests.WithLabelValues(route, statusClass(status)).Inc()
	r.duration.WithLabelValues(route).Observe(took.Seconds())
}

// AuthDenied implements port.RequestMetrics.
func (r *Registry) AuthDenied(operation, reason string) {
	r.denied.WithLabelValues(
		r.operations.admit(operation, codeLabel.MatchString),
		r.reasons.admit(reason, codeLabel.MatchString),
	).Inc()
}

// ResourceToken implements port.OIDCMetrics.
func (r *Registry) ResourceToken(resource, outcome string) {
	r.resTokens.WithLabelValues(
		r.resources.admit(resource, resourceLabel.MatchString),
		r.reasons.admit(outcome, codeLabel.MatchString),
	).Inc()
}

// Introspection implements port.OIDCMetrics.
func (r *Registry) Introspection(resource, outcome string) {
	r.introspect.WithLabelValues(
		r.resources.admit(resource, resourceLabel.MatchString),
		r.reasons.admit(outcome, codeLabel.MatchString),
	).Inc()
}

// PermissionChange implements port.OIDCMetrics.
func (r *Registry) PermissionChange(change string, grantsEnded int) {
	label := r.reasons.admit(change, codeLabel.MatchString)
	r.changes.WithLabelValues(label).Inc()

	if grantsEnded > 0 {
		r.ended.WithLabelValues(label).Add(float64(grantsEnded))
	}
}

// MailProcessed implements port.Metrics.
func (r *Registry) MailProcessed(class authflow.QuotaClass, outcome port.MailOutcome, queueDelay, sendDuration time.Duration) {
	r.mailJobs.WithLabelValues(string(outcome), string(class)).Inc()
	r.queueDelay.WithLabelValues(string(class)).Observe(queueDelay.Seconds())

	if sendDuration > 0 {
		r.sendTime.WithLabelValues(string(outcome)).Observe(sendDuration.Seconds())
	}
}

// RefreshReuseDetected implements port.Metrics.
func (r *Registry) RefreshReuseDetected() {
	r.reuse.Inc()
}

// QueueStatsFunc reads the current state of the mail queue.
type QueueStatsFunc func(ctx context.Context, now time.Time) (port.QueueStats, error)

// RegisterQueue adds the queue depth and the age of the oldest due job. The values are
// read on every scrape, so they are exact and need no background goroutine. A failed
// read drops the queue series from that scrape instead of reporting stale numbers.
func (r *Registry) RegisterQueue(stats QueueStatsFunc, clock port.Clock) error {
	return r.reg.Register(&queueCollector{
		stats: stats, clock: clock,
		depth:  prometheus.NewDesc("airlance_auth_mail_queue_depth", "Queued sign-in emails, leased or not, by quota class.", []string{"quota_class"}, nil),
		oldest: prometheus.NewDesc("airlance_auth_mail_oldest_due_wait_seconds", "Age of the oldest due queued email by quota class; 0 when none is due.", []string{"quota_class"}, nil),
		errors: prometheus.NewDesc("airlance_auth_mail_queue_stats_up", "1 if the queue could be read during this scrape.", nil, nil),
	})
}

// Handler serves the registry in the Prometheus text format.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

type queueCollector struct {
	stats                 QueueStatsFunc
	clock                 port.Clock
	depth, oldest, errors *prometheus.Desc
}

func (c *queueCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.depth

	ch <- c.oldest

	ch <- c.errors
}

func (c *queueCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := c.stats(ctx, c.clock.Now())
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.errors, prometheus.GaugeValue, 0)
		return
	}

	ch <- prometheus.MustNewConstMetric(c.errors, prometheus.GaugeValue, 1)

	for _, class := range classes {
		ch <- prometheus.MustNewConstMetric(c.depth, prometheus.GaugeValue, float64(stats.Queued[class]), string(class))

		ch <- prometheus.MustNewConstMetric(c.oldest, prometheus.GaugeValue, stats.OldestWait[class].Seconds(), string(class))
	}
}
