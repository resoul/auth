package port

import (
	"context"

	"go.airlance.org/auth/internal/domain/quota"
)

// SpendKind is the quota being spent.
type SpendKind = quota.Kind

// Quota kinds.
const (
	SpendSend    = quota.KindSend
	SpendVerify  = quota.KindVerify
	SpendPasskey = quota.KindPasskey
	SpendAdmin   = quota.KindAdmin
	SpendDevice  = quota.KindDevice
	SpendOIDC    = quota.KindOIDC
)

// Spend identifies one quota expenditure; Now and IP are set by the use case.
type Spend = quota.Spend

// Limiter spends quotas atomically with the caller's transaction.
type Limiter interface {
	// Allow charges every budget the spend draws from and reports true, or reports
	// false and charges none. An exhausted quota is an expected denial, not an error.
	// Concurrent calls never admit more than a budget's limit within its window.
	Allow(ctx context.Context, spend Spend) (bool, error)
}
