package quota

import (
	"errors"
	"math"
	"time"
)

// GuessBound is the conservative probability of one correct guess of a random code:
// min(1, A / (M - m + 1)) for M possible codes, m attempts per flow and A comparisons
// in total.
func GuessBound(codes, flowAttempts, comparisons int64) float64 {
	if codes <= 0 || flowAttempts <= 0 || flowAttempts > codes || comparisons < 0 {
		return 1
	}

	return math.Min(1, float64(comparisons)/float64(codes-flowAttempts+1))
}

// ComparisonBudget is the most code comparisons the unknown clients of one address can
// make in a period. Buckets of a fixed length touch ceil(period/Per)+1 buckets, so a
// burst on a boundary is counted; the tightest window decides.
func (p Profile) ComparisonBudget(period time.Duration) (int64, error) {
	ws := p.windows[UnknownVerifyEmail]
	if len(ws) == 0 {
		return 0, errors.New("the profile does not limit the verify budget of an address")
	}

	budget := int64(math.MaxInt64)

	for _, w := range ws {
		buckets := int64((period+w.Per-1)/w.Per) + 1
		if a := int64(w.Limit) * buckets; a < budget {
			budget = a
		}
	}

	return budget, nil
}
