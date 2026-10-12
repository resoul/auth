package memory_test

import (
	"testing"

	"airlance.org/auth/internal/adapter/memory"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/quota"
	"airlance.org/auth/internal/testutil"
)

func TestStoreContract(t *testing.T) {
	testutil.RunStoreContract(t, func(*testing.T) port.UnitOfWork { return memory.NewStore() })
}

func TestLimiterContract(t *testing.T) {
	testutil.RunLimiterContract(t, func(_ *testing.T, p quota.Profile) port.UnitOfWork {
		return memory.NewStore(memory.WithQuota(p))
	})
}
