package bootstrap

import (
	"context"

	"go.airlance.org/auth/internal/adapter/id"
	"go.airlance.org/auth/internal/adapter/postgres"
	"go.airlance.org/auth/internal/config"
)

// openStore connects to the configured database in the configured schema.
func openStore(ctx context.Context, cfg config.Config, maxConns int32) (*postgres.Store, error) {
	return postgres.Open(ctx, cfg.Database.URL.Reveal(), id.Generator{},
		postgres.WithMaxConns(maxConns), postgres.WithSchema(cfg.Database.Schema))
}
