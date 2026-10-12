package bootstrap

import (
	"context"

	"airlance.org/auth/internal/adapter/id"
	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/config"
)

// openStore connects to the configured database in the configured schema.
func openStore(ctx context.Context, cfg config.Config, maxConns int32) (*postgres.Store, error) {
	return postgres.Open(ctx, cfg.Database.URL.Reveal(), id.Generator{},
		postgres.WithMaxConns(maxConns), postgres.WithSchema(cfg.Database.Schema))
}
