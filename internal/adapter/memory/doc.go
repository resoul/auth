// Package memory is a test double of the PostgreSQL store: the same repositories behind the
// same UnitOfWork, held in maps. It exists so use-case tests run without a database, and it
// passes the same contract tests as the PostgreSQL adapter, so the two cannot drift apart.
//
// It is not a runtime mode of the service: nothing survives a restart and nothing is shared
// between processes. Production code must not import it; depguard in .golangci.yml enforces that.
package memory
