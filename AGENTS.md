# AGENTS.md: Architectural Roles and Boundaries

This document defines the responsibilities for each module in the project.
We follow **Clean Architecture** (Ports & Adapters) principles — business logic stays decoupled from
external tools like Supabase Auth, Gin, or GORM.

---

## 1. Project Structure

```text
.
├── cmd/
│   ├── root.go             # Cobra root command, WaitGroup injection
│   ├── serve.go            # HTTP server lifecycle — no route wiring, no business logic
│   └── migrate.go          # Migration CLI (up / down), never shares serve-time container
├── internal/
│   ├── config/
│   │   └── config.go       # Env-based config (envconfig + godotenv)
│   ├── di/
│   │   └── container.go    # Composition root — holds all singletons
│   ├── models/
│   │   └── user.go         # Shared DB-mapped structs (auth.users mirror)
│   ├── infrastructure/
│   │   └── db/
│   │       └── migrations/
│   │           └── migrations.go   # gormigrate migration list
│   ├── transport/
│   │   └── http/
│   │       ├── router/
│   │       │   ├── router.go       # All route wiring — single source of truth
│   │       │   └── profile.go      # Profile handler (inline, pre-extraction)
│   │       └── utils/
│   │           ├── respond.go      # RespondOK, RespondError, RespondCreated
│   │           └── response.go     # ErrorResponse struct
│   └── utilities/
│       └── version.go      # Build-time version variable (ldflags)
├── main.go                 # Signal handling, WaitGroup, Cobra entry point
├── go.mod
├── go.sum
├── Makefile
└── .env
```

---

## 2. Layer Responsibilities

### A. CLI & Entry Point (`cmd/`)

- `root.go` — defines the root `studio` Cobra command; accepts a `*sync.WaitGroup` from `main.go`
  for coordinated graceful shutdown.
- `serve.go` — initialises `di.Container`, wires dependencies, starts the Gin router and HTTP
  server, handles graceful shutdown on context cancellation. **No route definitions here.**
- `migrate.go` — opens a raw GORM connection and runs `gormigrate` commands (`up` / `down`);
  never shares the serve-time container.
- **No business logic in `cmd/`** — delegate everything to service/handler layers.

### B. Config (`internal/config/`)

Loaded once per process via `config.Init(ctx)`. Populated from environment variables using
`kelseyhightower/envconfig` with `.env` file support via `joho/godotenv`.

| Struct | Env Prefix | Fields |
|--------|-----------|--------|
| `DatabaseConfig` | `DB_` | `DSN` (required) |
| `LoggingConfig` | `LOG_` | `Level` (default: `debug`) |
| `ServerConfig` | `SERVER_` | `Port` (default: `8080`) |
| `AuthConfig` | `AUTH_` | `URL` (required), `APIKey` (required) |

**Rules:**
- `Init` panics on misconfiguration — fail fast at startup, never at request time.
- Config structs are passed by pointer to constructors; never read env vars outside this package.

### C. Dependency Injection (`internal/di/`)

`Container` is the single composition root constructed in `cmd/serve.go`.

| Field | Type | Source |
|-------|------|--------|
| `Config` | `*config.Config` | `config.Init(ctx)` |
| `DB` | `*gorm.DB` | `postgres.Open(cfg.DB.DSN)` |
| `Auth` | `auth.Client` | `auth.New(cfg.Auth.URL, cfg.Auth.APIKey)` |

Connection pool settings applied to `*sql.DB` underlying GORM:

| Setting | Value |
|---------|-------|
| `MaxOpenConns` | 25 |
| `MaxIdleConns` | 5 |
| `ConnMaxLifetime` | 1 hour |

`Container.Close()` closes the underlying `*sql.DB`; called via `defer` in `cmd/serve.go`.

**Rules:**
- Handlers and services receive only the specific dependencies they need — **never the full container**.
- Optional infrastructure (future: RabbitMQ, MinIO) must not prevent startup on absence.

### D. Models (`internal/models/`)

Thin GORM-mapped structs that mirror external or shared DB schemas.

| File | Struct | Table |
|------|--------|-------|
| `user.go` | `User` | `auth.users` |

`User` is a **read-only mirror** of the Supabase `auth.users` table — it is never written to by
this application. It exists solely for JOIN queries or direct lookups when the auth SDK is
insufficient.

**Rules:**
- No business logic in model structs.
- `TableName()` must be explicitly defined when the table lives in a non-default schema (e.g. `auth.users`).

### E. Infrastructure (`internal/infrastructure/`)

#### Migrations (`db/migrations/migrations.go`)

- Returns a `[]*gormigrate.Migration` slice consumed by `cmd/migrate.go`.
- **FORBIDDEN:** `db.AutoMigrate()` inside application startup.
- Each migration entry has a unique time-prefixed ID: `YYYYMMDDHHMI_<description>`.
- `Migrate` function uses `tx.AutoMigrate(models...)` or raw SQL; `Rollback` undoes it cleanly.
- Migrations run only via `api migrate up` / `api migrate down` — never at serve time.

> **Current state:** one placeholder migration (`202404041700_initial_schema`) with empty
> `AutoMigrate()` call. Populate with actual model structs as the schema evolves.

### F. Transport Layer (`internal/transport/http/`)

#### Router (`router/router.go`)

Single source of truth for all route definitions. Constructed via `router.New(cfg, db, authClient)`;
returns a ready `*gin.Engine`.

Current routes:

| Method | Path | Handler |
|--------|------|---------|
| `GET` | `/api/v1/health` | inline — returns `{"status":"ok"}` |
| `GET` | `/api/v1/profile` | `ProfileHandler(authClient)` |

**Rules:**
- All routes live under a versioned group (`/api/v1`).
- Adding a new endpoint means editing only this file (+ creating a handler file if needed).
- Never hand-code HTTP status codes for domain/auth errors — use `utils.RespondError`.

#### Handlers (`router/profile.go` — inline, to be extracted)

`ProfileHandler` is currently co-located in the `router/` package. As the project grows, handlers
must be extracted to `transport/http/handlers/<resource>_handler.go`.

**Current handler contract:**

1. Extract `Authorization: Bearer <token>` header; reject with `401` if missing or malformed.
2. Call `authClient.WithToken(token).GetUser()` to validate the token and fetch identity.
3. On auth error → `utils.RespondError(c, 401, ...)`.
4. On success → `utils.RespondOK(c, payload)`.

**Future handler contract (once service layer is added):**

1. Extract identity from context (set by auth middleware).
2. Bind and validate request (JSON or multipart).
3. Call the service method.
4. On error → `utils.RespondMapped(c, err)` — never hand-code status codes for domain errors.
5. On success → `utils.RespondOK` / `utils.RespondCreated` / `c.Status(204)`.

#### Utils (`transport/http/utils/`)

| File | Exports |
|------|---------|
| `respond.go` | `RespondOK`, `RespondError`, `RespondCreated` |
| `response.go` | `ErrorResponse{Error, Message, Details}` |

**Rules:**
- All JSON responses go through these helpers — never call `c.JSON` directly in handlers.
- `ErrorResponse.Details` is `map[string]interface{}` for validation field errors only; all other
  payloads use named structs.

---

## 3. Auth Integration (Supabase Auth)

Authentication is handled via `supabase-community/auth-go` client.

| Concern | Approach |
|---------|----------|
| Token validation | `authClient.WithToken(jwt).GetUser()` — validates JWT with the auth server |
| Identity | `auth.User` struct returned by `GetUser()` |
| Session | Stateless JWT — no server-side session storage |
| Auth server URL | `AUTH_URL` env var |
| Auth API key | `AUTH_API_KEY` env var (service-role key) |

**Current pattern (inline in handler):** the Bearer token is extracted and validated per-handler.

**Target pattern (middleware):** extract token validation into a Gin middleware that injects
`*auth.User` into `gin.Context`, so handlers can call `c.MustGet("user").(*auth.User)` without
repeating auth logic.

---

## 4. Entry Point (`main.go`)

Responsibilities:
- Configures `logrus` JSON formatter globally.
- Creates a `signal.NotifyContext` cancelling on `SIGTERM`, `SIGHUP`, `SIGINT`.
- Passes a `*sync.WaitGroup` to `cmd.RootCommand` for coordinated cleanup.
- After `ExecuteContext` returns, waits up to **30 seconds** for background goroutines to finish
  before exiting; logs an error if timeout is exceeded.

---

## 5. Build & Tooling

### Makefile targets

| Target | Description |
|--------|-------------|
| `build` | Builds all three binary variants |
| `studio` | Native (current OS/arch) |
| `studio-x86` | `linux/amd64` |
| `studio-arm64` | `linux/arm64` |
| `studio-darwin-arm64` | `linux/arm64` (cross-compile from Darwin) |
| `deps` | `go mod download && go mod verify` |

Build version is injected via ldflags into `internal/utilities.Version`:

```
-X github.com/resoul/api/internal/utilities.Version=$(VERSION)
```

`VERSION` resolves to `git describe --tags` or `v$(RELEASE_VERSION)` if set.

All binaries are built with `CGO_ENABLED=0` for static linking.

---

## 6. Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DB_DSN` | ✅ | — | PostgreSQL DSN |
| `LOG_LEVEL` | — | `debug` | Logrus log level |
| `SERVER_PORT` | — | `8080` | HTTP listen port |
| `AUTH_URL` | ✅ | — | Supabase Auth base URL |
| `AUTH_API_KEY` | ✅ | — | Supabase service-role JWT |

---

## 7. Technology Stack

| Concern | Tool |
|---------|------|
| CLI | [Cobra](https://github.com/spf13/cobra) |
| Web Framework | [Gin Gonic](https://github.com/gin-gonic/gin) |
| ORM | [GORM](https://gorm.io/) |
| Migrations | [gormigrate](https://github.com/go-gormigrate/gormigrate) |
| Auth | [Supabase Auth](https://github.com/supabase-community/auth-go) |
| Database | PostgreSQL (via `pgx/v5` driver) |
| Config | envconfig + godotenv |
| Logging | logrus (JSON formatter) |

---

## 8. Known Issues / Technical Debt

| Location | Issue | Recommendation |
|----------|-------|----------------|
| `router/profile.go` | Handler lives in `router/` package, not `handlers/` | Extract to `transport/http/handlers/profile_handler.go` |
| `router/profile.go` | Auth token validation duplicated per-handler | Extract into a `middleware/auth.go` Gin middleware that injects `*auth.User` into context |
| `router/profile.go` | Response payload uses `gin.H` (raw map) | Replace with a typed `ProfileResponse` struct |
| `di/container.go` | `Config` field on `Container` is exposed but `serve.go` re-calls `config.Init` independently | Pass `container.Config` to `router.New` instead of calling `config.Init` twice |
| `migrations/migrations.go` | Placeholder migration has empty `AutoMigrate()` call | Populate with actual model structs or raw SQL as schema is defined |
| `models/user.go` | Lives in `internal/models/` but AGENTS.md previously prescribed `internal/domain/` | Decide on canonical location: `models/` for DB structs, `domain/` for business entities — keep them separate |
| `utils/response.go` | `ErrorResponse.Details` uses `map[string]interface{}` | Acceptable for validation errors only; all other payloads must use named structs |

---

## 9. Adding a New Resource (Checklist)

When introducing a new domain object (e.g. `Workspace`, `Project`):

- [ ] Add entity struct to `internal/models/<resource>.go` (GORM-mapped) or `internal/domain/<resource>.go` (business logic)
- [ ] Add repository interface + service interface to `internal/domain/<resource>.go` if adding a service layer
- [ ] Add sentinel errors to `domain/errors.go` if new failure modes are needed
- [ ] Implement repository in `internal/infrastructure/db/<resource>_repository.go`
- [ ] Add migration entry in `internal/infrastructure/db/migrations/migrations.go`
- [ ] Implement service in `internal/service/<resource>_service.go`
- [ ] Add handler file in `internal/transport/http/handlers/<resource>_handler.go`
- [ ] Register routes in `internal/transport/http/router/router.go`
- [ ] Add error mapping in `utils/errors.go` (`MapError` + `RespondMapped`) if new sentinel errors were added
- [ ] Wire repository → service → handler in `cmd/serve.go` (via `di.Container`)
- [ ] Update `di/container.go` with any new infrastructure singletons

---

## 10. Communication Patterns

1. **Strong Typing** — inter-layer data uses named structs. `gin.H` / `map[string]any` only for
   one-off inline responses (health check); never for domain payloads.
2. **Dependency Injection** — all dependencies passed via `New…` constructors; handlers never
   reach into the container directly.
3. **Context Propagation** — `context.Context` threaded from handler down to GORM queries and
   external HTTP calls.
4. **Graceful Shutdown** — `main.go` owns signal handling; `cmd/serve.go` owns `http.Server.Shutdown`;
   background goroutines coordinate via the shared `*sync.WaitGroup`.
5. **Graceful Degradation** — optional infrastructure must not prevent startup. Guard with nil
   checks before use.
