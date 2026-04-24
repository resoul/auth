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
│   ├── domain/
│   │   └── errors.go       # Sentinel errors — single source of truth for domain failures
│   ├── models/
│   │   └── user.go         # GORM-mapped structs (auth.users mirror — read-only)
│   ├── infrastructure/
│   │   └── db/
│   │       └── migrations/
│   │           └── migrations.go   # gormigrate migration list
│   ├── transport/
│   │   └── http/
│   │       ├── router/
│   │       │   └── router.go       # All route wiring — single source of truth
│   │       ├── handlers/
│   │       │   └── profile_handler.go  # GET /user/me
│   │       ├── middleware/
│   │       │   └── auth.go         # Bearer token validation → injects *types.User into context
│   │       └── utils/
│   │           ├── errors.go       # MapError + RespondMapped
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

- `root.go` — defines the root `studio` Cobra command; accepts a `*sync.WaitGroup` from `main.go`.
- `serve.go` — calls `di.NewContainer`, uses `container.Config` directly (no second `config.Init`),
  wires router, starts HTTP server, handles graceful shutdown.
- `migrate.go` — opens a raw GORM connection and runs `gormigrate` commands; never shares the
  serve-time container.
- **No business logic in `cmd/`.**

### B. Config (`internal/config/`)

Loaded once per process via `config.Init(ctx)` inside `di.NewContainer`. Populated from environment
variables using `kelseyhightower/envconfig` with `.env` support via `joho/godotenv`.

| Struct | Env Prefix | Fields |
|--------|-----------|--------|
| `DatabaseConfig` | `DB_` | `DSN` (required) |
| `LoggingConfig` | `LOG_` | `Level` (default: `debug`) |
| `ServerConfig` | `SERVER_` | `Port` (default: `8080`) |
| `AuthConfig` | `AUTH_` | `URL` (required), `APIKey` (required) |

**Rules:**
- `Init` panics on misconfiguration — fail fast at startup.
- `cmd/serve.go` must use `container.Config` — **never call `config.Init` a second time**.

### C. Domain Layer (`internal/domain/`)

The "language" of the project. **No external dependencies allowed here.**

| File | Contents |
|------|----------|
| `errors.go` | Sentinel errors: `ErrNotFound`, `ErrConflict`, `ErrUnauthorized`, `ErrForbidden`, `ErrInvalidInput` |

Add new sentinel errors here as new failure modes are introduced. Never define domain errors
outside this package.

### D. Dependency Injection (`internal/di/`)

`Container` is the single composition root, constructed once in `cmd/serve.go`.

| Field | Type | Source |
|-------|------|--------|
| `Config` | `*config.Config` | `config.Init(ctx)` — called **once**, here |
| `DB` | `*gorm.DB` | `openDB(cfg.DB.DSN)` |
| `Auth` | `auth.Client` | `auth.New(cfg.Auth.URL, cfg.Auth.APIKey)` |

Connection pool settings applied to the underlying `*sql.DB`:

| Setting | Value |
|---------|-------|
| `MaxOpenConns` | 25 |
| `MaxIdleConns` | 5 |
| `ConnMaxLifetime` | 1 hour |

`Container.Close()` closes the underlying `*sql.DB`; called via `defer` in `cmd/serve.go`.

**Rules:**
- Handlers and services receive only the specific dependencies they need — **never the full container**.
- Optional infrastructure (future: RabbitMQ, MinIO) must not prevent startup on absence.

### E. Models (`internal/models/`)

Thin GORM-mapped structs mirroring external or shared DB schemas.

| File | Struct | Table | Notes |
|------|--------|-------|-------|
| `user.go` | `User` | `auth.users` | Read-only mirror of Supabase auth schema |

`TableName()` must be explicitly defined when the table lives in a non-default schema.

### F. Infrastructure (`internal/infrastructure/`)

#### Migrations (`db/migrations/migrations.go`)

Returns `[]*gormigrate.Migration` consumed by `cmd/migrate.go`.

**Rules:**
- **FORBIDDEN:** `db.AutoMigrate()` inside application startup.
- Each migration has a unique time-prefixed ID: `YYYYMMDDHHMI_<description>`.
- Never remove or reorder existing entries — only append.
- Migrations run only via `api migrate up` / `api migrate down`.

Current migrations:

| ID | Description |
|----|-------------|
| `202404041700_initial_schema` | Placeholder — no-op, kept for history continuity |
| `202504240001_create_profiles` | `profiles` table with `user_id` unique index |

### G. Transport Layer (`internal/transport/http/`)

#### Router (`router/router.go`)

Single source of truth for all route definitions. Adding a new endpoint means editing only this file.

Current routes:

| Method | Path | Auth | Handler |
|--------|------|------|---------|
| `GET` | `/api/v1/health` | — | inline |
| `GET` | `/api/v1/user/me` | ✅ | `ProfileHandler.GetMe` |

Route groups:
- `api` (`/api/v1`) — base group, no auth.
- `authed` (`/api/v1/`) — protected group, `middleware.Auth` applied once for all children.

**Rules:**
- All routes under versioned prefix `/api/v1`.
- Never register auth middleware per-route — attach it to the group.
- `r.NoRoute` returns a consistent `404` via `utils.RespondError`.

#### Handlers (`handlers/`)

| File | Handler | Routes |
|------|---------|--------|
| `profile_handler.go` | `ProfileHandler` | `GET /user/me` |

**Handler contract:**
1. Extract identity via `contextUser(c)` — injected by `middleware.Auth`.
2. Bind and validate request (JSON or multipart).
3. Call the service method (when service layer is added).
4. On error → `utils.RespondMapped(c, err)` — never hand-code status codes for domain errors.
5. On success → `utils.RespondOK` / `utils.RespondCreated` / `c.Status(204)`.

Response payloads must use **named structs** — never `gin.H` except for trivial inline responses
like the health check.

#### Middleware (`middleware/`)

| File | Middleware | Description |
|------|-----------|-------------|
| `auth.go` | `Auth(authClient)` | Validates Bearer token via Supabase Auth; injects `*types.User` into context under key `ContextKeyUser` |

`ContextKeyUser = "user"` — exported constant; all handlers use it to retrieve the identity.

On any auth failure the middleware calls `c.Abort()` after writing the error response —
downstream handlers are never reached.

#### Error Mapping (`utils/errors.go`)

`MapError(err) HTTPError` converts domain sentinel errors to HTTP status codes.
`RespondMapped(c, err)` calls `MapError` and writes the JSON response in one call.

| Domain error | HTTP status | Code |
|---|---|---|
| `ErrNotFound` / `gorm.ErrRecordNotFound` | 404 | `not_found` |
| `ErrConflict` | 409 | `conflict` |
| `ErrUnauthorized` | 401 | `unauthorized` |
| `ErrForbidden` | 403 | `forbidden` |
| `ErrInvalidInput` | 400 | `invalid_input` |
| anything else | 500 | `internal_error` |

Use `utils.RespondMapped(c, err)` in handlers — **never duplicate this table** in handler code.

#### Utils (`transport/http/utils/`)

| File | Exports |
|------|---------|
| `errors.go` | `MapError`, `RespondMapped`, `HTTPError` |
| `respond.go` | `RespondOK`, `RespondError`, `RespondCreated` |
| `response.go` | `ErrorResponse{Error, Message, Details}` |

---

## 3. Auth Integration (Supabase Auth)

| Concern | Approach |
|---------|----------|
| Token validation | `authClient.WithToken(jwt).GetUser()` in `middleware.Auth` |
| Identity in context | `*types.User` under key `middleware.ContextKeyUser` |
| Session | Stateless JWT — no server-side session storage |
| Auth server URL | `AUTH_URL` env var |
| Auth API key | `AUTH_API_KEY` env var (service-role key) |

Handlers retrieve the authenticated user with:

```go
user, ok := c.Get(middleware.ContextKeyUser)
// or via the contextUser() helper in the handlers package
```

---

## 4. Entry Point (`main.go`)

- Configures `logrus` JSON formatter globally.
- Creates a `signal.NotifyContext` cancelling on `SIGTERM`, `SIGHUP`, `SIGINT`.
- Passes a `*sync.WaitGroup` to `cmd.RootCommand` for coordinated cleanup.
- Waits up to **30 seconds** for background goroutines after `ExecuteContext` returns.

---

## 5. Build & Tooling

### Makefile targets

| Target | Description |
|--------|-------------|
| `build` | Builds all three binary variants |
| `studio` | Native (current OS/arch) |
| `studio-x86` | `linux/amd64` |
| `studio-arm64` | `linux/arm64` |
| `studio-darwin-arm64` | `linux/arm64` cross-compile |
| `deps` | `go mod download && go mod verify` |

Build version injected via ldflags into `internal/utilities.Version`:
```
-X github.com/resoul/api/internal/utilities.Version=$(VERSION)
```

All binaries built with `CGO_ENABLED=0`.

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
| `models/user.go` | Lives in `internal/models/` alongside GORM structs | As domain grows: keep `models/` for DB-mapped structs, use `domain/` strictly for business entities and interfaces |
| `utils/response.go` | `ErrorResponse.Details` uses `map[string]interface{}` | Acceptable for validation errors only; all other payloads must use named structs |

---

## 9. Adding a New Resource (Checklist)

When introducing a new domain object (e.g. `Workspace`, `Project`):

- [ ] Add entity struct to `internal/models/<resource>.go` (GORM) and/or `internal/domain/<resource>.go` (business logic + interfaces)
- [ ] Add repository interface + service interface to `internal/domain/<resource>.go`
- [ ] Add sentinel errors to `internal/domain/errors.go` if new failure modes are needed
- [ ] Implement repository in `internal/infrastructure/db/<resource>_repository.go`
- [ ] Add migration entry in `internal/infrastructure/db/migrations/migrations.go`
- [ ] Implement service in `internal/service/<resource>_service.go`
- [ ] Add handler file in `internal/transport/http/handlers/<resource>_handler.go`
- [ ] Register routes in `internal/transport/http/router/router.go` (inside `authed` group if auth required)
- [ ] Extend `utils/errors.go` mapper if new sentinel errors were added
- [ ] Wire repository → service → handler in `cmd/serve.go` (via `di.Container` fields)
- [ ] Update `di/container.go` with any new infrastructure singletons

---

## 10. Communication Patterns

1. **Strong Typing** — inter-layer data uses named structs. `gin.H` only for trivial inline responses (health check); never for domain payloads.
2. **Dependency Injection** — all dependencies passed via `New…` constructors; handlers never reach into the container directly.
3. **Config Ownership** — `config.Init` is called exactly once, inside `di.NewContainer`; `cmd/serve.go` reads `container.Config`.
4. **Sentinel Errors** — services return `domain.Err*` values; the transport layer maps them to HTTP codes via `utils.MapError`. Never hand-code HTTP status codes for domain conditions.
5. **Context Propagation** — `context.Context` threaded from handler down to GORM queries and external HTTP calls.
6. **Graceful Shutdown** — `main.go` owns signal handling; `cmd/serve.go` owns `http.Server.Shutdown`; background goroutines coordinate via `*sync.WaitGroup`.
7. **Graceful Degradation** — optional infrastructure must not prevent startup; guard with nil checks before use.
