# AGENTS.md: Architectural Roles and Boundaries

This document defines the responsibilities for each module in the project.
We follow **Clean Architecture** (Ports & Adapters) principles — business logic stays decoupled from
external tools like Gin or GORM.

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
│   │   └── container.go    # Composition root — holds all singletons and wires layers
│   ├── domain/
│   │   ├── errors.go       # Sentinel errors — single source of truth for domain failures
│   │   └── profile.go      # Profile entity, ProfileRepository, ProfileService, input structs
│   ├── models/
│   │   └── user.go         # GORM-mapped struct for auth.users (read-only mirror)
│   ├── service/
│   │   └── profile_service.go  # ProfileService implementation
│   ├── infrastructure/
│   │   └── db/
│   │       ├── profile_repository.go   # GORM ProfileRepository implementation
│   │       └── migrations/
│   │           └── migrations.go       # gormigrate migration list
│   ├── middleware/
│   │   └── auth.go             # Bearer JWT validation → injects *middleware.AuthUser into context
│   ├── transport/
│   │   └── http/
│   │       ├── router/
│   │       │   └── router.go           # All route wiring — single source of truth
│   │       ├── handlers/
│   │       │   └── profile_handler.go  # GET /user/me, PATCH /user/profile
│   │       └── utils/
│   │           ├── errors.go           # MapError + RespondMapped
│   │           ├── respond.go          # RespondOK, RespondError, RespondCreated
│   │           └── response.go         # ErrorResponse struct
│   └── utilities/
│       └── version.go      # Build-time version variable (ldflags)
├── main.go
├── go.mod / go.sum
├── Makefile
└── .env
```

---

## 2. Layer Responsibilities

### A. CLI & Entry Point (`cmd/`)

- `root.go` — defines the root `studio` Cobra command; accepts `*sync.WaitGroup` from `main.go`.
- `serve.go` — calls `di.NewContainer`, reads `container.Config` (no second `config.Init`), wires
  `router.New`, starts HTTP server, handles graceful shutdown on context cancellation.
- `migrate.go` — opens a raw GORM connection and runs `gormigrate` commands; never shares the
  serve-time container.
- **No business logic in `cmd/`.**

### B. Config (`internal/config/`)

Loaded once per process inside `di.NewContainer`. Populated via `kelseyhightower/envconfig` with
`.env` support from `joho/godotenv`.

| Struct | Env prefix | Fields |
|---|---|---|
| `DatabaseConfig` | `DB_` | `DSN` (required) |
| `LoggingConfig` | `LOG_` | `Level` (default: `debug`) |
| `ServerConfig` | `SERVER_` | `Port` (default: `8080`) |
| `AuthConfig` | `AUTH_` | `URL` (required), `APIKey` (required), `JWTSecret` (required) |

**Rules:**
- `Init` panics on misconfiguration — fail fast at startup.
- `cmd/serve.go` reads `container.Config` — **never call `config.Init` a second time**.

### C. Domain Layer (`internal/domain/`)

The "language" of the project. **No external dependencies allowed here** — only stdlib.

| File | Contents |
|---|---|
| `errors.go` | Sentinel errors: `ErrNotFound`, `ErrConflict`, `ErrUnauthorized`, `ErrForbidden`, `ErrInvalidInput` |
| `profile.go` | `Profile` entity, `UpdateProfileInput`, `ProfileRepository` interface, `ProfileService` interface |

**Hard rules:**
- No imports from `service/`, `infrastructure/`, or `transport/`.
- All inter-layer data uses named structs — `map[string]any` is forbidden for domain types.
- New sentinel errors go in `errors.go`; new domain objects get their own file.

### D. Dependency Injection (`internal/di/`)

`Container` is the single composition root. Wiring order: config → DB → repositories → services.

| Field | Type | Source |
|---|---|---|
| `Config` | `*config.Config` | `config.Init(ctx)` — called **once**, here |
| `DB` | `*gorm.DB` | `openDB(cfg.DB.DSN)` |
| `ProfileService` | `domain.ProfileService` | `service.NewProfileService(profileRepo)` |

`Container.Close()` closes the underlying `*sql.DB`.

**Rules:**
- Handlers and services receive only the specific dependencies they need — **never the full container**.
- When adding a new resource: add its repository and service to `NewContainer`, expose only the
  service interface on `Container`.

### E. Models (`internal/models/`)

Thin GORM-mapped structs mirroring external schemas this service does not own.

| File | Struct | Table | Notes |
|---|---|---|---|
| `user.go` | `User` | `auth.users` | Read-only mirror of GoTrue auth schema |

`TableName()` must be explicitly defined for non-default schemas.

### F. Service Layer (`internal/service/`)

Business logic. Coordinates domain entities and repository interfaces.

**Hard rules:**
- Must NOT import from `transport/`, `infrastructure/`, or `handlers/`.
- Returns `domain.Err*` sentinel errors — never raw strings or HTTP codes.
- Must NOT know about Gin, GORM internals, or any HTTP concerns.

#### ProfileService (`profile_service.go`)

| Method | Behaviour |
|---|---|
| `GetOrCreate(ctx, userID)` | Returns existing profile or creates an empty one (idempotent). |
| `Update(ctx, userID, inp)` | Returns `ErrInvalidInput` if all fields in `inp` are nil. Reads current profile, patches non-nil fields, calls `Upsert`. Returns `ErrNotFound` if no profile exists. |

### G. Infrastructure Layer (`internal/infrastructure/`)

#### ProfileRepository (`db/profile_repository.go`)

GORM implementation of `domain.ProfileRepository`.

| Method | Notes |
|---|---|
| `FindByUserID` | Translates `gorm.ErrRecordNotFound` → `domain.ErrNotFound` at the boundary. |
| `Upsert` | Uses `clause.OnConflict` on `user_id` — atomic, no race between SELECT and INSERT. Updates only `display_name`, `avatar_url`, `bio`, `updated_at` on conflict. |

#### Migrations (`db/migrations/migrations.go`)

Returns `[]*gormigrate.Migration` consumed by `cmd/migrate.go`.

**Rules:**
- **FORBIDDEN:** `db.AutoMigrate()` at application startup.
- Reference `domain.*` structs in `Migrate` so column definitions stay in sync with the entity.
- Never remove or reorder existing entries — only append.
- Migrations run only via `api migrate up` / `api migrate down`.

Current migrations:

| ID | Description |
|---|---|
| `202404041700_initial_schema` | Creates `profiles` table via `AutoMigrate(&domain.Profile{})` |

### H. Middleware (`internal/middleware/`)

| File | Middleware | Context key |
|---|---|---|
| `auth.go` | `Auth(jwtSecret string)` | `ContextKeyUser = "user"` |

`Auth` validates the `Authorization: Bearer <token>` header using `golang-jwt/jwt/v5` with the
HS256 secret from `cfg.Auth.JWTSecret`. On success it injects `*middleware.AuthUser` into the Gin
context. On failure it calls `RespondError` + `c.Abort()` — downstream handlers are never reached.

```go
type AuthUser struct {
    ID    string
    Email string
    Role  string
}
```

`bearerToken()` uses `strings.SplitN(..., 2)` and `strings.EqualFold` for RFC 7235 compliance.

Handlers retrieve the authenticated user:

```go
raw, _ := c.Get(middleware.ContextKeyUser)
user := raw.(*middleware.AuthUser)
```

### I. Transport Layer (`internal/transport/http/`)

#### Router (`router/router.go`)

Single source of truth for all route definitions.

Signature: `router.New(cfg *config.Config, db *gorm.DB, profileSvc domain.ProfileService)`

Current routes:

| Method | Path | Auth | Handler |
|---|---|---|---|
| `GET` | `/api/v1/health` | — | inline |
| `GET` | `/api/v1/user/me` | ✅ | `ProfileHandler.GetMe` |
| `PATCH` | `/api/v1/user/profile` | ✅ | `ProfileHandler.UpdateProfile` |

Route groups:
- `api` (`/api/v1`) — base group, no auth.
- `authed` (`/api/v1/`) — `middleware.Auth(cfg.Auth.JWTSecret)` applied once; all protected routes go here.

**Rules:**
- Never attach auth middleware per-route — use the `authed` group.
- `r.NoRoute` returns a consistent `404` via `utils.RespondError`.

CORS is configured via `gin-contrib/cors` to allow `http://dashboard.studio.localhost`.

#### Handlers (`handlers/`)

| File | Handler | Routes |
|---|---|---|
| `profile_handler.go` | `ProfileHandler` | `GET /user/me`, `PATCH /user/profile` |

**Handler contract:**
1. Extract identity via `contextUser(c)` — set by `middleware.Auth`.
2. Bind and validate request body with `c.ShouldBindJSON`.
3. Call service method with `c.Request.Context()`.
4. On error → `utils.RespondMapped(c, err)`.
5. On success → `utils.RespondOK` / `utils.RespondCreated` / `c.Status(204)`.

`ProfileResponse` merges auth fields (`email`, `role`) with profile fields
(`display_name`, `avatar_url`, `bio`) — this merge happens only here.

#### Error Mapping (`utils/errors.go`)

| Domain error | HTTP | Code |
|---|---|---|
| `ErrNotFound` / `gorm.ErrRecordNotFound` | 404 | `not_found` |
| `ErrConflict` | 409 | `conflict` |
| `ErrUnauthorized` | 401 | `unauthorized` |
| `ErrForbidden` | 403 | `forbidden` |
| `ErrInvalidInput` | 400 | `invalid_input` |
| anything else | 500 | `internal_error` |

Use `utils.RespondMapped(c, err)` — **never duplicate this table** in handler code.

---

## 3. Data Flow

```
HTTP Request
  → middleware.Auth              (validates HS256 JWT, injects *middleware.AuthUser)
  → ProfileHandler               (extracts user, binds JSON)
  → ProfileService               (business rules, returns domain.Err* on failure)
  → ProfileRepository            (GORM query, translates gorm errors → domain errors)
  → PostgreSQL (schema: app)

HTTP Response
  ← ProfileResponse              (merged auth + profile fields)
  ← utils.RespondMapped          (domain error → HTTP status)
```

---

## 4. Auth Integration

Authentication uses **local JWT validation** — the token is issued by GoTrue (Supabase Auth) and
verified locally using the shared HS256 secret (`AUTH_JWT_SECRET`).

| Concern | Approach |
|---|---|
| Token validation | `golang-jwt/jwt/v5` with HS256, secret from `cfg.Auth.JWTSecret` |
| Identity in context | `*middleware.AuthUser` under `middleware.ContextKeyUser` |
| Session model | Stateless JWT — no server-side session storage |

Claims extracted from the JWT: `sub` → `ID`, `email` → `Email`, `role` → `Role`.

---

## 5. Entry Point (`main.go`)

- Configures `logrus` JSON formatter globally.
- Creates `signal.NotifyContext` cancelling on `SIGTERM`, `SIGHUP`, `SIGINT`.
- Passes `*sync.WaitGroup` to `cmd.RootCommand` for coordinated cleanup.
- Waits up to **30 seconds** for goroutines after `ExecuteContext` returns.

---

## 6. Build & Tooling

| Target | Description |
|---|---|
| `build` / `studio` | Native OS/arch binary |
| `deps` | `go mod download && verify` |

Version injected via: `-X github.com/resoul/api/internal/utilities.Version=$(VERSION)`

All binaries: `CGO_ENABLED=0`.

---

## 7. Configuration Reference (`.env`)

| Variable | Required | Default | Description |
|---|---|---|---|
| `DB_DSN` | ✅ | — | PostgreSQL DSN (`host=db user=app ...`) |
| `LOG_LEVEL` | — | `debug` | Logrus log level |
| `SERVER_PORT` | — | `8080` | HTTP listen port |
| `AUTH_URL` | ✅ | — | GoTrue base URL (`http://auth:9999`) |
| `AUTH_API_KEY` | ✅ | — | GoTrue service-role JWT |
| `AUTH_JWT_SECRET` | ✅ | — | HS256 secret for local JWT validation |

---

## 8. Technology Stack

| Concern | Tool |
|---|---|
| CLI | [Cobra](https://github.com/spf13/cobra) |
| Web Framework | [Gin Gonic](https://github.com/gin-gonic/gin) |
| ORM | [GORM](https://gorm.io/) |
| Migrations | [gormigrate](https://github.com/go-gormigrate/gormigrate) |
| JWT validation | [golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt) (HS256) |
| Database | PostgreSQL 16 (pgx/v5 driver) |
| Config | envconfig + godotenv |
| Logging | logrus (JSON) |

---

## 9. Known Issues / Technical Debt

| Location | Issue | Recommendation |
|---|---|---|
| `models/user.go` | Sits in `models/` alongside GORM structs | Keep `models/` for DB-only mirrors of external schemas; use `domain/` for owned entities with business logic |
| `utils/response.go` | `ErrorResponse.Details` uses `map[string]interface{}` | Acceptable for validation field errors only; all other payloads must use named structs |
| `middleware/auth.go` | Claims cast without type assertion safety (`claims["sub"].(string)`) | Add safe assertion with fallback to avoid panic on malformed tokens |

---

## 10. Adding a New Resource (Checklist)

- [ ] `internal/domain/<resource>.go` — entity, repository interface, service interface, input structs
- [ ] `internal/domain/errors.go` — add sentinel errors for new failure modes
- [ ] `internal/infrastructure/db/<resource>_repository.go` — GORM implementation
- [ ] `internal/infrastructure/db/migrations/migrations.go` — append new migration using `&domain.<Resource>{}`
- [ ] `internal/service/<resource>_service.go` — business logic
- [ ] `internal/transport/http/handlers/<resource>_handler.go` — handler + typed response struct
- [ ] `internal/transport/http/router/router.go` — register routes (inside `authed` group if protected)
- [ ] `internal/transport/http/utils/errors.go` — extend `MapError` if new sentinel errors added
- [ ] `internal/di/container.go` — wire repo → service, expose service on `Container`
- [ ] `cmd/serve.go` — pass new service to `router.New`

---

## 11. Communication Patterns

1. **Strong Typing** — named structs everywhere. `gin.H` only for trivial inline responses (health check).
2. **Dependency Injection** — all deps via `New…` constructors; nothing reaches into `Container` directly.
3. **Config Ownership** — `config.Init` called exactly once inside `di.NewContainer`.
4. **Sentinel Errors** — services return `domain.Err*`; transport maps via `utils.MapError`. Never hand-code HTTP statuses for domain conditions.
5. **Context Propagation** — `context.Context` passed from handler down to GORM calls.
6. **Graceful Shutdown** — `main.go` owns signals; `cmd/serve.go` owns `http.Server.Shutdown`; goroutines coordinate via `*sync.WaitGroup`.
7. **Migration Strategy** — reference domain structs in `Migrate()` functions so column definitions never diverge from entities.
