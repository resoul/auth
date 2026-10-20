GOLANGCI_LINT_VERSION := v2.14.0
GOVULNCHECK_VERSION   := v1.8.0
GITLEAKS_IMAGE        := ghcr.io/gitleaks/gitleaks:v8.28.0
KUBECONFORM_IMAGE     := ghcr.io/yannh/kubeconform:v0.7.0
KUBE_VERSION          := 1.33.0
SQLC_VERSION          := v1.31.1
OAPI_CODEGEN_VERSION  := v2.8.0

BIN   := $(CURDIR)/bin
LINT  := $(BIN)/golangci-lint
VULN  := $(BIN)/govulncheck
SQLC  := $(BIN)/sqlc
OAPI  := $(BIN)/oapi-codegen
OAPI_CONFIG := api/openapi/oapi-codegen.yaml
OAPI_SPEC   := api/openapi/auth.yaml
OAPI_OUTPUT := internal/transport/http/openapi/openapi.gen.go
COMPOSE := docker compose -f deploy/compose.yaml
# Function bodies on their own lines; gofmt keeps one-line bodies and golangci-lint has no rule against them.
FUNCSTYLE := go run ./tools/funcstyle -exclude '^(internal/transport/http/openapi/openapi\.gen\.go|internal/adapter/postgres/sqlc/)'
# Local database from deploy/compose.yaml; its credentials are for that throwaway container only.
DATABASE_URL ?= postgres://airlance_auth:airlance_auth@127.0.0.1:5432/airlance_auth?sslmode=disable

export PYTHONDONTWRITEBYTECODE := 1

.PHONY: help build tools fmt fmt-check lint vet test test-race test-int test-scripts test-browser migrate \
	generate generate-check vuln tidy-check check ci up down demo tunnel real real-check test-e2e backup backup-check restore quota-load test-alerts secrets kube-check

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "%-16s %s\n", $$1, $$2}'

build: ## Build bin/airlance-auth
	go build -o $(BIN)/airlance-auth ./cmd/airlance-auth

tools: $(LINT) $(VULN) $(SQLC) $(OAPI) ## Install pinned tools into bin/

$(LINT):
	GOBIN=$(BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(VULN):
	GOBIN=$(BIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

$(SQLC):
	GOBIN=$(BIN) go install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)

$(OAPI):
	GOBIN=$(BIN) go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION)

generate: $(SQLC) $(OAPI) ## Regenerate sqlc code and the OpenAPI types/server
	$(SQLC) generate -f internal/adapter/postgres/sqlc.yaml
	$(OAPI) -config $(OAPI_CONFIG) $(OAPI_SPEC)
	@tmp=$$(mktemp) && sed '/^\/\/ Package openapi /,/^\/\/ Code generated /d' $(OAPI_OUTPUT) > "$$tmp" && mv "$$tmp" $(OAPI_OUTPUT)

# oapi-codegen ignores -o when a config is given, so the check generates from a copy
# of the config that points into a temporary directory.
generate-check: $(SQLC) $(OAPI) ## Fail if generated code is out of date
	$(SQLC) diff -f internal/adapter/postgres/sqlc.yaml
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
		sed 's|^output: .*|output: '"$$tmp"'/openapi.gen.go|' $(OAPI_CONFIG) > "$$tmp/config.yaml" && \
		$(OAPI) -config "$$tmp/config.yaml" $(OAPI_SPEC) && \
		sed '/^\/\/ Package openapi /,/^\/\/ Code generated /d' "$$tmp/openapi.gen.go" > "$$tmp/openapi.normalized.go" && \
		diff -u $(OAPI_OUTPUT) "$$tmp/openapi.normalized.go"

fmt: $(LINT) ## Format Go code
	$(FUNCSTYLE) -fix .
	$(LINT) fmt ./...

fmt-check: $(LINT) ## Fail if Go code is not formatted
	$(LINT) fmt --diff ./...

lint: $(LINT) ## Static checks including import boundaries and one-line function bodies
	$(FUNCSTYLE) .
	$(LINT) run ./...

vet:
	go vet ./...

test: ## Fast unit suite
	go test ./...

test-race: ## Unit suite with the race detector
	go test -race -count=1 ./...

test-int: ## Integration suite against PostgreSQL (make up first)
	AIRLANCE_AUTH_TEST_DATABASE_URL=$(DATABASE_URL) go test -race -count=1 -tags=integration ./...

test-e2e: ## End-to-end scenarios of the built binary against PostgreSQL and Mailpit (make up first)
	AIRLANCE_AUTH_TEST_DATABASE_URL=$(DATABASE_URL) go test -count=1 -tags=e2e -timeout 5m ./tests/...

LOAD_REQUESTS ?= 1000
LOAD_WORKERS ?= 1,8,32
LOAD_POOL ?= 8
LOAD_SCENARIOS ?= passkey_ip,passkey_ref_rotating_ip,passkey_ipv6_64,passkey_unknown_ip,passkey_distributed,email_change_new_address,email_change_shared_ip,email_change_distributed,email_verify_rotating_clients

quota-load: ## Measure PostgreSQL quotas in isolated schemas; save JSON report in .secrets/load/
	AIRLANCE_AUTH_TEST_DATABASE_URL=$(DATABASE_URL) python3 scripts/quota_load.py --requests "$(LOAD_REQUESTS)" --workers "$(LOAD_WORKERS)" --pool "$(LOAD_POOL)" --scenarios "$(LOAD_SCENARIOS)"

PROMETHEUS_IMAGE := prom/prometheus:v3.5.0

test-alerts: ## Check the alert rules and run their unit tests with promtool (needs Docker)
	docker run --rm -v "$(CURDIR)/deploy:/rules:ro" -w /rules --entrypoint promtool $(PROMETHEUS_IMAGE) check rules alerts.yaml
	docker run --rm -v "$(CURDIR)/deploy:/rules:ro" -w /rules --entrypoint promtool $(PROMETHEUS_IMAGE) test rules alerts_test.yaml

test-scripts: $(LINT) ## Tests of the repository check scripts
	PATH="$(BIN):$$PATH" python3 -m unittest discover -s scripts

test-browser: ## Browser example regressions: cancellation, tabs and QR (needs node)
	node --test examples/browser/app.test.cjs

vuln: $(VULN)
	$(VULN) ./...

secrets: ## Scan the git history for committed secrets (needs Docker; CI runs the same image)
	docker run --rm -v "$(CURDIR)":/repo $(GITLEAKS_IMAGE) git /repo --config /repo/.gitleaks.toml --no-banner --redact --verbose

kube-check: ## Build the Kubernetes manifests and validate them against the API schemas (needs kubectl and Docker)
	@tmp=$$(mktemp) && trap 'rm -f "$$tmp"' EXIT && \
		{ kubectl kustomize deploy/kubernetes; echo '---'; kubectl kustomize deploy/kubernetes/migrate; } > "$$tmp" && \
		docker run --rm -v "$$tmp":/manifests.yaml $(KUBECONFORM_IMAGE) -strict -summary -kubernetes-version $(KUBE_VERSION) /manifests.yaml

tidy-check: ## Fail if go.mod/go.sum are not tidy
	go mod tidy -diff

check: fmt-check lint vet test-race tidy-check ## Everything CI runs except vuln and script tests

ci: check generate-check test-scripts test-browser test-alerts vuln secrets kube-check ## Local equivalent of the checks in .gitlab-ci.yml, except integration/e2e

demo: build ## Prototype demo against the make up services
	DATABASE_URL=$(DATABASE_URL) scripts/demo.sh

tunnel: ## Page and API behind one HTTPS host through Cloudflare Tunnel, for real devices (make up first)
	DATABASE_URL=$(DATABASE_URL) scripts/tunnel.sh

real: ## HTTPS browser example using real SMTP from .env (local PostgreSQL must be running)
	python3 scripts/real.py

real-check: ## Validate real SMTP settings in .env without connecting or sending mail
	python3 scripts/real.py --check

KEYRING ?= $(CURDIR)/.secrets/real/keyring.json

backup: ## Back up the local Compose database and complete keyring
	python3 scripts/backup.py create --keyring "$(KEYRING)"

backup-check: ## Restore BACKUP into a temporary database, verify it, then remove the test copy
	python3 scripts/backup.py check --backup "$(BACKUP)"

restore: ## Restore BACKUP only into a new RESTORE_DB; leave its keyring in .secrets/restored/
	python3 scripts/backup.py restore --backup "$(BACKUP)" --database "$(RESTORE_DB)"

migrate: build ## Apply pending migrations to the local database
	AIRLANCE_AUTH_DATABASE_URL=$(DATABASE_URL) $(BIN)/airlance-auth migrate up

up: ## Start local PostgreSQL and Mailpit
	$(COMPOSE) up -d --wait

down: ## Stop local services (data volume is kept)
	$(COMPOSE) down
