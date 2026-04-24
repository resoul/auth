.PHONY: all build deps image migrate test vet sec vulncheck format unused release
CHECK_FILES ?= ./...

ifdef RELEASE_VERSION
	VERSION=v$(RELEASE_VERSION)
else
	VERSION=$(shell git describe --tags)
endif

BUILD_VERSION_PKG = github.com/resoul/api/internal/utilities
BUILD_LD_FLAGS = -X $(BUILD_VERSION_PKG).Version=$(VERSION)
BUILD_CMD = go build \
	-o $(1) \
	-buildvcs=false \
	-ldflags "$(BUILD_LD_FLAGS)$(2)"

build: studio studio-arm64 studio-darwin-arm64

studio: deps
	CGO_ENABLED=0 $(call BUILD_CMD,$(@),)

studio-x86: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(call BUILD_CMD,$(@),)

studio-arm64: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(call BUILD_CMD,$(@),)

studio-darwin-arm64: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(call BUILD_CMD,$(@),)

deps: ## Install dependencies.
	@go mod download
	@go mod verify
