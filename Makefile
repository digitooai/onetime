# onetime — developer entrypoints.
#
# Everything here is also what CI runs, so `make lint test-race` locally is a
# faithful preview of the pipeline.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

MODULE   := github.com/digitooai/onetime
BINARY   := onetime
CMD      := ./cmd/onetime
IMAGE    := ghcr.io/digitooai/onetime
CHART    := deploy/helm/onetime

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)

GO ?= go

# Local dev runs outside a container, so point the data dirs somewhere writable.
# DATA_DIR and TMP_DIR must stay on the same filesystem: blob writes are an
# atomic rename from tmp into blobs, and rename does not cross mount points.
DEV_DATA_DIR := $(CURDIR)/.data/blobs
DEV_TMP_DIR  := $(CURDIR)/.data/tmp
# Dev-only keyring. Never reuse these bytes anywhere real.
DEV_MASTER_KEYS := v1:ZGV2LWRldi1kZXYtZGV2LWRldi1kZXYtZGV2LWRlMDE=

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the static binary into ./onetime
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags='$(LDFLAGS)' -o $(BINARY) $(CMD)

.PHONY: run
run: ## Run the server locally against a local Redis (see docker-compose.yml)
	@mkdir -p $(DEV_DATA_DIR) $(DEV_TMP_DIR)
	ONETIME_BASE_URL=http://localhost:8080 \
	ONETIME_REDIS_MODE=sidecar \
	ONETIME_REDIS_ADDR=127.0.0.1:6379 \
	ONETIME_MASTER_KEYS='$(DEV_MASTER_KEYS)' \
	ONETIME_DATA_DIR=$(DEV_DATA_DIR) \
	ONETIME_TMP_DIR=$(DEV_TMP_DIR) \
	ONETIME_LOG_FORMAT=text \
	ONETIME_LOG_LEVEL=debug \
	$(GO) run $(CMD) serve

.PHONY: test
test: ## Run unit tests with coverage
	$(GO) test -shuffle=on -covermode=atomic -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out | tail -n 1

.PHONY: test-race
test-race: ## Run tests under the race detector (what CI runs)
	$(GO) test -race -shuffle=on -covermode=atomic -coverprofile=coverage.out ./...

.PHONY: cover
cover: test ## Open the HTML coverage report
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "wrote coverage.html"

.PHONY: fmt
fmt: ## Format all Go sources
	gofmt -s -w .

.PHONY: lint
lint: ## gofmt check + go vet + golangci-lint
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	@command -v golangci-lint >/dev/null 2>&1 \
		|| { echo "golangci-lint not installed: https://golangci-lint.run/welcome/install/"; exit 1; }
	golangci-lint run

.PHONY: vuln
vuln: ## Scan dependencies for known vulnerabilities
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: tidy
tidy: ## go mod tidy + verify
	$(GO) mod tidy
	$(GO) mod verify

.PHONY: image
image: ## Build the container image for the local platform
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):dev \
		.

.PHONY: image-multiarch
image-multiarch: ## Cross-build amd64+arm64 (no QEMU, requires a buildx builder)
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE):$(VERSION) \
		.

.PHONY: keygen
keygen: ## Print a fresh master keyring entry (rotate: prepend, never delete)
	$(GO) run $(CMD) keygen

.PHONY: helm-lint
helm-lint: ## Lint and render the chart across the three supported value matrices
	@# The same three shapes CI checks. values.schema.json rejects a bare base64
	@# blob as masterKey.value - it must be a real "<id>:<base64>" keyring, so a
	@# malformed one fails here instead of crash-looping in the cluster.
	@for f in default external-redis no-persistence; do \
		echo "--> $$f"; \
		helm lint $(CHART) --strict --values $(CHART)/ci/$$f-values.yaml || exit 1; \
		helm template onetime $(CHART) --values $(CHART)/ci/$$f-values.yaml >/dev/null || exit 1; \
	done
	@echo "chart OK"

.PHONY: helm-package
helm-package: ## Package the chart into dist/
	@mkdir -p dist
	helm package $(CHART) --version $(patsubst v%,%,$(VERSION)) --app-version $(VERSION) -d dist

.PHONY: compose-up
compose-up: ## Start the local dev stack (app + redis)
	docker compose up --build

.PHONY: compose-down
compose-down: ## Stop the local dev stack and drop its volumes
	docker compose down -v

.PHONY: e2e
e2e: ## Spin up a kind cluster, install the chart, run `helm test`
	kind create cluster --name onetime-e2e || true
	$(MAKE) image
	kind load docker-image $(IMAGE):dev --name onetime-e2e
	helm upgrade --install onetime $(CHART) \
		--namespace onetime --create-namespace \
		--set image.tag=dev \
		--set image.pullPolicy=Never \
		--set persistence.enabled=false \
		--set masterKey.value='$(DEV_MASTER_KEYS)' \
		--set config.baseURL=http://onetime.localtest.me \
		--wait --timeout 5m
	helm test onetime --namespace onetime --logs
	@echo "e2e OK — tear down with: kind delete cluster --name onetime-e2e"

.PHONY: e2e-down
e2e-down: ## Delete the kind e2e cluster
	kind delete cluster --name onetime-e2e

.PHONY: clean
clean: ## Remove build output and local data
	rm -rf $(BINARY) dist coverage.out coverage.html .data
