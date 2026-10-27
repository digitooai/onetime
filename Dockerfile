# syntax=docker/dockerfile:1.9
#
# onetime — one-time secret sharing.
#
# Two stages, no Node stage: the frontend is Go html/template plus static CSS/JS
# embedded with go:embed, so there is nothing to bundle.
#
# The builder always runs on the *native* platform ($BUILDPLATFORM) and
# cross-compiles to $TARGETOS/$TARGETARCH. That is why there is no QEMU setup in
# the release workflow: a linux/amd64+linux/arm64 build costs roughly the same as
# a single-arch build, instead of the 5-10x penalty of emulated compilation.

# Must satisfy the `go` directive in go.mod. prometheus/client_golang requires
# 1.25, so building on an older toolchain fails at `go mod download`.
ARG GO_VERSION=1.26

# ---------------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

# Injected by BuildKit. TARGETOS/TARGETARCH describe the image we are producing;
# the compiler itself keeps running natively.
ARG TARGETOS
ARG TARGETARCH

# Injected by the release workflow (docker/metadata-action outputs).
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /src

# Dependency layer first: it only invalidates when go.mod/go.sum change.
# `go.*` rather than `go.mod go.sum`: a literal source that matches nothing
# fails the build, and go.sum does not exist until the first dependency lands.
COPY go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# CGO_ENABLED=0    -> fully static binary, runs on distroless/static and scratch.
# -trimpath        -> strips local paths, makes the build reproducible.
# -buildvcs=false  -> do not embed VCS state; we pass it explicitly via ldflags
#                     so the value is identical whether or not .git is present.
# -s -w            -> drop the symbol table and DWARF, ~30 % smaller binary.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.buildDate=${BUILD_DATE}" \
      -o /out/onetime \
      ./cmd/onetime

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# org.opencontainers.image.source is what links the GHCR package page back to the
# repository and enables inherited repo permissions on the package.
LABEL org.opencontainers.image.title="onetime" \
      org.opencontainers.image.description="One-time secret and file sharing (single-use links, encrypted at rest)" \
      org.opencontainers.image.vendor="Fortion" \
      org.opencontainers.image.source="https://github.com/fortionnet/onetime" \
      org.opencontainers.image.url="https://onetime.fortion.cloud" \
      org.opencontainers.image.documentation="https://github.com/fortionnet/onetime/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

COPY --from=builder /out/onetime /usr/local/bin/onetime

# 65532 is the `nonroot` user baked into the distroless base. The Helm chart
# pins runAsUser/runAsGroup/fsGroup to the same number — if they drift apart the
# pod cannot write to its PersistentVolume.
USER 65532:65532

# 8080 = HTTP (behind the ingress), 9090 = Prometheus metrics (never exposed
# through the ingress; scraped in-cluster only).
EXPOSE 8080 9090

WORKDIR /

# Distroless has no shell, so the exec form is mandatory. `healthcheck` is a
# subcommand of the binary itself and talks to /healthz on the local listener.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/onetime", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/onetime"]
CMD ["serve"]
