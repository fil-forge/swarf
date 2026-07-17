# Build stage - runs natively on build machine, cross-compiles to target.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
ARG TARGETARCH
ARG TARGETOS=linux
WORKDIR /go/src/swarf
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download || true
COPY . .

# Production build - stripped binary.
FROM build AS build-prod
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /swarf ./cmd/swarf

# Development build - debug-friendly binary.
FROM build AS build-dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -gcflags="all=-N -l" -o /swarf ./cmd/swarf
RUN GOARCH=${TARGETARCH} go install github.com/go-delve/delve/cmd/dlv@latest && \
    cp /go/bin/linux_${TARGETARCH}/dlv /go/bin/dlv 2>/dev/null || cp /go/bin/dlv /go/bin/dlv 2>/dev/null || true

# Production target - minimal runtime.
FROM debian:bookworm-slim AS prod
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build-prod /swarf /usr/bin/swarf
EXPOSE 8080
ENTRYPOINT ["/usr/bin/swarf", "serve"]

# Development target - includes debug tools.
FROM debian:bookworm-slim AS dev
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    bash-completion \
    less \
    vim-tiny \
    procps \
    htop \
    strace \
    iputils-ping \
    dnsutils \
    net-tools \
    tcpdump \
    jq \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build-dev /swarf /usr/bin/swarf
COPY --from=build-dev /go/bin/dlv /usr/bin/dlv
EXPOSE 8080
ENTRYPOINT ["/usr/bin/swarf", "serve"]
