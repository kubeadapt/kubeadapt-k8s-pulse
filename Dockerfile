# Multi-stage build for eBPF agent
# Supports multi-arch: linux/amd64, linux/arm64
#
# Stage 1: Generate BPF binaries (using bpf-builder toolchain)
# Stage 2: Build Go binary
# Stage 3: Minimal runtime image

# ==============================================================================
# Stage 1: BPF Generation
# ==============================================================================
# Generate BPF binaries for BOTH architectures (amd64 + arm64)
# Uses BUILDPLATFORM to run only once - bpf2go cross-compiles for all targets
# This stage uses the same toolchain as Dockerfile.bpf-builder
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS bpf-generator

# Build arguments
ARG BUILDPLATFORM
ARG LLVM_VERSION=14
ARG BPF2GO_VERSION=v0.19.0

# Install BPF compilation dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends \
    -o Dpkg::Options::="--force-confnew" \
    clang-${LLVM_VERSION} \
    llvm-${LLVM_VERSION} \
    libbpf-dev \
    libelf-dev \
    linux-libc-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create versioned symlinks for clang tools
RUN ln -sf /usr/bin/clang-${LLVM_VERSION} /usr/bin/clang && \
    ln -sf /usr/bin/llvm-strip-${LLVM_VERSION} /usr/bin/llvm-strip

# Fix asm/types.h not found issue
RUN if [ "$(uname -m)" = "x86_64" ]; then \
        ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm; \
    elif [ "$(uname -m)" = "aarch64" ]; then \
        ln -sf /usr/include/aarch64-linux-gnu/asm /usr/include/asm; \
    fi

# Set up Go environment
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

# Install bpf2go
RUN go install github.com/cilium/ebpf/cmd/bpf2go@${BPF2GO_VERSION}

WORKDIR /build

# Copy only what's needed for BPF generation
COPY go.mod go.sum ./
RUN go mod download

COPY bpf/ ./bpf/
COPY internal/bpf/*.go ./internal/bpf/

# Generate BPF binaries (IPv4 + IPv6 dual-stack, kernel 5.10+ compatible)
RUN cd internal/bpf && \
    bpf2go -go-package bpf -cc clang \
        -cflags "-O2 -Wall -Werror" \
        -target amd64,arm64 \
        network ../../bpf/network_monitor_tc.c

# ==============================================================================
# Stage 2: Go Build
# ==============================================================================
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apt-get update && apt-get install -y \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Download Go dependencies first (better caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Copy generated BPF binaries from bpf-generator stage
COPY --from=bpf-generator /build/internal/bpf/network_*.go ./internal/bpf/
COPY --from=bpf-generator /build/internal/bpf/network_*.o ./internal/bpf/

# Build the Go binary for target platform.
# -mod=mod: bypass vendor/ (lazy resolution from go.mod). Avoids strict modules.txt
# drift between local Go 1.26 and Dockerfile's golang:1.25.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -mod=mod \
    -ldflags="-w -s -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev') -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o kubeadapt-k8s-pulse \
    cmd/agent/main.go

# ==============================================================================
# Stage 3: Runtime
# ==============================================================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/kubeadapt-k8s-pulse /usr/local/bin/kubeadapt-k8s-pulse

# Create necessary directories
RUN mkdir -p /sys/fs/bpf

# Expose metrics port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# Run as root (required for BPF operations)
USER root

ENTRYPOINT ["/usr/local/bin/kubeadapt-k8s-pulse"]
