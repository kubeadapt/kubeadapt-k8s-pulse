***REMOVED*** Multi-stage build for eBPF agent
***REMOVED*** Supports multi-arch: linux/amd64, linux/arm64

***REMOVED*** Build stage - use native platform for faster compilation
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder

***REMOVED*** Declare buildx automatic platform variables
ARG TARGETOS
ARG TARGETARCH
ARG BUILDPLATFORM

***REMOVED*** Install BPF build dependencies
RUN apt-get update && apt-get install -y \
    clang-14 \
    llvm-14 \
    libbpf-dev \
    linux-headers-generic \
    make \
    gcc \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

***REMOVED*** Create symlinks for asm headers to fix cross-compilation
RUN ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm && \
    ln -sf /usr/include/$(uname -m)-linux-gnu/asm-generic /usr/include/asm-generic

WORKDIR /build

***REMOVED*** Download Go dependencies first (better caching)
COPY go.mod go.sum ./
RUN go mod download

***REMOVED*** Copy source code
COPY . .

***REMOVED*** Note: BPF bindings are pre-generated in internal/bpf/ directory
***REMOVED*** They include network_x86_bpfel.go, network_arm64_bpfel.go and .o files
***REMOVED*** To regenerate, run: make generate on the host

***REMOVED*** Build the Go binary for target platform
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev') -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o ebpf-agent \
    cmd/agent/main.go

***REMOVED*** Runtime stage - minimal image with root access for BPF
FROM debian:bookworm-slim

***REMOVED*** Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

***REMOVED*** Copy binary from builder
COPY --from=builder /build/ebpf-agent /usr/local/bin/ebpf-agent

***REMOVED*** Create necessary directories
RUN mkdir -p /sys/fs/bpf

***REMOVED*** Note: BPF operations require root privileges
***REMOVED*** The container MUST run with:
***REMOVED*** - privileged: true OR
***REMOVED*** - capabilities: CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_BPF, CAP_PERFMON
***REMOVED*** These are set via SecurityContext in Kubernetes deployment

***REMOVED*** Expose metrics port
EXPOSE 9090

***REMOVED*** Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

***REMOVED*** Run as root (required for BPF operations)
***REMOVED*** Security is enforced at the container runtime level via capabilities
USER root

***REMOVED*** Set entrypoint
ENTRYPOINT ["/usr/local/bin/ebpf-agent"]