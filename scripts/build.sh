***REMOVED***!/bin/bash

***REMOVED*** Build script for eBPF agent
set -e

***REMOVED*** Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION=${VERSION:-$(git describe --tags --always 2>/dev/null || echo "dev")}
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE_NAME=${IMAGE_NAME:-"kubeadapt/ebpf-agent"}
IMAGE_TAG=${IMAGE_TAG:-$VERSION}

***REMOVED*** Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' ***REMOVED*** No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

***REMOVED*** Function to check prerequisites
check_prerequisites() {
    echo_info "Checking prerequisites..."

    ***REMOVED*** Check for Go
    if ! command -v go &> /dev/null; then
        echo_error "Go is not installed. Please install Go 1.21+"
        exit 1
    fi

    ***REMOVED*** Check Go version
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    REQUIRED_VERSION="1.21"
    if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
        echo_error "Go version $REQUIRED_VERSION or higher is required. Current version: $GO_VERSION"
        exit 1
    fi

    ***REMOVED*** Check for Docker
    if ! command -v docker &> /dev/null; then
        echo_warn "Docker is not installed. Skipping container build."
        SKIP_DOCKER=1
    fi

    ***REMOVED*** Check for clang (for local BPF compilation)
    if ! command -v clang &> /dev/null; then
        echo_warn "Clang is not installed. BPF compilation will only work in Docker."
    fi

    echo_info "Prerequisites check completed"
}

***REMOVED*** Function to generate BPF bytecode
generate_bpf() {
    echo_info "Generating BPF bytecode..."

    if command -v clang &> /dev/null; then
        cd "$PROJECT_ROOT"

        ***REMOVED*** Create output directory
        mkdir -p bpf/output

        ***REMOVED*** Compile BPF program
        clang -O2 -target bpf \
            -D__KERNEL__ -D__BPF_TRACING__ \
            -I/usr/include/bpf \
            -c bpf/network_monitor.c \
            -o bpf/output/network_monitor.o

        echo_info "BPF bytecode generated successfully"
    else
        echo_warn "Skipping local BPF compilation (clang not found)"
    fi
}

***REMOVED*** Function to generate Go bindings
generate_go_bindings() {
    echo_info "Generating Go bindings for BPF..."

    cd "$PROJECT_ROOT"

    ***REMOVED*** Install bpf2go if not present
    if ! command -v bpf2go &> /dev/null; then
        echo_info "Installing bpf2go..."
        go install github.com/cilium/ebpf/cmd/bpf2go@latest
    fi

    ***REMOVED*** Generate Go bindings
    if command -v bpf2go &> /dev/null; then
        bpf2go -type container_net_stats network bpf/network_monitor.c || echo_warn "bpf2go generation failed, using Docker build"
    else
        echo_warn "bpf2go not found, Go bindings will be generated in Docker"
    fi
}

***REMOVED*** Function to build Go binary
build_binary() {
    echo_info "Building Go binary..."

    cd "$PROJECT_ROOT"

    ***REMOVED*** Download dependencies
    go mod download

    ***REMOVED*** Build binary
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -ldflags="-w -s -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME" \
        -o bin/ebpf-agent \
        cmd/agent/main.go

    echo_info "Binary built: bin/ebpf-agent"
    echo_info "Version: $VERSION"
    echo_info "Build Time: $BUILD_TIME"
}

***REMOVED*** Function to build Docker image
build_docker() {
    if [ "$SKIP_DOCKER" = "1" ]; then
        return
    fi

    echo_info "Building Docker image..."

    cd "$PROJECT_ROOT"

    ***REMOVED*** Build production image
    docker build \
        --build-arg VERSION="$VERSION" \
        --build-arg BUILD_TIME="$BUILD_TIME" \
        -f Dockerfile.production \
        -t "${IMAGE_NAME}:${IMAGE_TAG}" \
        -t "${IMAGE_NAME}:latest" \
        .

    echo_info "Docker image built: ${IMAGE_NAME}:${IMAGE_TAG}"

    ***REMOVED*** Show image size
    docker images "${IMAGE_NAME}:${IMAGE_TAG}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
}

***REMOVED*** Function to run tests
run_tests() {
    echo_info "Running tests..."

    cd "$PROJECT_ROOT"

    ***REMOVED*** Run unit tests
    go test -v -race -coverprofile=coverage.out ./...

    ***REMOVED*** Show coverage
    go tool cover -func=coverage.out | grep total || true

    echo_info "Tests completed"
}

***REMOVED*** Function to run linters
run_linters() {
    echo_info "Running linters..."

    cd "$PROJECT_ROOT"

    ***REMOVED*** Install golangci-lint if not present
    if ! command -v golangci-lint &> /dev/null; then
        echo_info "Installing golangci-lint..."
        curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2
    fi

    ***REMOVED*** Run linters
    if command -v golangci-lint &> /dev/null; then
        golangci-lint run ./... || echo_warn "Linting issues found"
    else
        echo_warn "golangci-lint not found, skipping linting"
    fi
}

***REMOVED*** Main build process
main() {
    echo_info "Starting eBPF Agent build process..."
    echo_info "Project root: $PROJECT_ROOT"

    ***REMOVED*** Parse command line arguments
    while [[ $***REMOVED*** -gt 0 ]]; do
        case $1 in
            --skip-tests)
                SKIP_TESTS=1
                shift
                ;;
            --skip-docker)
                SKIP_DOCKER=1
                shift
                ;;
            --skip-lint)
                SKIP_LINT=1
                shift
                ;;
            --version)
                VERSION="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --skip-tests    Skip running tests"
                echo "  --skip-docker   Skip Docker image build"
                echo "  --skip-lint     Skip running linters"
                echo "  --version       Set version string"
                echo "  --help          Show this help message"
                exit 0
                ;;
            *)
                echo_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    ***REMOVED*** Run build steps
    check_prerequisites
    generate_bpf
    generate_go_bindings

    if [ "$SKIP_LINT" != "1" ]; then
        run_linters
    fi

    if [ "$SKIP_TESTS" != "1" ]; then
        run_tests
    fi

    build_binary
    build_docker

    echo_info "Build completed successfully!"

    ***REMOVED*** Show build artifacts
    echo ""
    echo "Build artifacts:"
    echo "  Binary: $PROJECT_ROOT/bin/ebpf-agent"
    if [ "$SKIP_DOCKER" != "1" ]; then
        echo "  Docker image: ${IMAGE_NAME}:${IMAGE_TAG}"
    fi
}

***REMOVED*** Run main function
main "$@"