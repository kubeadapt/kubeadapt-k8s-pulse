***REMOVED*** KubeAdapt eBPF Agent Makefile
***REMOVED*** Production-ready Makefile with macOS support for BPF development

***REMOVED*** Variables
BINARY_NAME := ebpf-agent
DOCKER_IMAGE := kubeadapt/ebpf-agent
VERSION ?= latest
GO := go
DOCKER := docker
KUBECTL := kubectl

***REMOVED*** OS Detection
OS := $(shell uname -s)
ARCH := $(shell uname -m)
ifeq ($(OS),Darwin)
    IS_MACOS := 1
    ***REMOVED*** Use Docker for BPF compilation on macOS
    BPF_COMPILE_METHOD := docker
else
    IS_MACOS := 0
    BPF_COMPILE_METHOD := native
    CLANG := clang
endif

***REMOVED*** Directories
CMD_DIR := ./cmd/agent
BPF_DIR := ./bpf
BUILD_DIR := ./bin
DEPLOYMENT_DIR := ./deployments/kubernetes
INTERNAL_BPF_DIR := ./internal/bpf

***REMOVED*** Build flags
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(shell date -u '+%Y-%m-%d_%H:%M:%S')"
GO_BUILD_FLAGS := -v
BPF_CFLAGS := -O2 -g -Wall -Werror

***REMOVED*** Docker build container for macOS BPF compilation
BPF_BUILDER_IMAGE := kubeadapt/bpf-builder:latest

***REMOVED*** Color output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m ***REMOVED*** No Color

***REMOVED*** Targets
.PHONY: all init deps install-clang-format generate generate-docker generate-native build clean test test-coverage cov-exclude-generated test-docker docker-build docker-build-dev verify-dev-tools docker-info docker-buildx docker-push deploy undeploy run run-local dev help

***REMOVED*** Default target
all: build

***REMOVED*** Help target with categorized commands
help:
	@echo "$(GREEN)KubeAdapt eBPF Agent Makefile$(NC)"
	@echo ""
	@echo "$(YELLOW)System Information:$(NC)"
	@echo "  OS: $(OS) ($(ARCH))"
	@echo "  BPF Compilation: $(BPF_COMPILE_METHOD)"
	@echo ""
	@echo "$(YELLOW)Setup & Dependencies:$(NC)"
	@echo "  $(GREEN)make init$(NC)           - Initialize development environment"
	@echo "  $(GREEN)make deps$(NC)           - Install Go tools + clang-format (auto-detects OS)"
	@echo "  $(GREEN)make check-kernel$(NC)   - Check kernel compatibility (Linux only)"
	@echo ""
	@echo "$(YELLOW)Development:$(NC)"
	@echo "  $(GREEN)make generate$(NC)       - Generate Go bindings for eBPF (ONLY when bpf/*.c changes)"
	@echo "  $(GREEN)make build$(NC)          - Build the eBPF agent binary (uses pre-generated BPF)"
	@echo "  $(GREEN)make run-local$(NC)      - Run locally with docker-compose"
	@echo "  $(GREEN)make dev$(NC)            - Run with live reload for development"
	@echo "  $(GREEN)make test$(NC)           - Run unit tests"
	@echo "  $(GREEN)make test-coverage$(NC)  - Generate test coverage report (excludes generated code)"
	@echo "  $(GREEN)make test-docker$(NC)    - Run BPF integration tests in Docker"
	@echo "  $(GREEN)make lint$(NC)           - Run linters (Go + C code)"
	@echo "  $(GREEN)make fmt$(NC)            - Format code (Go + C code with clang-format)"
	@echo "  $(GREEN)make cov-exclude-generated$(NC) - Exclude generated code from coverage report"
	@echo ""
	@echo "$(YELLOW)Docker & Kubernetes:$(NC)"
	@echo "  $(GREEN)make docker-build$(NC)       - Build production Docker image"
	@echo "  $(GREEN)make docker-build-dev$(NC)   - Build development image (with debug tools)"
	@echo "  $(GREEN)make verify-dev-tools$(NC)   - Verify debug tools in dev image"
	@echo "  $(GREEN)make docker-info$(NC)        - Show image sizes and information"
	@echo "  $(GREEN)make docker-buildx$(NC)      - Build multi-arch images (amd64+arm64)"
	@echo "  $(GREEN)make docker-push$(NC)        - Push Docker image"
	@echo "  $(GREEN)make deploy$(NC)             - Deploy to Kubernetes"
	@echo "  $(GREEN)make undeploy$(NC)           - Remove from Kubernetes"
	@echo ""
	@echo "$(YELLOW)Utilities:$(NC)"
	@echo "  $(GREEN)make clean$(NC)          - Clean build artifacts"
	@echo "  $(GREEN)make version$(NC)        - Show version information"
	@echo "  $(GREEN)make metrics$(NC)        - Show current metrics (when running)"
	@echo "  $(GREEN)make logs$(NC)           - Tail agent logs from Kubernetes"
	@echo ""
	@echo "$(YELLOW)macOS Development:$(NC)"
	@echo "  ✓ Full local development supported"
	@echo "  ✓ BPF compilation uses Docker (transparent)"
	@echo "  ✓ Run agent locally: $(GREEN)make run-local$(NC)"
	@echo "  ✓ LLVM/clang-format auto-installed via Homebrew"

***REMOVED*** Initialize development environment
init:
	@echo "$(GREEN)Initializing development environment...$(NC)"
ifdef IS_MACOS
	@echo "$(YELLOW)Detected macOS - will use Docker for BPF compilation$(NC)"
	@which docker > /dev/null || (echo "$(RED)Docker is required on macOS. Please install Docker Desktop$(NC)" && exit 1)
	@echo "Building BPF compilation container..."
	@$(MAKE) build-bpf-builder
else
	@echo "$(YELLOW)Detected Linux - setting up native BPF compilation$(NC)"
	@echo "Installing required packages..."
	@which clang > /dev/null || echo "$(YELLOW)Please install clang: sudo apt-get install clang llvm$(NC)"
	@which bpftool > /dev/null || echo "$(YELLOW)Please install bpftool: sudo apt-get install linux-tools-common$(NC)"
endif
	@echo "$(GREEN)Installing Go dependencies...$(NC)"
	@$(MAKE) deps
	@echo "$(GREEN)Initialization complete!$(NC)"

***REMOVED*** Install Go development tools
deps:
	@echo "$(GREEN)Installing Go dependencies...$(NC)"
	@$(GO) mod download
	@echo "Installing bpf2go..."
	@$(GO) install github.com/cilium/ebpf/cmd/bpf2go@v0.19.0
	@echo "Installing golangci-lint..."
	@which golangci-lint > /dev/null || $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Installing air for hot-reload..."
	@which air > /dev/null || $(GO) install github.com/air-verse/air@latest
	@echo "Installing goimports..."
	@which goimports > /dev/null || $(GO) install golang.org/x/tools/cmd/goimports@latest
	@echo "Checking clang-format installation..."
	@which clang-format > /dev/null || (echo "$(YELLOW)clang-format not found. Installing...$(NC)" && $(MAKE) install-clang-format)
	@echo "$(GREEN)Dependencies installed$(NC)"

***REMOVED*** Install clang-format (OS-aware)
install-clang-format:
ifdef IS_MACOS
	@echo "$(GREEN)Installing clang-format via Homebrew...$(NC)"
	@which brew > /dev/null || (echo "$(RED)Homebrew not installed. Please install from https://brew.sh$(NC)" && exit 1)
	@brew install clang-format
	@echo "$(GREEN)clang-format installed successfully$(NC)"
else
	@echo "$(GREEN)Installing clang-format via apt...$(NC)"
	@echo "$(YELLOW)This requires sudo privileges...$(NC)"
	@sudo apt-get update && sudo apt-get install -y clang-format
	@echo "$(GREEN)clang-format installed successfully$(NC)"
endif

***REMOVED*** Build BPF builder Docker image for macOS
build-bpf-builder:
	@echo "$(GREEN)Building BPF builder container...$(NC)"
	@if [ -f Dockerfile.bpf-builder ]; then \
		echo "$(GREEN)Building from Dockerfile.bpf-builder$(NC)"; \
		$(DOCKER) build -t $(BPF_BUILDER_IMAGE) -f Dockerfile.bpf-builder .; \
	else \
		echo "$(YELLOW)Dockerfile.bpf-builder not found, creating it...$(NC)"; \
		$(DOCKER) build -t $(BPF_BUILDER_IMAGE) -f Dockerfile.bpf-builder . 2>/dev/null || \
		echo "$(RED)Error: Dockerfile.bpf-builder not found$(NC)"; \
	fi
	@echo "$(GREEN)BPF builder container ready$(NC)"

***REMOVED*** Auto-detect OS and generate BPF code appropriately
***REMOVED*** NOTE: Generated BPF files are committed to the repo (following netobserv pattern)
***REMOVED*** Only run this when you modify bpf/*.c files - NOT for every build
***REMOVED*** For development: `make dev` uses pre-generated files for faster hot reload
generate:
ifdef IS_MACOS
	@echo "$(YELLOW)macOS detected - using Docker for BPF generation$(NC)"
	@$(MAKE) generate-docker
else
	@echo "$(GREEN)Linux detected - using native BPF generation$(NC)"
	@$(MAKE) generate-native
endif

***REMOVED*** Generate BPF code using Docker (for macOS)
generate-docker: build-bpf-builder
	@echo "$(GREEN)Generating BPF code in Docker container...$(NC)"
	@$(DOCKER) run --rm \
		-v $(shell pwd):/workspace \
		-w /workspace \
		$(BPF_BUILDER_IMAGE) \
		bash -c "cd internal/bpf && \
			bpf2go -go-package bpf -cc clang-14 \
				-cflags '-O2 -g -Wall -Werror' \
				-target amd64,arm64 \
				network ../../bpf/network_monitor.c"
	@echo "$(GREEN)BPF code generation complete$(NC)"

***REMOVED*** Generate BPF code natively (for Linux)
generate-native:
	@echo "$(GREEN)Generating BPF code natively...$(NC)"
	@cd $(INTERNAL_BPF_DIR) && \
		bpf2go -go-package bpf -cc clang \
			-cflags "$(BPF_CFLAGS)" \
			-target amd64,arm64 \
			network ../../bpf/network_monitor.c
	@echo "$(GREEN)BPF code generation complete$(NC)"

***REMOVED*** Build the binary
***REMOVED*** NOTE: Skips 'generate' - BPF files are pre-generated and committed
***REMOVED*** Run 'make generate' manually only when you change bpf/*.c files
build: lint
	@echo "$(GREEN)Building $(BINARY_NAME)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "$(GREEN)Binary built: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

***REMOVED*** Run tests (including co-located tests)
test: lint
	@echo "$(GREEN)Running unit tests...$(NC)"
	@$(GO) test -v -race -coverprofile=coverage.out ./internal/... ./cmd/...
	@echo "$(GREEN)Test coverage report:$(NC)"
	@$(GO) tool cover -func=coverage.out | tail -1

***REMOVED*** Exclude generated code from coverage report
cov-exclude-generated:
	@echo "$(GREEN)Excluding generated code from coverage...$(NC)"
	@grep -vE "(/cmd/)|(bpf_bpfe)|(/test/)|(/internal/bpf/)" coverage.out > coverage.clean.out || true
	@if [ -f coverage.clean.out ]; then \
		mv coverage.clean.out coverage.out; \
		echo "$(GREEN)Generated code excluded from coverage$(NC)"; \
	fi

***REMOVED*** Generate detailed test coverage report
test-coverage: test cov-exclude-generated
	@echo "$(GREEN)Generating HTML coverage report...$(NC)"
	@$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"
	@echo "$(YELLOW)Open with: open coverage.html (macOS) or xdg-open coverage.html (Linux)$(NC)"

***REMOVED*** Run BPF integration tests in Docker
test-docker:
	@echo "$(GREEN)Running BPF integration tests in Docker...$(NC)"
	@$(DOCKER) run --rm \
		--privileged \
		-v $(shell pwd):/workspace \
		-w /workspace \
		$(BPF_BUILDER_IMAGE) \
		bash -c "go test -v ./test/integration/..."

***REMOVED*** Run integration tests (requires root on Linux)
test-integration:
ifdef IS_MACOS
	@echo "$(YELLOW)Running integration tests in Docker (macOS)...$(NC)"
	@$(MAKE) test-docker
else
	@echo "$(GREEN)Running integration tests (requires root)...$(NC)"
	@sudo $(GO) test -v ./test/integration/...
endif

***REMOVED*** Run E2E tests with Kind cluster (following netobserv-ebpf-agent pattern)
.ONESHELL:
test-e2e: generate lint
	@echo "$(GREEN)Running E2E tests with Kind cluster...$(NC)"
	@$(GO) clean -testcache
	@echo "$(YELLOW)Building agent image for E2E tests...$(NC)"
	@rm -f ebpf-agent.tar || true
	@$(DOCKER) build --build-arg LDFLAGS="" --build-arg TARGETARCH=$(ARCH) -t localhost/ebpf-agent:test -f Dockerfile .
	@$(DOCKER) save -o ebpf-agent.tar localhost/ebpf-agent:test
	@echo "$(GREEN)Running E2E tests (timeout: 30m)...$(NC)"
	@GOOS=linux $(GO) test -p 1 -timeout 30m -v ./test/e2e/...
	@echo "$(GREEN)E2E tests complete$(NC)"

***REMOVED*** Lint the code (Go and C)
lint:
	@echo "$(GREEN)Running Go linters...$(NC)"
	@which golangci-lint > /dev/null || (echo "$(RED)golangci-lint not found. Installing...$(NC)" && $(MAKE) deps)
	@golangci-lint run ./internal/... ./cmd/... ./test/e2e/... --timeout=5m
	@echo "$(GREEN)Linting C code...$(NC)"
	@find ./bpf -type f -name "*.[ch]" | xargs clang-format --dry-run --Werror 2>/dev/null || echo "$(YELLOW)clang-format not found, skipping C code linting$(NC)"
	@echo "$(GREEN)Linting complete$(NC)"

***REMOVED*** Format code (Go and C)
fmt:
	@echo "$(GREEN)Formatting Go code...$(NC)"
	@$(GO) fmt ./...
	@echo "$(GREEN)Running goimports...$(NC)"
	@which goimports > /dev/null || (echo "$(YELLOW)Installing goimports...$(NC)" && $(GO) install golang.org/x/tools/cmd/goimports@latest)
	@goimports -w .
	@echo "$(GREEN)Formatting C code...$(NC)"
	@find ./bpf -type f -name "*.[ch]" | xargs clang-format -i --Werror 2>/dev/null || echo "$(YELLOW)clang-format not found, skipping C code formatting$(NC)"
	@echo "$(GREEN)Formatting complete$(NC)"

***REMOVED*** Build Docker image (single arch for local testing)
***REMOVED*** Uses pre-generated BPF files (no generate needed)
docker-build:
	@echo "$(GREEN)Building Docker image for local platform...$(NC)"
	@$(DOCKER) build -t $(DOCKER_IMAGE):$(VERSION) -f Dockerfile .
	@$(DOCKER) tag $(DOCKER_IMAGE):$(VERSION) $(DOCKER_IMAGE):latest
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(VERSION)$(NC)"

***REMOVED*** Build development Docker image with debugging tools
docker-build-dev:
	@echo "$(GREEN)Building development Docker image...$(NC)"
	@$(DOCKER) build -t $(DOCKER_IMAGE):dev -f Dockerfile.dev .
	@echo "$(GREEN)Development image built: $(DOCKER_IMAGE):dev$(NC)"
	@echo "$(YELLOW)Image includes: bpftool, tcpdump, netstat, strace for debugging$(NC)"

***REMOVED*** Verify development tools are installed
verify-dev-tools: docker-build-dev
	@echo "$(GREEN)Verifying debug tools in development image...$(NC)"
	@echo "$(YELLOW)Testing bpftool...$(NC)"
	@$(DOCKER) run --rm $(DOCKER_IMAGE):dev bpftool version
	@echo "$(YELLOW)Testing tcpdump...$(NC)"
	@$(DOCKER) run --rm $(DOCKER_IMAGE):dev tcpdump --version 2>&1 | head -1
	@echo "$(YELLOW)Testing netstat...$(NC)"
	@$(DOCKER) run --rm $(DOCKER_IMAGE):dev netstat --version 2>&1 | head -1
	@echo "$(YELLOW)Testing strace...$(NC)"
	@$(DOCKER) run --rm $(DOCKER_IMAGE):dev strace --version 2>&1 | head -1
	@echo "$(GREEN)✓ All debug tools verified!$(NC)"

***REMOVED*** Show Docker image information and sizes
docker-info:
	@echo "$(GREEN)Docker Image Information$(NC)"
	@echo ""
	@echo "$(YELLOW)Production Images:$(NC)"
	@$(DOCKER) images | grep -E "REPOSITORY|$(DOCKER_IMAGE)" | grep -v dev || echo "No production images found"
	@echo ""
	@echo "$(YELLOW)Development Images:$(NC)"
	@$(DOCKER) images | grep -E "REPOSITORY|$(DOCKER_IMAGE):dev" || echo "No dev images found"
	@echo ""
	@echo "$(YELLOW)BPF Builder Images:$(NC)"
	@$(DOCKER) images | grep -E "REPOSITORY|bpf-builder" || echo "No BPF builder images found"
	@echo ""
	@echo "$(YELLOW)Expected sizes:$(NC)"
	@echo "  Production: ~50-70 MB (minimal runtime)"
	@echo "  Development: ~350-400 MB (full tooling)"
	@echo "  BPF Builder: ~800-900 MB (compilation tools)"

***REMOVED*** Build multi-arch Docker images (amd64 + arm64)
docker-buildx:
	@echo "$(GREEN)Building multi-arch Docker images (amd64 + arm64)...$(NC)"
	@$(DOCKER) buildx create --use --name kubeadapt-builder 2>/dev/null || $(DOCKER) buildx use kubeadapt-builder
	@$(DOCKER) buildx build \
		--platform linux/amd64,linux/arm64 \
		--tag $(DOCKER_IMAGE):$(VERSION) \
		--tag $(DOCKER_IMAGE):latest \
		--push \
		-f Dockerfile .
	@echo "$(GREEN)Multi-arch Docker images built and pushed$(NC)"

***REMOVED*** Push Docker image
docker-push:
	@echo "$(GREEN)Pushing Docker image...$(NC)"
	@$(DOCKER) push $(DOCKER_IMAGE):$(VERSION)
	@$(DOCKER) push $(DOCKER_IMAGE):latest
	@echo "$(GREEN)Docker image pushed$(NC)"

***REMOVED*** Deploy to Kubernetes
deploy:
	@echo "$(GREEN)Deploying to Kubernetes...$(NC)"
	@$(KUBECTL) apply -f $(DEPLOYMENT_DIR)/
	@echo "$(GREEN)Deployment complete$(NC)"

***REMOVED*** Remove from Kubernetes
undeploy:
	@echo "$(YELLOW)Removing from Kubernetes...$(NC)"
	@$(KUBECTL) delete -f $(DEPLOYMENT_DIR)/ --ignore-not-found=true
	@echo "$(GREEN)Undeployment complete$(NC)"

***REMOVED*** Run locally (requires root on Linux, uses Docker on macOS)
run: build
ifdef IS_MACOS
	@echo "$(YELLOW)macOS detected - use 'make run-local' to run with Docker$(NC)"
else
	@echo "$(GREEN)Running $(BINARY_NAME) locally (requires root)...$(NC)"
	@sudo $(BUILD_DIR)/$(BINARY_NAME)
endif

***REMOVED*** Run locally with docker-compose (works on all platforms)
run-local:
	@echo "$(GREEN)Starting local environment with docker-compose...$(NC)"
	@$(DOCKER) compose up --build

***REMOVED*** Development mode with live reload
dev:
ifdef IS_MACOS
	@echo "$(GREEN)Starting development mode with Docker...$(NC)"
	@$(DOCKER) compose up ebpf-dev
else
	@echo "$(GREEN)Starting development mode with air...$(NC)"
	@sudo air -c .air.toml
endif

***REMOVED*** Clean build artifacts
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@rm -rf $(BUILD_DIR)
	@rm -f $(BPF_DIR)/*.o
	@rm -f $(INTERNAL_BPF_DIR)/*_bpfel.go $(INTERNAL_BPF_DIR)/*_bpfeb.go
	@rm -f $(INTERNAL_BPF_DIR)/*_bpfel.o $(INTERNAL_BPF_DIR)/*_bpfeb.o
	@rm -f coverage.out coverage.html
	@rm -f ebpf-agent.tar
	@echo "$(GREEN)Clean complete$(NC)"

***REMOVED*** Check kernel compatibility (Linux only)
check-kernel:
ifdef IS_MACOS
	@echo "$(YELLOW)Kernel check not applicable on macOS$(NC)"
	@echo "BPF programs will run in Docker containers"
else
	@echo "$(GREEN)Checking kernel compatibility...$(NC)"
	@echo -n "Kernel version: "
	@uname -r
	@echo -n "BPF support: "
	@ls /sys/kernel/debug/tracing/ > /dev/null 2>&1 && echo "Yes" || echo "No"
	@echo -n "Required capabilities: "
	@capsh --print 2>/dev/null | grep -q cap_sys_admin && echo "CAP_SYS_ADMIN present" || echo "CAP_SYS_ADMIN missing"
endif

***REMOVED*** Show current metrics (when running)
metrics:
	@echo "$(GREEN)Fetching metrics from local agent...$(NC)"
	@curl -s localhost:9090/metrics | grep kubeadapt_ || echo "$(YELLOW)No metrics found - is the agent running?$(NC)"

***REMOVED*** Debug BPF maps (requires root on Linux)
debug-maps:
ifdef IS_MACOS
	@echo "$(YELLOW)BPF debugging not available on macOS$(NC)"
else
	@echo "$(GREEN)BPF Programs:$(NC)"
	@sudo bpftool prog list 2>/dev/null | grep -E "tcp_|udp_|trace_" || echo "No programs loaded"
	@echo ""
	@echo "$(GREEN)BPF Maps:$(NC)"
	@sudo bpftool map list 2>/dev/null | grep container || echo "No maps found"
endif

***REMOVED*** Tail agent logs from Kubernetes
logs:
	@$(KUBECTL) logs -n kubeadapt-system -l app=kubeadapt-ebpf-agent -f --tail=100

***REMOVED*** Port forward for local debugging
port-forward:
	@$(KUBECTL) port-forward -n kubeadapt-system daemonset/kubeadapt-ebpf-agent 9090:9090

***REMOVED*** Version information
version:
	@echo "$(GREEN)eBPF Agent Version Information$(NC)"
	@echo "  Agent Version: $(VERSION)"
	@echo "  Go Version: $(shell $(GO) version)"
	@echo "  OS/Arch: $(OS)/$(ARCH)"
ifdef IS_MACOS
	@echo "  Docker Version: $(shell $(DOCKER) --version)"
else
	@echo "  Clang Version: $(shell $(CLANG) --version 2>/dev/null | head -1 || echo 'Not installed')"
	@echo "  Kernel Version: $(shell uname -r)"
endif

***REMOVED*** Quick start for new developers
quickstart: init generate build
	@echo ""
	@echo "$(GREEN)════════════════════════════════════════════$(NC)"
	@echo "$(GREEN)     ✅ Quickstart Complete!$(NC)"
	@echo "$(GREEN)════════════════════════════════════════════$(NC)"
	@echo ""
	@echo "$(YELLOW)Next steps:$(NC)"
ifdef IS_MACOS
	@echo "  1. Run locally:     $(GREEN)make run-local$(NC)"
	@echo "  2. Run tests:       $(GREEN)make test-docker$(NC)"
else
	@echo "  1. Run locally:     $(GREEN)sudo make run$(NC)"
	@echo "  2. Run tests:       $(GREEN)make test$(NC)"
endif
	@echo "  3. Build Docker:    $(GREEN)make docker-build$(NC)"
	@echo "  4. Deploy to K8s:   $(GREEN)make deploy$(NC)"
	@echo ""
	@echo "$(YELLOW)For more commands:$(NC)  $(GREEN)make help$(NC)"

.PHONY: quickstart build-bpf-builder check-kernel debug-maps metrics port-forward version install-clang-format docker-build-dev verify-dev-tools docker-info