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
.PHONY: all init deps generate generate-docker generate-native build clean test test-docker docker-build docker-push deploy undeploy run run-local dev help

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
	@echo "  $(GREEN)make deps$(NC)           - Install Go development tools"
	@echo "  $(GREEN)make check-kernel$(NC)   - Check kernel compatibility (Linux only)"
	@echo ""
	@echo "$(YELLOW)Development:$(NC)"
	@echo "  $(GREEN)make generate$(NC)       - Generate Go bindings for eBPF (auto-detects OS)"
	@echo "  $(GREEN)make build$(NC)          - Build the eBPF agent binary"
	@echo "  $(GREEN)make run-local$(NC)      - Run locally with docker-compose"
	@echo "  $(GREEN)make dev$(NC)            - Run with live reload for development"
	@echo "  $(GREEN)make test$(NC)           - Run unit tests"
	@echo "  $(GREEN)make test-docker$(NC)    - Run BPF integration tests in Docker"
	@echo "  $(GREEN)make lint$(NC)           - Run linters"
	@echo "  $(GREEN)make fmt$(NC)            - Format code"
	@echo ""
	@echo "$(YELLOW)Docker & Kubernetes:$(NC)"
	@echo "  $(GREEN)make docker-build$(NC)   - Build Docker image (single arch)"
	@echo "  $(GREEN)make docker-buildx$(NC)  - Build multi-arch images (amd64+arm64)"
	@echo "  $(GREEN)make docker-push$(NC)    - Push Docker image"
	@echo "  $(GREEN)make deploy$(NC)         - Deploy to Kubernetes"
	@echo "  $(GREEN)make undeploy$(NC)       - Remove from Kubernetes"
	@echo ""
	@echo "$(YELLOW)Utilities:$(NC)"
	@echo "  $(GREEN)make clean$(NC)          - Clean build artifacts"
	@echo "  $(GREEN)make version$(NC)        - Show version information"
	@echo "  $(GREEN)make metrics$(NC)        - Show current metrics (when running)"
	@echo "  $(GREEN)make logs$(NC)           - Tail agent logs from Kubernetes"
	@echo ""
	@echo "$(YELLOW)macOS Notes:$(NC)"
	@echo "  - BPF compilation uses Docker automatically"
	@echo "  - Use 'make run-local' for local testing"
	@echo "  - LLVM installation not required on macOS"

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
	@$(GO) install github.com/cilium/ebpf/cmd/bpf2go@v0.11.0
	@echo "Installing golangci-lint..."
	@which golangci-lint > /dev/null || $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "Installing air for hot-reload..."
	@which air > /dev/null || $(GO) install github.com/cosmtrek/air@latest
	@echo "$(GREEN)Dependencies installed$(NC)"

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
build: generate
	@echo "$(GREEN)Building $(BINARY_NAME)...$(NC)"
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "$(GREEN)Binary built: $(BUILD_DIR)/$(BINARY_NAME)$(NC)"

***REMOVED*** Run tests
test:
	@echo "$(GREEN)Running unit tests...$(NC)"
	@$(GO) test -v -race ./internal/... ./cmd/...

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

***REMOVED*** Lint the code
lint:
	@echo "$(GREEN)Running linters...$(NC)"
	@golangci-lint run ./...
	@echo "$(GREEN)Linting complete$(NC)"

***REMOVED*** Format code
fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	@$(GO) fmt ./...
	@goimports -w .
	@echo "$(GREEN)Formatting complete$(NC)"

***REMOVED*** Build Docker image (single arch for local testing)
docker-build: generate
	@echo "$(GREEN)Building Docker image for local platform...$(NC)"
	@$(DOCKER) build -t $(DOCKER_IMAGE):$(VERSION) -f Dockerfile .
	@$(DOCKER) tag $(DOCKER_IMAGE):$(VERSION) $(DOCKER_IMAGE):latest
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(VERSION)$(NC)"

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

.PHONY: quickstart build-bpf-builder check-kernel debug-maps metrics port-forward version