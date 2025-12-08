***REMOVED*** Contributing to KubeAdapt eBPF Agent

Welcome! Whether you're fixing a bug, adding a feature, or just exploring eBPF, this guide will help you become productive quickly.

***REMOVED******REMOVED*** 📖 Table of Contents

- [Your First Day: Getting Set Up](***REMOVED***your-first-day-getting-set-up)
- [Understanding Your Development Environment](***REMOVED***understanding-your-development-environment)
- [Your Daily Workflow: Making Changes](***REMOVED***your-daily-workflow-making-changes)
- [Testing: Fast Feedback Loops](***REMOVED***testing-fast-feedback-loops)
- [Friday Afternoon: Debugging Production Issues](***REMOVED***friday-afternoon-debugging-production-issues)
- [Docker Architecture: The Real Story](***REMOVED***docker-architecture-the-real-story)
- [Common Development Scenarios](***REMOVED***common-development-scenarios)
- [When Things Go Wrong](***REMOVED***when-things-go-wrong)
- [Code Quality & Standards](***REMOVED***code-quality--standards)
- [Submitting Your Work](***REMOVED***submitting-your-work)

---

***REMOVED******REMOVED*** 🎯 Your First Day: Getting Set Up

**Meet Sarah**: She's a backend developer who just joined the team. She has a MacBook Pro M2, knows Go reasonably well, but has never touched eBPF before. She's been asked to fix a bug in the network filtering logic. Here's her journey...

***REMOVED******REMOVED******REMOVED*** Prerequisites Check

Before you start, make sure you have:

- **Go 1.21+** - `go version` should work
- **Docker Desktop** (macOS) or **Docker Engine** (Linux) - `docker --version` should work
- **Make** - `make --version` should work (comes with Xcode tools on macOS)
- **Git** - Already have it if you cloned this repo!

**macOS developers**: Yes, that's it! You don't need LLVM, clang, or Linux kernel headers locally. We'll explain why in a moment.

***REMOVED******REMOVED******REMOVED*** The Quickstart Path

Sarah wants to get coding as fast as possible:

```bash
***REMOVED*** 1. Clone the repository
git clone <repository-url>
cd ebpf-agent

***REMOVED*** 2. One command to rule them all
make quickstart
***REMOVED*** ☕ Grab coffee... this takes ~2-3 minutes on first run

***REMOVED*** 3. Run the agent locally
make run-local
***REMOVED*** ⏱️  Takes ~30 seconds to start
```

**What just happened?**

- `make quickstart` detected macOS and set up Docker-based BPF compilation
- Built a specialized container with clang, LLVM, and eBPF tools
- Generated Go bindings from the BPF C code (`network_monitor.c`)
- Compiled the Go binary
- Verified everything works

**Result**: Sarah now has a running eBPF agent collecting network metrics locally! She can access:
- Metrics: `http://localhost:9090/metrics`
- Health check: `http://localhost:9090/health`
- Prometheus UI: `http://localhost:9091`

***REMOVED******REMOVED******REMOVED*** The "I Want to Understand Everything" Path

If you're like Sarah's colleague Marcus, who wants to understand each step:

```bash
***REMOVED*** Step 1: Initialize development environment
make init
***REMOVED*** Output: "Detected macOS - will use Docker for BPF compilation"
***REMOVED*** ⏱️  ~60 seconds (builds BPF builder container)

***REMOVED*** Step 2: Install Go tools
make deps
***REMOVED*** Installs: bpf2go, golangci-lint, air (hot-reload), goimports, clang-format
***REMOVED*** ⏱️  ~30 seconds

***REMOVED*** Step 3: Generate BPF code
make generate
***REMOVED*** Compiles network_monitor.c → generates network_bpfel.go and network_bpfeb.go
***REMOVED*** ⏱️  ~5 seconds (happens in Docker transparently)

***REMOVED*** Step 4: Build the Go binary
make build
***REMOVED*** Compiles cmd/agent/main.go → bin/ebpf-agent
***REMOVED*** ⏱️  ~2 seconds

***REMOVED*** Step 5: Run tests
make test
***REMOVED*** Unit tests for Go code
***REMOVED*** ⏱️  ~10 seconds

***REMOVED*** Step 6: Run the full stack
make run-local
***REMOVED*** Starts agent + Prometheus
***REMOVED*** ⏱️  ~30 seconds
```

**Total time from zero to running agent**: ~2-3 minutes

---

***REMOVED******REMOVED*** 🧠 Understanding Your Development Environment

***REMOVED******REMOVED******REMOVED*** What's Really Running Where?

This is the most important concept to understand. Here's what happens on **your MacBook**:

```
┌─────────────────────────────────────────┐
│         Your MacBook (macOS)            │
├─────────────────────────────────────────┤
│                                         │
│  ✓ Code editing (VS Code, Vim, etc.)   │
│  ✓ Git operations                       │
│  ✓ Go compilation (fast!)               │
│  ✓ Go testing (unit tests)              │
│  ✓ Linting (golangci-lint)              │
│  ✓ Code formatting                      │
│                                         │
└─────────────────────────────────────────┘
                    ↓
                    ↓ (only for BPF and runtime)
                    ↓
┌─────────────────────────────────────────┐
│    Docker Container (Linux kernel)      │
├─────────────────────────────────────────┤
│                                         │
│  ✓ BPF C code compilation (clang)       │
│  ✓ eBPF program loading (needs kernel)  │
│  ✓ Agent runtime (needs BPF syscalls)   │
│  ✓ Integration tests                    │
│                                         │
└─────────────────────────────────────────┘
```

**Key insight**: You ARE doing real local development! Docker is just a transparent Linux kernel provider for the parts that need it. This is not a workaround—it's the industry standard approach for cross-platform eBPF development.

***REMOVED******REMOVED******REMOVED*** Why Docker? (The Real Answer)

**Not because macOS is "lacking"—because this is the industry standard approach:**

1. **eBPF requires Linux kernel** - It's a Linux kernel feature, like ext4 filesystems or cgroups. You can't run it on macOS any more than you can mount an ext4 partition natively.

2. **Consistent toolchain** - Everyone gets the same clang version, same LLVM version, same kernel headers. No "works on my machine" issues.

3. **Production parity** - Your Docker container uses the same environment as production Kubernetes clusters. When it works locally, it works in prod.

4. **Industry proven** - Production-grade eBPF observability projects use the exact same Docker-based compilation approach.

***REMOVED******REMOVED******REMOVED*** The Three Dockerfiles (And Why They Exist)

We have three Dockerfiles, each with a specific job:

***REMOVED******REMOVED******REMOVED******REMOVED*** 1. `Dockerfile.bpf-builder` - The Compilation Factory

**Purpose**: Compiles BPF C code into Go bindings

**You interact with it**: Indirectly through `make generate`

**Contains**:
- clang-14, LLVM
- Linux kernel headers
- bpf2go tool
- Cross-compilation support (amd64 + arm64)

**When it runs**: Only when you modify BPF C code

```bash
***REMOVED*** Sarah modifies bpf/network_monitor.c
make generate  ***REMOVED*** Uses this container transparently
***REMOVED*** Takes ~5 seconds
```

***REMOVED******REMOVED******REMOVED******REMOVED*** 2. `Dockerfile.dev` - Your Development Playground

**Purpose**: Development container with hot-reload

**You interact with it**: Through `make dev`

**Contains**:
- Go runtime
- Development tools (air for hot-reload, delve for debugging)
- Text editors (vim, nano)
- Your code (mounted as volume)

**When it runs**: When you want live-reload during development

```bash
make dev
***REMOVED*** Now edit Go code - changes trigger automatic rebuilds!
```

***REMOVED******REMOVED******REMOVED******REMOVED*** 3. `Dockerfile` - The Production Build

**Purpose**: Slim, secure, production-ready image

**You interact with it**: When building for deployment

**Contains**:
- Just the agent binary
- Minimal base image (distroless or alpine)
- No dev tools, no bloat

**When it runs**: Building for Kubernetes deployment

```bash
make docker-build   ***REMOVED*** Single-arch (local testing)
make docker-buildx  ***REMOVED*** Multi-arch (production)
```

---

***REMOVED******REMOVED*** 💻 Your Daily Workflow: Making Changes

***REMOVED******REMOVED******REMOVED*** Scenario 1: Fixing a Bug in Go Code

**Sarah's task**: The byte counter overflows for connections > 4GB. She needs to fix the aggregation logic.

```bash
***REMOVED*** 1. Find the bug
grep -r "BytesSent" internal/

***REMOVED*** 2. Edit the file
***REMOVED*** Open internal/collector/connection_collector.go
***REMOVED*** Change: bytesSent += uint32(flow.Bytes)
***REMOVED*** To: bytesSent += uint64(flow.Bytes)

***REMOVED*** 3. Run tests
make test
***REMOVED*** ⏱️  ~10 seconds (runs locally, no Docker needed!)

***REMOVED*** 4. Lint your changes
make lint
***REMOVED*** ⏱️  ~5 seconds

***REMOVED*** 5. Build the binary
make build
***REMOVED*** ⏱️  ~2 seconds

***REMOVED*** 6. Test in full environment
make run-local
curl localhost:9090/metrics | grep ebpf_connection_bytes_sent
***REMOVED*** Verify the fix works!
```

**Total time from bug found to verified fix**: ~30 seconds (after first edit)

***REMOVED******REMOVED******REMOVED*** Scenario 2: Modifying BPF Code

**Marcus's task**: Add support for IPv6 connection tracking in the eBPF program.

```bash
***REMOVED*** 1. Edit the BPF program
***REMOVED*** Open bpf/network_monitor.c
***REMOVED*** Add IPv6 struct and logic

***REMOVED*** 2. Regenerate Go bindings
make generate
***REMOVED*** ⏱️  ~5 seconds (Docker compilation happens transparently)
***REMOVED*** Creates: internal/bpf/network_bpfel.go, network_bpfeb.go

***REMOVED*** 3. Update Go code to use new bindings
***REMOVED*** Edit internal/bpf/loader.go to load new maps

***REMOVED*** 4. Test BPF loading
make test-docker
***REMOVED*** ⏱️  ~20 seconds (needs Linux kernel for BPF)

***REMOVED*** 5. Run full stack
make run-local

***REMOVED*** 6. Verify IPv6 metrics appear
curl localhost:9090/metrics | grep ipv6
```

**Total time from BPF change to working feature**: ~17 seconds (excluding debugging time)

***REMOVED******REMOVED******REMOVED*** Scenario 3: Adding a New Feature End-to-End

**Sarah's feature**: Add TCP connection duration tracking

```bash
***REMOVED*** Phase 1: BPF Changes (~5 minutes)
***REMOVED*** Edit bpf/network_monitor.c - add timestamp tracking
make generate  ***REMOVED*** 5 seconds

***REMOVED*** Phase 2: Go Integration (~10 minutes)
***REMOVED*** Edit internal/collector/connection_collector.go
***REMOVED*** Add duration calculation logic
make test      ***REMOVED*** 10 seconds

***REMOVED*** Phase 3: Metrics Exposure (~5 minutes)
***REMOVED*** Edit internal/metrics/server.go
***REMOVED*** Add new Prometheus metric: ebpf_connection_duration_seconds
make build     ***REMOVED*** 2 seconds

***REMOVED*** Phase 4: Full Testing (~5 minutes)
make run-local
curl localhost:9090/metrics | grep duration
***REMOVED*** Verify the new metric appears in Prometheus

***REMOVED*** Phase 5: Submit for Review
make lint          ***REMOVED*** 5 seconds
make test-docker   ***REMOVED*** 20 seconds
git add .
git commit -m "feat(bpf): add TCP connection duration tracking"
```

**Total development time**: ~25 minutes (plus testing and debugging)

***REMOVED******REMOVED******REMOVED*** The Hot-Reload Workflow (For Rapid Iteration)

When you're making lots of small changes:

```bash
***REMOVED*** Terminal 1: Start development mode
make dev
***REMOVED*** Agent runs with hot-reload enabled

***REMOVED*** Terminal 2: Watch logs
docker-compose logs -f ebpf-dev

***REMOVED*** Terminal 3: Make changes
***REMOVED*** Edit any Go file
***REMOVED*** Save → automatic rebuild → automatic restart!
***REMOVED*** ⏱️  ~2 seconds per change
```

**Pro tip**: Use this when tuning metric collection, debugging edge cases, or experimenting with new features.

---

***REMOVED******REMOVED*** 🧪 Testing: Fast Feedback Loops

***REMOVED******REMOVED******REMOVED*** The Testing Hierarchy

We have three layers of testing, each with different purposes and speed:

***REMOVED******REMOVED******REMOVED******REMOVED*** Level 1: Unit Tests (Fastest)

**What they test**: Go business logic, no kernel interaction

**When to use**: You changed Go code (not BPF)

**Speed**: ~10 seconds

**Command**:
```bash
make test
***REMOVED*** Or directly:
go test ./internal/... ./cmd/... -v
```

**Example output**:
```
✓ TestConnectionAggregation (0.01s)
✓ TestContainerMetadataExtraction (0.02s)
✓ TestPrometheusMetricsFormat (0.01s)
--- PASS: TestConnectionAggregation (0.01s)
Total: 10 seconds
Coverage: 78.4%
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Level 2: Integration Tests (Medium)

**What they test**: BPF loading, map operations, kernel interaction

**When to use**: You changed BPF code or loader logic

**Speed**: ~20 seconds

**Command**:
```bash
make test-docker
***REMOVED*** Runs in Docker because it needs Linux kernel
```

**Example output**:
```
✓ TestBPFProgramLoading (2.5s)
✓ TestBPFMapOperations (1.8s)
✓ TestPacketCapture (3.2s)
Total: 20 seconds
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Level 3: E2E Tests (Slowest)

**What they test**: Full system in a Kind cluster

**When to use**: Before submitting PR, testing production scenarios

**Speed**: ~5 minutes

**Command**:
```bash
make test-e2e
***REMOVED*** Builds Docker image
***REMOVED*** Creates Kind cluster
***REMOVED*** Deploys agent
***REMOVED*** Runs traffic tests
***REMOVED*** Verifies metrics
```

**Example output**:
```
Creating Kind cluster... (30s)
Building agent image... (60s)
Deploying to cluster... (20s)
Running traffic tests... (120s)
Verifying metrics... (30s)
✓ All E2E tests passed!
Total: 5 minutes
```

***REMOVED******REMOVED******REMOVED*** Test Selection Cheatsheet

| I changed...                    | Run this test           | Time  |
|---------------------------------|-------------------------|-------|
| Go business logic               | `make test`             | 10s   |
| Metric calculation              | `make test`             | 10s   |
| BPF C code                      | `make test-docker`      | 20s   |
| BPF loader                      | `make test-docker`      | 20s   |
| Kubernetes integration          | `make test-e2e`         | 5min  |
| Configuration parsing           | `make test`             | 10s   |
| Prometheus metrics format       | `make test`             | 10s   |

***REMOVED******REMOVED******REMOVED*** Coverage Reports

```bash
***REMOVED*** Generate HTML coverage report
make test-coverage
***REMOVED*** Opens coverage.html in your browser
***REMOVED*** ⏱️  ~15 seconds

***REMOVED*** What it shows:
***REMOVED*** - Which lines are tested (green)
***REMOVED*** - Which lines are untested (red)
***REMOVED*** - Excludes generated BPF code automatically
```

**Pro tip**: Aim for >70% coverage on new code. Generated BPF bindings don't count.

---

***REMOVED******REMOVED*** 🔍 Friday Afternoon: Debugging Production Issues

***REMOVED******REMOVED******REMOVED*** Scenario: Metrics Stopped Appearing

**The call**: "Hey, our production cluster stopped reporting network metrics 30 minutes ago!"

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 1: Quick Health Check

```bash
***REMOVED*** Check if agent is running
make run-local  ***REMOVED*** or check production pods

***REMOVED*** Health endpoints
curl localhost:9090/health
***REMOVED*** Should return: {"status": "ok"}

curl localhost:9090/health/ready
***REMOVED*** Should return: {"ready": true}

curl localhost:9090/health/live
***REMOVED*** Should return: {"alive": true}
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 2: Check Logs

```bash
***REMOVED*** Local Docker:
docker-compose logs -f ebpf-agent

***REMOVED*** Production Kubernetes:
make logs
***REMOVED*** Or: kubectl logs -n kubeadapt-system -l app=kubeadapt-ebpf-agent -f
```

**Look for**:
- `ERROR` lines (obvious!)
- `failed to load BPF program` (kernel issue)
- `permission denied` (privilege issue)
- `no such device` (container runtime issue)

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 3: Debug BPF Programs

```bash
***REMOVED*** Are BPF programs loaded?
docker-compose exec ebpf-agent bpftool prog list
***REMOVED*** Should show: tcp_connect, tcp_close, etc.

***REMOVED*** Check BPF maps
docker-compose exec ebpf-agent bpftool map list
***REMOVED*** Should show: connection_map, container_info_map

***REMOVED*** Dump a map's contents
docker-compose exec ebpf-agent bpftool map dump id 42
***REMOVED*** Shows actual data in the map
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 4: Trace Live Events

```bash
***REMOVED*** Watch BPF events in real-time
docker-compose exec ebpf-agent cat /sys/kernel/debug/tracing/trace_pipe

***REMOVED*** Generate some traffic to test
docker-compose exec ebpf-agent ping google.com

***REMOVED*** You should see events appear!
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 5: Verify Metrics Endpoint

```bash
***REMOVED*** Check raw metrics
curl localhost:9090/metrics | grep ebpf_

***REMOVED*** Expected output:
***REMOVED*** ebpf_connection_bytes_sent_total{...} 123456
***REMOVED*** ebpf_connection_bytes_received_total{...} 654321
***REMOVED*** ebpf_connections_active{...} 42
```

***REMOVED******REMOVED******REMOVED*** Scenario: BPF Program Won't Load

**Error**: `failed to load BPF program: permission denied`

```bash
***REMOVED*** Check privileges (production)
kubectl get pod <pod-name> -o yaml | grep privileged
***REMOVED*** Should be: privileged: true

***REMOVED*** Check security context
kubectl get pod <pod-name> -o yaml | grep -A5 securityContext
***REMOVED*** Should have: CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_BPF

***REMOVED*** Check kernel version
docker-compose exec ebpf-agent uname -r
***REMOVED*** Need: 5.4+ (preferably 5.8+)

***REMOVED*** Check memory limits
docker-compose exec ebpf-agent ulimit -l
***REMOVED*** Should be: unlimited
```

***REMOVED******REMOVED******REMOVED*** Debugging with Delve (Go Debugger)

```bash
***REMOVED*** Method 1: Inside dev container
docker-compose exec ebpf-dev dlv debug cmd/agent/main.go

***REMOVED*** Method 2: VS Code remote debugging
***REMOVED*** Add to .vscode/launch.json:
{
  "name": "Debug in Container",
  "type": "go",
  "request": "attach",
  "mode": "remote",
  "remotePath": "/workspace",
  "port": 2345,
  "host": "localhost"
}
```

***REMOVED******REMOVED******REMOVED*** Performance Debugging

```bash
***REMOVED*** Enable CPU profiling
curl localhost:9090/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

***REMOVED*** Enable memory profiling
curl localhost:9090/debug/pprof/heap > mem.prof
go tool pprof mem.prof

***REMOVED*** Check goroutine leaks
curl localhost:9090/debug/pprof/goroutine?debug=1
```

---

***REMOVED******REMOVED*** 🐳 Docker Architecture: The Real Story

***REMOVED******REMOVED******REMOVED*** Service Orchestration (docker-compose.yml)

Our `docker-compose.yml` defines the full local development stack:

| Service         | Purpose                          | Port  | When Running          |
|-----------------|----------------------------------|-------|-----------------------|
| `ebpf-agent`    | Main agent (production mode)     | 9090  | `make run-local`      |
| `ebpf-dev`      | Development with hot-reload      | 9090  | `make dev`            |
| `bpf-builder`   | BPF compilation only             | N/A   | `make generate` (internal) |
| `prometheus`    | Metrics collection               | 9091  | `make run-local`      |

***REMOVED******REMOVED******REMOVED*** How Docker Builds Actually Work

***REMOVED******REMOVED******REMOVED******REMOVED*** Single-Arch Build (Local Testing)

```bash
make docker-build
***REMOVED*** What happens:
***REMOVED*** 1. Runs 'make generate' (compiles BPF)
***REMOVED*** 2. Builds Go binary inside Docker
***REMOVED*** 3. Creates minimal image with just the binary
***REMOVED*** 4. Tags as: kubeadapt/ebpf-agent:latest
***REMOVED*** ⏱️  ~60 seconds
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Multi-Arch Build (Production)

```bash
make docker-buildx
***REMOVED*** What happens:
***REMOVED*** 1. Creates Docker buildx builder
***REMOVED*** 2. Cross-compiles for amd64 AND arm64
***REMOVED*** 3. Pushes to registry with manifest
***REMOVED*** 4. Both architectures tagged as :latest
***REMOVED*** ⏱️  ~3 minutes
```

**Why multi-arch?**
- Production clusters might have mixed node types
- ARM64 is cheaper on cloud providers (AWS Graviton, GCP Tau T2A)
- Our M1/M2 Mac developers can test on native architecture

***REMOVED******REMOVED******REMOVED*** Volume Mounts Explained

When you run `make dev`, Docker mounts your code:

```yaml
volumes:
  - .:/workspace          ***REMOVED*** Your entire repo
  - /workspace/bin        ***REMOVED*** Except build artifacts
  - /workspace/.git       ***REMOVED*** Except .git (performance)
```

**This means**:
- Edit files on your Mac → changes appear in container instantly
- Compile in container → binary appears on your Mac
- Git operations on your Mac → container sees changes

---

***REMOVED******REMOVED*** 🎯 Common Development Scenarios

***REMOVED******REMOVED******REMOVED*** Scenario: Adding a New Prometheus Metric

**Goal**: Add a metric for DNS query latency

```bash
***REMOVED*** 1. Update BPF code to capture DNS events
***REMOVED*** Edit: bpf/network_monitor.c
***REMOVED*** Add DNS timestamp tracking

***REMOVED*** 2. Regenerate bindings
make generate  ***REMOVED*** 5 seconds

***REMOVED*** 3. Update Go collector
***REMOVED*** Edit: internal/collector/dns_collector.go
func (c *DNSCollector) CollectLatency() {
    // Calculate latency from timestamps
}

***REMOVED*** 4. Register Prometheus metric
***REMOVED*** Edit: internal/metrics/server.go
dnsLatencyHistogram := prometheus.NewHistogram(...)
prometheus.MustRegister(dnsLatencyHistogram)

***REMOVED*** 5. Test locally
make run-local
curl localhost:9090/metrics | grep dns_latency

***REMOVED*** 6. Verify in Prometheus
***REMOVED*** Open http://localhost:9091
***REMOVED*** Query: rate(ebpf_dns_latency_seconds_sum[5m])
```

**Time**: ~30 minutes end-to-end

***REMOVED******REMOVED******REMOVED*** Scenario: Testing Against Different Kernel Versions

**Goal**: Verify the agent works on older kernels

```bash
***REMOVED*** Use test-e2e with Kind
***REMOVED*** Kind lets you specify kernel-equivalent images

***REMOVED*** Edit test/e2e/kind_test.go:
kindConfig := `
nodes:
- role: control-plane
  image: kindest/node:v1.24.0  ***REMOVED*** Kernel 5.10
`

make test-e2e
***REMOVED*** Verifies agent works on this kernel version
```

***REMOVED******REMOVED******REMOVED*** Scenario: Profiling Memory Usage

**Goal**: Agent memory usage is growing over time

```bash
***REMOVED*** 1. Enable pprof endpoint (already enabled)
***REMOVED*** 2. Run agent with load
make run-local

***REMOVED*** 3. Generate some load
for i in {1..1000}; do
  docker-compose exec ebpf-agent curl google.com
done

***REMOVED*** 4. Capture heap profile
curl localhost:9090/debug/pprof/heap > heap.prof

***REMOVED*** 5. Analyze with pprof
go tool pprof heap.prof
(pprof) top
***REMOVED*** Shows top memory allocators

(pprof) list functionName
***REMOVED*** Shows line-by-line allocation
```

***REMOVED******REMOVED******REMOVED*** Scenario: Updating Kubernetes Manifests

**Goal**: Agent needs new RBAC permissions

```bash
***REMOVED*** 1. Edit manifest
***REMOVED*** Edit: deployments/kubernetes/daemonset.yaml
***REMOVED*** Add new ClusterRole permissions

***REMOVED*** 2. Test in Kind cluster
make test-e2e
***REMOVED*** Verifies permissions work

***REMOVED*** 3. Update staging
kubectl apply -f deployments/kubernetes/
kubectl rollout status daemonset/kubeadapt-ebpf-agent -n kubeadapt-system

***REMOVED*** 4. Verify agent starts successfully
make logs
***REMOVED*** Should see: "Successfully loaded BPF programs"
```

---

***REMOVED******REMOVED*** 🚨 When Things Go Wrong

***REMOVED******REMOVED******REMOVED*** Error: "clang: command not found" (macOS)

**Why this happens**: You're trying to run Linux-native commands

**Solution**:
```bash
***REMOVED*** ✗ Don't do this on macOS:
make generate-native  ***REMOVED*** This is for Linux!

***REMOVED*** ✓ Do this instead:
make generate  ***REMOVED*** Auto-detects OS and uses Docker
```

**Explanation**: The Makefile has two code paths:
- **macOS**: `make generate` → `make generate-docker` (Docker)
- **Linux**: `make generate` → `make generate-native` (clang)

***REMOVED******REMOVED******REMOVED*** Error: "Docker daemon not running"

**macOS**:
```bash
***REMOVED*** Open Docker Desktop app
open -a Docker
***REMOVED*** Wait for whale icon to be steady
```

**Linux**:
```bash
***REMOVED*** Start Docker service
sudo systemctl start docker
sudo systemctl enable docker  ***REMOVED*** Start on boot
```

***REMOVED******REMOVED******REMOVED*** Error: "Port 9090 already in use"

```bash
***REMOVED*** Find what's using the port
lsof -i :9090  ***REMOVED*** macOS/Linux
***REMOVED*** or
netstat -anp | grep 9090  ***REMOVED*** Linux

***REMOVED*** Kill the process
kill -9 <PID>

***REMOVED*** Or use a different port
METRICS_PORT=9091 make run-local
```

***REMOVED******REMOVED******REMOVED*** Error: "BPF program failed to load: invalid instruction"

**Possible causes**:
1. Kernel too old (need 5.4+)
2. BTF not enabled
3. BPF code has unsupported instruction

**Debug**:
```bash
***REMOVED*** Check kernel version
docker-compose exec ebpf-agent uname -r

***REMOVED*** Check BTF support
docker-compose exec ebpf-agent ls /sys/kernel/btf/vmlinux
***REMOVED*** Should exist

***REMOVED*** Verify BPF is compiled correctly
make generate
***REMOVED*** Look for compilation errors
```

***REMOVED******REMOVED******REMOVED*** Error: "Permission denied" When Loading BPF

**Docker** (usually not an issue):
```bash
***REMOVED*** Check Docker has required capabilities
docker-compose exec ebpf-agent capsh --print
***REMOVED*** Should show: cap_sys_admin, cap_net_admin
```

**Kubernetes**:
```yaml
***REMOVED*** Ensure DaemonSet has:
securityContext:
  privileged: true
  capabilities:
    add:
    - SYS_ADMIN
    - NET_ADMIN
    - BPF
```

***REMOVED******REMOVED******REMOVED*** Error: "go.mod: module not found"

```bash
***REMOVED*** Update Go modules
go mod download
go mod tidy

***REMOVED*** Rebuild vendor (if using)
go mod vendor
```

***REMOVED******REMOVED******REMOVED*** Error: Tests Failing with "no such file or directory"

**Cause**: BPF bindings not generated

**Solution**:
```bash
***REMOVED*** Regenerate BPF code
make generate

***REMOVED*** Verify files exist
ls internal/bpf/network_bpfel.go
ls internal/bpf/network_bpfeb.go

***REMOVED*** Then retry tests
make test
```

***REMOVED******REMOVED******REMOVED*** Error: Docker Build Fails with "exec format error"

**Cause**: Architecture mismatch (M1 Mac building amd64 image)

**Solution**:
```bash
***REMOVED*** Use buildx for multi-arch
make docker-buildx

***REMOVED*** Or build for native arch only
docker build --platform linux/arm64 -t ebpf-agent:test .
```

---

***REMOVED******REMOVED*** 📋 Code Quality & Standards

***REMOVED******REMOVED******REMOVED*** Go Code Style

**We follow**:
- Standard Go conventions
- `gofmt` formatting (tabs, not spaces)
- `goimports` for import sorting
- `golangci-lint` for static analysis

**Before committing**:
```bash
***REMOVED*** Format your code
make fmt
***REMOVED*** Runs: gofmt, goimports, clang-format

***REMOVED*** Check for issues
make lint
***REMOVED*** Runs: golangci-lint, clang-format --dry-run
```

***REMOVED******REMOVED******REMOVED*** BPF C Code Style

**We follow**:
- Linux kernel coding style
- Tabs for indentation (not spaces)
- 80-character line limit (when possible)

**Key rules**:
```c
// ✓ Good: Descriptive function names
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    // ✓ Good: Clear variable names
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    // ✓ Good: Comments for complex logic
    // Check if this is an IPv4 socket before proceeding
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
}

// ✗ Bad: Single-letter variables, no comments
SEC("kprobe/tcp_connect")
int f(struct pt_regs *c) {
    struct sock *s = (struct sock *)PT_REGS_PARM1(c);
    u16 f = BPF_CORE_READ(s, __sk_common.skc_family);
}
```

***REMOVED******REMOVED******REMOVED*** File Organization

Our codebase follows this structure:

```
ebpf-agent/
├── bpf/                          ***REMOVED*** BPF C programs (kernel side)
│   └── network_monitor.c         ***REMOVED*** Main BPF program
├── cmd/agent/                    ***REMOVED*** Application entry point
│   └── main.go                   ***REMOVED*** Main function, flag parsing
├── internal/                     ***REMOVED*** Internal packages (not importable)
│   ├── bpf/                      ***REMOVED*** BPF loader and generated bindings
│   │   ├── loader.go             ***REMOVED*** BPF program loader
│   │   ├── network_bpfel.go      ***REMOVED*** Generated (Little-Endian)
│   │   └── network_bpfeb.go      ***REMOVED*** Generated (Big-Endian)
│   ├── collector/                ***REMOVED*** Metrics collection logic
│   │   ├── connection_collector.go
│   │   └── dns_collector.go
│   ├── config/                   ***REMOVED*** Configuration parsing
│   │   └── config.go
│   ├── container/                ***REMOVED*** Container runtime detection
│   │   └── detector.go
│   ├── k8s/                      ***REMOVED*** Kubernetes API integration
│   │   └── client.go
│   ├── metrics/                  ***REMOVED*** Prometheus metrics server
│   │   └── server.go
│   └── network/                  ***REMOVED*** Network utilities
│       └── utils.go
├── deployments/                  ***REMOVED*** Deployment configurations
│   └── kubernetes/               ***REMOVED*** K8s manifests
│       ├── daemonset.yaml
│       ├── configmap.yaml
│       └── service.yaml
├── test/                         ***REMOVED*** Tests
│   ├── e2e/                      ***REMOVED*** End-to-end tests
│   └── integration/              ***REMOVED*** Integration tests
├── configs/                      ***REMOVED*** Configuration files
│   └── agent.yaml
└── scripts/                      ***REMOVED*** Helper scripts
    └── install.sh
```

***REMOVED******REMOVED******REMOVED*** Testing Standards

**Coverage expectations**:
- New features: >70% coverage
- Bug fixes: Add regression test
- Refactoring: Maintain existing coverage

**Test naming**:
```go
// ✓ Good: Descriptive test names
func TestConnectionAggregation_WithMultipleFlows_SumsBytesCorrectly(t *testing.T)
func TestBPFLoader_WhenKernelTooOld_ReturnsError(t *testing.T)

// ✗ Bad: Vague test names
func TestConnection(t *testing.T)
func TestLoader(t *testing.T)
```

**Table-driven tests** (preferred):
```go
func TestConnectionFiltering(t *testing.T) {
    tests := []struct {
        name     string
        conn     Connection
        filter   Filter
        expected bool
    }{
        {"IPv4_Matches", ipv4Conn, ipv4Filter, true},
        {"IPv6_Matches", ipv6Conn, ipv6Filter, true},
        {"NoMatch", ipv4Conn, ipv6Filter, false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := ApplyFilter(tt.conn, tt.filter)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

---

***REMOVED******REMOVED*** 📤 Submitting Your Work

***REMOVED******REMOVED******REMOVED*** The Pre-Submit Checklist

Before creating a pull request, run through this checklist:

```bash
***REMOVED*** 1. Format your code
make fmt
***REMOVED*** ✓ All code formatted

***REMOVED*** 2. Run linters
make lint
***REMOVED*** ✓ No linting errors

***REMOVED*** 3. Run unit tests
make test
***REMOVED*** ✓ All tests pass

***REMOVED*** 4. Run integration tests (if you changed BPF)
make test-docker
***REMOVED*** ✓ BPF programs load successfully

***REMOVED*** 5. Build Docker image
make docker-build
***REMOVED*** ✓ Image builds without errors

***REMOVED*** 6. Test locally
make run-local
curl localhost:9090/metrics | grep ebpf_
***REMOVED*** ✓ Metrics appear correctly
```

**Time**: ~2 minutes total

***REMOVED******REMOVED******REMOVED*** Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
<type>(<scope>): <subject>

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, not behavior)
- `refactor`: Code restructuring (no behavior change)
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Build process, dependencies, etc.

**Examples**:

```bash
***REMOVED*** Good commit messages
feat(bpf): add IPv6 support for connection tracking
fix(metrics): correct byte counter overflow for large connections
docs: update macOS development setup instructions
refactor(collector): simplify connection aggregation logic
perf(bpf): optimize map lookups with LRU cache

***REMOVED*** Bad commit messages
fix bug
update code
changes
WIP
```

**Scope examples**: `bpf`, `collector`, `metrics`, `k8s`, `config`, `docker`

***REMOVED******REMOVED******REMOVED*** Pull Request Process

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 1: Fork and Branch

```bash
***REMOVED*** Fork the repository on GitHub
***REMOVED*** Then clone your fork
git clone https://github.com/YOUR_USERNAME/ebpf-agent.git
cd ebpf-agent

***REMOVED*** Create a feature branch
git checkout -b feat/my-awesome-feature
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 2: Make Your Changes

```bash
***REMOVED*** Make changes
***REMOVED*** Test thoroughly (see checklist above)

***REMOVED*** Commit with clear messages
git add .
git commit -m "feat(bpf): add IPv6 connection tracking"
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 3: Push and Create PR

```bash
***REMOVED*** Push to your fork
git push origin feat/my-awesome-feature

***REMOVED*** Create PR on GitHub with:
***REMOVED*** - Clear title (same as commit message)
***REMOVED*** - Description explaining what/why
***REMOVED*** - Link to related issues
***REMOVED*** - Screenshots if UI changes
***REMOVED*** - Test results
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 4: PR Template

Your PR description should include:

```markdown
***REMOVED******REMOVED*** What Changed?
Brief description of your changes

***REMOVED******REMOVED*** Why?
Why this change is needed (link to issue if applicable)

***REMOVED******REMOVED*** How?
High-level explanation of your approach

***REMOVED******REMOVED*** Testing
- [ ] Unit tests pass locally (`make test`)
- [ ] Integration tests pass (`make test-docker`)
- [ ] Tested locally with `make run-local`
- [ ] Verified metrics appear correctly
- [ ] BPF programs load successfully

***REMOVED******REMOVED*** Screenshots (if applicable)
Prometheus query showing new metric

***REMOVED******REMOVED*** Checklist
- [ ] Code follows style guidelines (`make lint`)
- [ ] Documentation updated (if needed)
- [ ] Commit messages are clear
- [ ] No unnecessary files committed
```

***REMOVED******REMOVED******REMOVED******REMOVED*** Step 5: Code Review

**Expect feedback on**:
- Code clarity and maintainability
- Test coverage
- Performance implications
- Security considerations
- Documentation completeness

**How to respond**:
```bash
***REMOVED*** Make requested changes
***REMOVED*** Commit with descriptive message
git add .
git commit -m "refactor: extract DNS parsing into separate function"
git push

***REMOVED*** Reference the review comment in commit if helpful
git commit -m "fix: handle nil pointer in collector (addresses review)"
```

***REMOVED******REMOVED******REMOVED*** After Your PR Merges

```bash
***REMOVED*** Update your main branch
git checkout main
git pull upstream main

***REMOVED*** Delete your feature branch
git branch -d feat/my-awesome-feature
git push origin --delete feat/my-awesome-feature

***REMOVED*** Celebrate! 🎉
```

---

***REMOVED******REMOVED*** 🆘 Getting Help

***REMOVED******REMOVED******REMOVED*** Resources

- **Issues**: Report bugs or request features on GitHub
- **Discussions**: Ask questions or share ideas
- **Documentation**:
  - This file (CONTRIBUTING.md)
  - README.md for project overview
  - docs/ARCHITECTURE_DECISIONS.md for architecture decisions
  - docs/ folder for detailed technical docs

***REMOVED******REMOVED******REMOVED*** Common Questions

**Q: I'm new to eBPF. Where do I start?**

A: Start by reading through the code in `bpf/network_monitor.c`. It's well-commented. Then read `internal/bpf/loader.go` to see how it's loaded. Finally, trace through `internal/collector/connection_collector.go` to see how data flows.

**Q: How do I know if my change needs a BPF update?**

A: If you're changing:
- How connections are tracked → BPF
- What metadata is captured → BPF
- How metrics are calculated → Go
- How metrics are formatted → Go
- How data is stored → BPF (maps)
- How data is aggregated → Go

**Q: Can I develop entirely in Docker?**

A: Yes! Use `make dev` to run the entire development environment in Docker with hot-reload. Your code still lives on your Mac (volume-mounted), but compilation and execution happen in Docker.

**Q: Why are there two generated files (bpfel.go and bpfeb.go)?**

A: BPF bytecode is architecture-dependent:
- `bpfel.go`: Little-Endian (x86_64, ARM64)
- `bpfeb.go`: Big-Endian (some MIPS, PowerPC)

Most modern systems use Little-Endian, but we support both for completeness.

**Q: How often should I regenerate BPF code?**

A: Only when you modify `bpf/network_monitor.c`. If you only change Go code, no need to regenerate.

---

***REMOVED******REMOVED*** 🔐 Security Considerations

***REMOVED******REMOVED******REMOVED*** Never Commit These

- ❌ Kubernetes cluster credentials
- ❌ Docker registry passwords
- ❌ Cloud provider access keys
- ❌ Personal tokens or certificates
- ❌ Production configuration files with secrets

***REMOVED******REMOVED******REMOVED*** How to Handle Secrets

**For local development**:
```bash
***REMOVED*** Use environment variables
export KUBECONFIG=~/.kube/config
export DOCKER_REGISTRY_TOKEN=xyz

***REMOVED*** Or use .env file (gitignored)
echo "REGISTRY_TOKEN=xyz" >> .env
```

**For production**:
```yaml
***REMOVED*** Use Kubernetes secrets
apiVersion: v1
kind: Secret
metadata:
  name: agent-config
type: Opaque
data:
  token: <base64-encoded>
```

***REMOVED******REMOVED******REMOVED*** Reporting Security Issues

**Do NOT create public GitHub issues for security vulnerabilities.**

Instead:
1. Email security@kubeadapt.io
2. Include detailed description
3. Include steps to reproduce
4. Allow time for a fix before disclosure

---

***REMOVED******REMOVED*** 📄 License

By contributing, you agree that your contributions will be licensed under the same license as the project (check LICENSE file).

---

***REMOVED******REMOVED*** 🎉 Thank You!

Every contribution makes KubeAdapt better:

- 🐛 **Bug fixes** improve stability for all users
- ✨ **Features** add value to the platform
- 📚 **Documentation** helps onboard new contributors
- 🧪 **Tests** prevent regressions
- 💡 **Ideas** spark innovation

Your time and expertise are genuinely appreciated. Welcome to the team! 🚀

---

**Quick Links**:
- [README.md](README.md) - Project overview
- [Makefile](Makefile) - All available commands (Lines 52-95 for help)
- [Architecture Decisions](docs/ARCHITECTURE_DECISIONS.md) - Design rationale
- [E2E Testing Guide](test/e2e/README.md) - End-to-end test details
