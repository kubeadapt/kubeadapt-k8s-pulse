***REMOVED*** Contributing to KubeAdapt eBPF Agent

***REMOVED******REMOVED*** Prerequisites

Before you start, make sure you have:

- **Go 1.21+** - `go version`
- **Docker Desktop** (macOS) or **Docker Engine** (Linux) - `docker --version`
- **Make** - `make --version` (comes with Xcode tools on macOS)

**macOS developers**: You don't need LLVM, clang, or Linux kernel headers locally - Docker handles BPF compilation.

***REMOVED******REMOVED*** Quick Start

```bash
***REMOVED*** Clone and setup
git clone <repository-url>
cd ebpf-agent

***REMOVED*** Initialize and build
make quickstart

***REMOVED*** Run the agent
make run-local
```

Access points:
- Metrics: `http://localhost:9090/metrics`
- Health: `http://localhost:9090/health`
- Prometheus: `http://localhost:9091`

***REMOVED******REMOVED*** Step-by-Step Setup

```bash
***REMOVED*** 1. Initialize development environment
make init

***REMOVED*** 2. Install Go tools
make deps

***REMOVED*** 3. Generate BPF code
make generate

***REMOVED*** 4. Build the Go binary
make build

***REMOVED*** 5. Run tests
make test

***REMOVED*** 6. Run the full stack
make run-local
```

---

***REMOVED******REMOVED*** Development Environment

***REMOVED******REMOVED******REMOVED*** macOS vs Linux

**On macOS**: Code editing, Git, Go compilation, unit tests, linting run natively.

**In Docker**: BPF compilation, eBPF program loading, agent runtime, integration tests.

eBPF requires Linux kernel - Docker provides a consistent Linux environment for cross-platform development.

***REMOVED******REMOVED******REMOVED*** Dockerfiles

| Dockerfile | Purpose | Command |
|------------|---------|---------|
| `Dockerfile.bpf-builder` | Compiles BPF C code into Go bindings | `make generate` |
| `Dockerfile.dev` | Development container with hot-reload | `make dev` |
| `Dockerfile` | Production build (slim image) | `make docker-build` |

---

***REMOVED******REMOVED*** Development Workflows

***REMOVED******REMOVED******REMOVED*** Fixing Go Code

```bash
***REMOVED*** Edit the file, then:
make test   ***REMOVED*** Run unit tests
make lint   ***REMOVED*** Check code style
make build  ***REMOVED*** Build binary
make run-local  ***REMOVED*** Test in full environment
```

***REMOVED******REMOVED******REMOVED*** Modifying BPF Code

```bash
***REMOVED*** Edit bpf/network_monitor.c, then:
make generate    ***REMOVED*** Regenerate Go bindings
make test-docker ***REMOVED*** Test BPF loading (needs Linux kernel)
make run-local   ***REMOVED*** Full stack test
```

***REMOVED******REMOVED******REMOVED*** Hot-Reload Development

```bash
***REMOVED*** Terminal 1: Start dev mode with hot-reload
make dev

***REMOVED*** Terminal 2: Watch logs
docker-compose logs -f ebpf-dev

***REMOVED*** Now edit Go files - changes trigger automatic rebuilds
```

---

***REMOVED******REMOVED*** Testing

***REMOVED******REMOVED******REMOVED*** Test Levels

| Level | Command | What it tests |
|-------|---------|---------------|
| Unit | `make test` | Go business logic (no kernel) |
| Integration | `make test-docker` | BPF loading, map operations |
| E2E | `make test-e2e` | Full system in Kind cluster |

***REMOVED******REMOVED******REMOVED*** Test Selection

| I changed... | Run this |
|--------------|----------|
| Go business logic | `make test` |
| BPF C code | `make test-docker` |
| Kubernetes integration | `make test-e2e` |

***REMOVED******REMOVED******REMOVED*** Coverage

```bash
make test-coverage  ***REMOVED*** Generates HTML coverage report
```

Aim for >70% coverage on new code.

---

***REMOVED******REMOVED*** Debugging

***REMOVED******REMOVED******REMOVED*** Health Check

```bash
curl localhost:9090/health
curl localhost:9090/health/ready
curl localhost:9090/health/live
```

***REMOVED******REMOVED******REMOVED*** Check Logs

```bash
***REMOVED*** Local
docker-compose logs -f ebpf-agent

***REMOVED*** Kubernetes
kubectl logs -n kubeadapt -l app.kubernetes.io/name=ebpf-agent -f
```

***REMOVED******REMOVED******REMOVED*** Debug BPF Programs

```bash
***REMOVED*** List loaded BPF programs
docker-compose exec ebpf-agent bpftool prog list

***REMOVED*** Check BPF maps
docker-compose exec ebpf-agent bpftool map list

***REMOVED*** Dump map contents
docker-compose exec ebpf-agent bpftool map dump id <map-id>
```

***REMOVED******REMOVED******REMOVED*** Performance Profiling

```bash
***REMOVED*** CPU profiling
curl localhost:9090/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

***REMOVED*** Memory profiling
curl localhost:9090/debug/pprof/heap > mem.prof
go tool pprof mem.prof
```

---

***REMOVED******REMOVED*** Docker Services

| Service | Purpose | Port |
|---------|---------|------|
| `ebpf-agent` | Main agent | 9090 |
| `ebpf-dev` | Development with hot-reload | 9090 |
| `bpf-builder` | BPF compilation | - |
| `prometheus` | Metrics collection | 9091 |

***REMOVED******REMOVED******REMOVED*** Build Commands

```bash
make docker-build   ***REMOVED*** Single-arch (local testing)
make docker-buildx  ***REMOVED*** Multi-arch (production: amd64 + arm64)
```

---

***REMOVED******REMOVED*** Troubleshooting

| Error | Solution |
|-------|----------|
| `clang: command not found` (macOS) | Use `make generate` (auto-detects OS and uses Docker) |
| Docker daemon not running | Start Docker Desktop or `sudo systemctl start docker` |
| Port 9090 in use | `lsof -i :9090` then kill the process |
| BPF program failed to load | Check kernel version (5.8+ required) |
| Permission denied (BPF) | Ensure container has `privileged: true` and required capabilities |
| Tests failing (no such file) | Run `make generate` first |
| exec format error | Use `make docker-buildx` for multi-arch builds |

---

***REMOVED******REMOVED*** Code Quality

***REMOVED******REMOVED******REMOVED*** Before Committing

```bash
make fmt   ***REMOVED*** Format code (gofmt, goimports, clang-format)
make lint  ***REMOVED*** Run linters (golangci-lint)
```

***REMOVED******REMOVED******REMOVED*** Style Guidelines

- **Go**: Standard Go conventions, `gofmt` formatting
- **BPF C**: Linux kernel coding style, tabs for indentation

***REMOVED******REMOVED******REMOVED*** Test Standards

- New features: >70% coverage
- Bug fixes: Add regression test
- Use descriptive test names and table-driven tests

---

***REMOVED******REMOVED*** Submitting Your Work

***REMOVED******REMOVED******REMOVED*** Pre-Submit Checklist

```bash
make fmt          ***REMOVED*** Format code
make lint         ***REMOVED*** Run linters
make test         ***REMOVED*** Unit tests
make test-docker  ***REMOVED*** Integration tests (if BPF changed)
make docker-build ***REMOVED*** Build image
make run-local    ***REMOVED*** Test locally
```

***REMOVED******REMOVED******REMOVED*** Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

**Examples**:
```bash
feat(bpf): add IPv6 support for connection tracking
fix(metrics): correct byte counter overflow
refactor(collector): simplify aggregation logic
```

***REMOVED******REMOVED******REMOVED*** Pull Request Process

1. Fork and create a feature branch
2. Make changes and test thoroughly
3. Push and create PR with clear description
4. Address code review feedback

---

***REMOVED******REMOVED*** FAQ

**Q: Where do I start with eBPF?**
A: Read `bpf/network_monitor.c`, then `internal/bpf/loader.go`.

**Q: When to regenerate BPF code?**
A: Only when you modify `bpf/network_monitor.c`.

**Q: Why two generated files (bpfel.go and bpfeb.go)?**
A: Little-Endian (x86_64, ARM64) and Big-Endian architectures.

---

***REMOVED******REMOVED*** Security

Never commit credentials, tokens, or secrets. Use environment variables or Kubernetes secrets.

Report security issues to security@kubeadapt.io (not public GitHub issues).

---

***REMOVED******REMOVED*** License

Contributions are licensed under the project's Apache 2.0 license.
