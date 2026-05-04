# Contributing to KubeAdapt eBPF Agent

## Prerequisites

Before you start, make sure you have:

- **Go 1.21+** - `go version`
- **Docker Desktop** (macOS) or **Docker Engine** (Linux) - `docker --version`
- **Make** - `make --version` (comes with Xcode tools on macOS)

**macOS developers**: You don't need LLVM, clang, or Linux kernel headers locally - Docker handles BPF compilation.

## Quick Start

```bash
# Clone and setup
git clone <repository-url>
cd ebpf-agent

# Initialize and build
make quickstart

# Run the agent
make run-local
```

Access points:
- Metrics: `http://localhost:9090/metrics`
- Health: `http://localhost:9090/health`
- Prometheus: `http://localhost:9091`

## Step-by-Step Setup

```bash
# 1. Initialize development environment
make init

# 2. Install Go tools
make deps

# 3. Generate BPF code
make generate

# 4. Build the Go binary
make build

# 5. Run tests
make test

# 6. Run the full stack
make run-local
```

---

## Development Environment

### macOS vs Linux

**On macOS**: Code editing, Git, Go compilation, unit tests, linting run natively.

**In Docker**: BPF compilation, eBPF program loading, agent runtime, integration tests.

eBPF requires Linux kernel - Docker provides a consistent Linux environment for cross-platform development.

### Dockerfiles

| Dockerfile | Purpose | Command |
|------------|---------|---------|
| `Dockerfile.bpf-builder` | Compiles BPF C code into Go bindings | `make generate` |
| `Dockerfile.dev` | Development container with hot-reload | `make dev` |
| `Dockerfile` | Production build (slim image) | `make docker-build` |

---

## Development Workflows

### Fixing Go Code

```bash
# Edit the file, then:
make test   # Run unit tests
make lint   # Check code style
make build  # Build binary
make run-local  # Test in full environment
```

### Modifying BPF Code

```bash
# Edit bpf/network_monitor.c, then:
make generate    # Regenerate Go bindings
make test-docker # Test BPF loading (needs Linux kernel)
make run-local   # Full stack test
```

### Hot-Reload Development

```bash
# Terminal 1: Start dev mode with hot-reload
make dev

# Terminal 2: Watch logs
docker-compose logs -f ebpf-dev

# Now edit Go files - changes trigger automatic rebuilds
```

---

## Testing

### Test Levels

| Level | Command | What it tests |
|-------|---------|---------------|
| Unit | `make test` | Go business logic (no kernel) |
| Integration | `make test-docker` | BPF loading, map operations |
| E2E | `make test-e2e` | Full system in Kind cluster |

### Test Selection

| I changed... | Run this |
|--------------|----------|
| Go business logic | `make test` |
| BPF C code | `make test-docker` |
| Kubernetes integration | `make test-e2e` |

### Coverage

```bash
make test-coverage  # Generates HTML coverage report
```

Aim for >70% coverage on new code.

---

## Debugging

### Health Check

```bash
curl localhost:9090/health
curl localhost:9090/health/ready
curl localhost:9090/health/live
```

### Check Logs

```bash
# Local
docker-compose logs -f ebpf-agent

# Kubernetes
kubectl logs -n kubeadapt -l app.kubernetes.io/name=ebpf-agent -f
```

### Debug BPF Programs

```bash
# List loaded BPF programs
docker-compose exec ebpf-agent bpftool prog list

# Check BPF maps
docker-compose exec ebpf-agent bpftool map list

# Dump map contents
docker-compose exec ebpf-agent bpftool map dump id <map-id>
```

### Performance Profiling

```bash
# CPU profiling
curl localhost:9090/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof cpu.prof

# Memory profiling
curl localhost:9090/debug/pprof/heap > mem.prof
go tool pprof mem.prof
```

---

## Docker Services

| Service | Purpose | Port |
|---------|---------|------|
| `ebpf-agent` | Main agent | 9090 |
| `ebpf-dev` | Development with hot-reload | 9090 |
| `bpf-builder` | BPF compilation | - |
| `prometheus` | Metrics collection | 9091 |

### Build Commands

```bash
make docker-build   # Single-arch (local testing)
make docker-buildx  # Multi-arch (production: amd64 + arm64)
```

---

## Troubleshooting

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

## Code Quality

### Before Committing

```bash
make fmt   # Format code (gofmt, goimports, clang-format)
make lint  # Run linters (golangci-lint)
```

### Style Guidelines

- **Go**: Standard Go conventions, `gofmt` formatting
- **BPF C**: Linux kernel coding style, tabs for indentation

### Test Standards

- New features: >70% coverage
- Bug fixes: Add regression test
- Use descriptive test names and table-driven tests

---

## Submitting Your Work

### Pre-Submit Checklist

```bash
make fmt          # Format code
make lint         # Run linters
make test         # Unit tests
make test-docker  # Integration tests (if BPF changed)
make docker-build # Build image
make run-local    # Test locally
```

### Commit Message Format

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

### Pull Request Process

1. Fork and create a feature branch
2. Make changes and test thoroughly
3. Push and create PR with clear description
4. Address code review feedback

---

## FAQ

**Q: Where do I start with eBPF?**
A: Read `bpf/network_monitor.c`, then `internal/bpf/loader.go`.

**Q: When to regenerate BPF code?**
A: Only when you modify `bpf/network_monitor.c`.

**Q: Why two generated files (bpfel.go and bpfeb.go)?**
A: Little-Endian (x86_64, ARM64) and Big-Endian architectures.

---

## Security

Never commit credentials, tokens, or secrets. Use environment variables or Kubernetes secrets.

Report security issues to security@kubeadapt.io (not public GitHub issues).

---

## License

Contributions are licensed under the project's Apache 2.0 license.
