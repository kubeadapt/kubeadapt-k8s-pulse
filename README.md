# KubeAdapt eBPF Network Metrics Agent

High-performance eBPF-based network observation agent for Kubernetes, providing accurate pod-level bandwidth metrics with minimal overhead.

## Overview

The eBPF agent runs as a DaemonSet on each Kubernetes node, capturing network packets at the Traffic Control (TC) layer to track pod-to-pod traffic. It exports raw IP-based connection metrics to Prometheus. Tasks such as metadata enrichment and traffic pattern analysis are intentionally left out of the agent and can be outsourced to external services, giving users the flexibility to choose or build their own processors for these functions.

### Key Features

- **Pod-Level Traffic Tracking**: Monitors network traffic between pods using TC eBPF hooks
- **Protocol Support**: TCP and UDP traffic with separate tracking
- **IPv4 and IPv6 Support**: Full dual-stack support (kernel 5.10+)
- **Pod Egress Tracking**: TC ingress hooks on host interfaces capture pod-to-pod and cross-node traffic
- **Multi-Interface Deduplication**: Prevents counting same packet across interface paths
- **Overflow Protection**: Ringbuffer captures flows when map reaches capacity

## Quick Start

### Prerequisites

- **Kubernetes**: 1.24+
- **Kernel**: Linux 5.8+ (for eBPF support)
- **Go**: 1.25+
- **LLVM/Clang**: 14+ (for BPF compilation)

### Installation via Helm

The eBPF agent is available as a standalone Helm chart.

```bash
# Add the KubeAdapt Helm repository
helm repo add kubeadapt https://kubeadapt.github.io/kubeadapt-helm
helm repo update

# Install the eBPF agent
helm install kubeadapt-kubeadapt-k8s-pulse kubeadapt/kubeadapt-k8s-pulse \
  -n kubeadapt --create-namespace

# Verify deployment
kubectl get pods -n kubeadapt -l app.kubernetes.io/name=kubeadapt-k8s-pulse
```

> **Note:** Using `kubeadapt-kubeadapt-k8s-pulse` as the release name ensures the service name matches Prometheus scrape configurations.

For chart configuration options, see the [kubeadapt-helm repository](https://github.com/kubeadapt/kubeadapt-helm/tree/main/charts/kubeadapt-k8s-pulse).

### Local Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed development setup instructions.

## Configuration

Configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `EBPF_METRICS_PORT` | `9090` | Prometheus metrics server port |
| `EBPF_COLLECTION_INTERVAL` | `25s` | Map reading interval |
| `EBPF_CONNECTION_TRACKING` | `true` | Enable connection tracking |
| `EBPF_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |
| `EBPF_LOG_FORMAT` | `json` | Log format (json/console) |
| `EBPF_DUMP_BPF_MAPS` | `false` | Dump BPF map contents for debugging |
| `NODE_NAME` | - | Kubernetes node name (auto-set by DaemonSet) |

## Exported Metrics

### Pod-Level Traffic Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `kubeadapt_connection_traffic_bytes_total` | Counter | Cumulative egress bytes (use `rate()` for throughput) |
| `kubeadapt_connection_traffic_packets_total` | Counter | Cumulative egress packets |
| `kubeadapt_active_connections` | Gauge | Current active connections |

### Internal Monitoring Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `kubeadapt_bpf_load_status` | Gauge | BPF program load status (1=loaded, 0=failed) |
| `kubeadapt_bpf_load_attempts_total` | Counter | Total BPF load attempts |
| `kubeadapt_bpf_load_duration_seconds` | Gauge | BPF program load duration |
| `kubeadapt_bpf_map_utilization_percent` | Gauge | BPF map utilization (0-100%) |
| `kubeadapt_overflow_flows_total` | Counter | Flows sent to overflow ringbuffer |
| `kubeadapt_ip_pairs_batch_size` | Gauge | Number of IP pairs in current batch |
| `kubeadapt_ebpf_collection_duration_seconds` | Histogram | Map collection cycle duration |
| `kubeadapt_collector_errors_total` | Counter | Collection errors by type |
| `kubeadapt_connection_tracking_info` | Gauge | Connection tracking configuration info |

## Architecture

For detailed architecture documentation including:
- High-level and low-level eBPF architecture diagrams
- Data flow and metric export details
- Counter metrics with read-then-delete pattern
- Performance characteristics

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Project Structure

```
kubeadapt-k8s-pulse/
├── bpf/
│   └── network_monitor_tc.c    # eBPF TC ingress hook program (captures pod egress)
├── cmd/agent/
│   └── main.go                 # Agent entry point
├── internal/
│   ├── bpf/                    # BPF program loading & generated Go bindings
│   ├── collector/              # Connection aggregation
│   ├── config/                 # Configuration management
│   ├── metrics/                # Prometheus HTTP server
│   └── system/                 # Kernel version detection
├── test/
│   ├── e2e/                    # End-to-end tests (Kind cluster)
│   └── integration/            # BPF integration tests
├── configs/                    # Configuration files
├── docs/                       # Architecture documentation
└── Makefile                    # Build automation
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, debugging, and contribution guidelines.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.