***REMOVED*** KubeAdapt eBPF Network Metrics Agent

High-performance eBPF-based network observation agent for Kubernetes, providing accurate pod-level bandwidth metrics with minimal overhead.

***REMOVED******REMOVED*** Overview

The eBPF agent runs as a DaemonSet on each Kubernetes node, capturing network packets at the Traffic Control (TC) layer to track pod-to-pod traffic. It exports raw IP-based connection metrics to Prometheus. Tasks such as metadata enrichment and traffic pattern analysis are intentionally left out of the agent and can be outsourced to external services, giving users the flexibility to choose or build their own processors for these functions.

***REMOVED******REMOVED******REMOVED*** Key Features

- **Pod-Level Traffic Tracking**: Monitors network traffic between pods using TC eBPF hooks
- **Protocol Support**: TCP and UDP traffic with separate tracking
- **IPv4 and IPv6 Support**: Full dual-stack support(IPv6 requires enabling a flag and only supported 5.15+ kernel versions)
- **Egress-Only Tracking**: same-node and cross-node across pods
- **Multi-Interface Deduplication**: Prevents counting same packet across interface paths
- **Overflow Protection**: Ringbuffer captures flows when map reaches capacity

***REMOVED******REMOVED*** Quick Start

***REMOVED******REMOVED******REMOVED*** Prerequisites

- **Kubernetes**: 1.24+
- **Kernel**: Linux 5.8+ (for eBPF support)
- **Go**: 1.25+
- **LLVM/Clang**: 14+ (for BPF compilation)

***REMOVED******REMOVED******REMOVED*** Installation via Helm

The eBPF agent is available as a standalone Helm chart.

```bash
***REMOVED*** Add the KubeAdapt Helm repository
helm repo add kubeadapt https://kubeadapt.github.io/kubeadapt-helm
helm repo update

***REMOVED*** Install the eBPF agent
helm install ebpf-agent kubeadapt/ebpf-agent \
  -n kubeadapt --create-namespace

***REMOVED*** Verify deployment
kubectl get pods -n kubeadapt -l app.kubernetes.io/name=ebpf-agent
```

For chart configuration options, see the [kubeadapt-helm repository](https://github.com/kubeadapt/kubeadapt-helm/tree/main/charts/ebpf-agent).

***REMOVED******REMOVED******REMOVED*** Local Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed development setup instructions.

***REMOVED******REMOVED*** Configuration

Configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `EBPF_METRICS_PORT` | `9090` | Prometheus metrics server port |
| `EBPF_COLLECTION_INTERVAL` | `25s` | Map reading interval |
| `EBPF_CONNECTION_TRACKING` | `true` | Enable connection tracking |
| `EBPF_NETNS_FILTER_MODE` | `default` | Network namespace filtering (`default` or `disabled`) |
| `EBPF_LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |
| `EBPF_LOG_FORMAT` | `json` | Log format (json/console) |
| `EBPF_DUMP_BPF_MAPS` | `false` | Dump BPF map contents for debugging |
| `NODE_NAME` | - | Kubernetes node name (auto-set by DaemonSet) |

***REMOVED******REMOVED*** Exported Metrics

***REMOVED******REMOVED******REMOVED*** Pod-Level Traffic Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `kubeadapt_connection_traffic_bytes_total` | Counter | Cumulative egress bytes (use `rate()` for throughput) |
| `kubeadapt_connection_traffic_packets_total` | Counter | Cumulative egress packets |
| `kubeadapt_active_connections` | Gauge | Current active connections |

***REMOVED******REMOVED******REMOVED*** Internal Monitoring Metrics

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

***REMOVED******REMOVED*** Architecture

For detailed architecture documentation including:
- High-level and low-level eBPF architecture diagrams
- Data flow and metric export details
- Counter metrics with read-then-delete pattern
- Performance characteristics

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

***REMOVED******REMOVED*** Project Structure

```
ebpf-agent/
├── bpf/
│   └── network_monitor_tc.c    ***REMOVED*** eBPF TC egress hook program
├── cmd/agent/
│   └── main.go                 ***REMOVED*** Agent entry point
├── internal/
│   ├── bpf/                    ***REMOVED*** BPF program loading & generated Go bindings
│   ├── collector/              ***REMOVED*** Connection aggregation
│   ├── config/                 ***REMOVED*** Configuration management
│   ├── metrics/                ***REMOVED*** Prometheus HTTP server
│   └── system/                 ***REMOVED*** Kernel version detection
├── test/
│   ├── e2e/                    ***REMOVED*** End-to-end tests (Kind cluster)
│   └── integration/            ***REMOVED*** BPF integration tests
├── configs/                    ***REMOVED*** Configuration files
├── docs/                       ***REMOVED*** Architecture documentation
└── Makefile                    ***REMOVED*** Build automation
```

***REMOVED******REMOVED*** Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, debugging, and contribution guidelines.

***REMOVED******REMOVED*** License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.