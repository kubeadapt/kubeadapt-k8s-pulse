***REMOVED*** Kubernetes Deployment Guide

This directory contains production-ready Kubernetes manifests for deploying the KubeAdapt eBPF Agent.

***REMOVED******REMOVED*** 📦 Deployment Files

| File | Purpose | Required |
|------|---------|----------|
| `namespace.yaml` | Creates `kubeadapt-system` namespace with Pod Security Standards | ✅ Yes |
| `rbac.yaml` | ServiceAccount, ClusterRole, ClusterRoleBinding for agent permissions | ✅ Yes |
| `daemonset.yaml` | DaemonSet that deploys agent to all nodes | ✅ Yes |
| `servicemonitor.yaml` | Prometheus ServiceMonitor for metrics scraping | ⚠️ Optional* |

\* Only required if using Prometheus Operator. For standard Prometheus, configure scraping manually.

***REMOVED******REMOVED*** 🚀 Deployment Order

**IMPORTANT**: Apply in this order to avoid dependency issues:

```bash
***REMOVED*** 1. Create namespace
kubectl apply -f namespace.yaml

***REMOVED*** 2. Create RBAC (ServiceAccount, ClusterRole, ClusterRoleBinding)
kubectl apply -f rbac.yaml

***REMOVED*** 3. Deploy the agent DaemonSet
kubectl apply -f daemonset.yaml

***REMOVED*** 4. (Optional) Add Prometheus ServiceMonitor
kubectl apply -f servicemonitor.yaml
```

***REMOVED******REMOVED******REMOVED*** Quick Deploy (All-in-One)

```bash
kubectl apply -f deployments/kubernetes/
```

This works because kubectl applies resources in the correct order automatically.

***REMOVED******REMOVED*** 🔍 Configuration Details

***REMOVED******REMOVED******REMOVED*** DaemonSet Configuration

**Security Context:**
- `privileged: true` - Required for eBPF kprobe attachment and BPF map operations
- `hostNetwork: true` - Required for host-level network monitoring
- `hostPID: true` - Required for cgroup/container discovery

**Volume Mounts:**
- `/sys` → Network interface discovery, cgroup data
- `/host/proc` → Container/process identification
- `/sys/fs/bpf` → BPF map persistence (bidirectional propagation)
- `/sys/fs/cgroup` → Container cgroup tracking
- `/sys/kernel/debug` → Kernel tracepoint access

**Resource Limits:**
- CPU: 500m limit, 100m request
- Memory: 384Mi limit, 128Mi request

**Collection Interval:**
- **25 seconds** (must be < Prometheus scrape interval)
- Ensures only ONE collection between scrapes (prevents gauge overwrites)
- 5-second safety buffer before 30s Prometheus scrape

***REMOVED******REMOVED******REMOVED*** RBAC Permissions

The agent requires **NO Kubernetes API permissions** - it only needs a ServiceAccount for pod identity:

**ServiceAccount Only:**
- No ClusterRole (no API access needed)
- No ClusterRoleBinding (no permissions granted)
- ServiceAccount exists only for cluster admission controllers that require it

**Why zero permissions?**
The agent exports **raw IP-based metrics only** (src_ip, dst_ip, protocol). The backend service handles **ALL enrichment** (pod names, namespaces, services, zones, regions) by querying the Kubernetes API separately. This architecture:
- ✅ Follows principle of least privilege (zero K8s API access)
- ✅ Reduces attack surface (agent can't access cluster metadata)
- ✅ Eliminates K8s API load from agents (no list/watch calls)
- ✅ Simplifies troubleshooting (no RBAC permission issues)

***REMOVED******REMOVED******REMOVED*** ServiceMonitor Configuration

**Scrape Configuration:**
- **Interval: 30 seconds** (standard Prometheus scrape)
- **Timeout: 10 seconds**
- **Port: 9090** (`/metrics` endpoint)

**Automatic Labels:**
- `node` - Node name from pod metadata
- `pod` - Pod name
- `namespace` - Namespace
- `zone` - From node label `topology.kubernetes.io/zone`
- `region` - From node label `topology.kubernetes.io/region`

***REMOVED******REMOVED*** ✅ Verification

***REMOVED******REMOVED******REMOVED*** Check Agent Status

```bash
***REMOVED*** View DaemonSet status
kubectl get daemonset -n kubeadapt-system

***REMOVED*** View agent pods
kubectl get pods -n kubeadapt-system -l app=kubeadapt-ebpf-agent

***REMOVED*** Check pod logs
kubectl logs -n kubeadapt-system -l app=kubeadapt-ebpf-agent --tail=50

***REMOVED*** Follow logs from all agents
kubectl logs -n kubeadapt-system -l app=kubeadapt-ebpf-agent -f
```

***REMOVED******REMOVED******REMOVED*** Verify Metrics

```bash
***REMOVED*** Port-forward to agent
kubectl port-forward -n kubeadapt-system daemonset/kubeadapt-ebpf-agent 9090:9090

***REMOVED*** Fetch metrics
curl http://localhost:9090/metrics | grep kubeadapt_

***REMOVED*** Check health endpoints
curl http://localhost:9090/health/live    ***REMOVED*** Liveness
curl http://localhost:9090/health/ready   ***REMOVED*** Readiness
```

***REMOVED******REMOVED******REMOVED*** Check Prometheus Integration

```bash
***REMOVED*** View ServiceMonitor
kubectl get servicemonitor -n kubeadapt-system

***REMOVED*** Check Prometheus targets (if using Prometheus Operator)
***REMOVED*** Navigate to: http://<prometheus-url>/targets
***REMOVED*** Look for: kubeadapt-system/kubeadapt-ebpf-agent/0
```

***REMOVED******REMOVED*** 🔧 Troubleshooting

***REMOVED******REMOVED******REMOVED*** Agent Pod CrashLoopBackOff

**Check kernel version:**
```bash
kubectl get nodes -o wide
***REMOVED*** eBPF requires kernel 4.18+ (5.8+ recommended)
```

**Check BPF filesystem:**
```bash
kubectl exec -n kubeadapt-system -it <pod-name> -- ls -la /sys/fs/bpf/
```

**View detailed logs:**
```bash
kubectl logs -n kubeadapt-system <pod-name> --previous
```

***REMOVED******REMOVED******REMOVED*** No Metrics in Prometheus

**Verify ServiceMonitor:**
```bash
kubectl get servicemonitor -n kubeadapt-system -o yaml
```

**Check Prometheus Operator logs:**
```bash
kubectl logs -n monitoring -l app=prometheus-operator
```

**Manual scrape test:**
```bash
kubectl run curl --image=curlimages/curl -it --rm -- \
  curl http://kubeadapt-ebpf-agent.kubeadapt-system.svc:9090/metrics
```

***REMOVED******REMOVED******REMOVED*** ServiceAccount Issues

**Verify ServiceAccount exists:**
```bash
kubectl get serviceaccount -n kubeadapt-system kubeadapt-ebpf-agent
```

**Note:** The agent does NOT access the Kubernetes API, so RBAC permission errors should never occur. If you see permission denied errors, they are NOT from the agent itself.

***REMOVED******REMOVED*** 🔐 Security Considerations

***REMOVED******REMOVED******REMOVED*** Why Privileged Mode?

The agent requires `privileged: true` for:
1. **BPF syscalls** - Loading eBPF programs into the kernel
2. **Kernel tracepoints** - Attaching kprobes to TCP/UDP functions
3. **BPF map operations** - Creating/reading shared maps with kernel
4. **Mount propagation** - Bidirectional propagation for `/sys/fs/bpf`

**This is standard for eBPF monitoring agents** (Cilium, Falco, Pixie, etc.)

***REMOVED******REMOVED******REMOVED*** Pod Security Standards

The namespace uses `pod-security.kubernetes.io/enforce: privileged` to allow eBPF operations.

This is appropriate because:
- Agent runs in isolated namespace (`kubeadapt-system`)
- Only read access to host resources (except BPF maps)
- No access to secrets or configmaps outside its namespace
- Read-only root filesystem (except BPF maps and /tmp)

***REMOVED******REMOVED*** 📊 Metrics Reference

The agent exposes these metric families:

**Network Metrics:**
- `kubeadapt_network_bytes_total` - Bytes transmitted/received per connection
- `kubeadapt_network_packets_total` - Packets transmitted/received
- `kubeadapt_network_connections_total` - Active connections by protocol

**Agent Health:**
- `kubeadapt_agent_info` - Agent version and build info
- `kubeadapt_bpf_map_entries` - BPF map utilization
- `kubeadapt_collection_duration_seconds` - Collection latency

All metrics include labels: `node`, `pod`, `namespace`, `zone`, `region`

***REMOVED******REMOVED*** 🔄 Updates and Rollouts

***REMOVED******REMOVED******REMOVED*** Update Agent Image

```bash
kubectl set image daemonset/kubeadapt-ebpf-agent \
  -n kubeadapt-system \
  ebpf-agent=kubeadapt/ebpf-agent:v1.2.3
```

***REMOVED******REMOVED******REMOVED*** Rolling Update Strategy

The DaemonSet uses `maxUnavailable: 1` to ensure:
- Only one node at a time loses monitoring during updates
- Gradual rollout minimizes risk
- Fast rollback if issues detected

***REMOVED******REMOVED******REMOVED*** Rollback

```bash
kubectl rollout undo daemonset/kubeadapt-ebpf-agent -n kubeadapt-system
```

***REMOVED******REMOVED*** 📚 Related Documentation

- [Architecture Overview](../../docs/architecture.md)
- [Development Guide](../../docs/development.md)
- [Metrics Reference](../../docs/metrics.md)
- [E2E Testing](../../test/e2e/README.md)

***REMOVED******REMOVED*** 🐛 Support

For issues or questions:
- GitHub Issues: https://github.com/kubeadapt/ebpf-agent/issues
- Documentation: https://docs.kubeadapt.io
- Slack: https://kubeadapt.slack.com
