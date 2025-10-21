***REMOVED*** Grafana Dashboard Configuration

This directory contains Grafana configuration for the KubeAdapt eBPF Agent dashboard.

***REMOVED******REMOVED*** 📁 Structure

```
grafana/
├── dashboards/
│   └── ebpf-agent-dashboard.json   ***REMOVED*** Main network monitoring dashboard
└── datasources/
    └── prometheus.yml              ***REMOVED*** Prometheus datasource configuration
```

***REMOVED******REMOVED*** 🚀 Quick Start

***REMOVED******REMOVED******REMOVED*** For Docker Compose

The dashboard is automatically provisioned when running `make run-local`. No manual setup required!

***REMOVED******REMOVED******REMOVED*** For Kubernetes

1. Create a ConfigMap for the datasource:
```bash
kubectl create configmap grafana-datasources \
  --from-file=configs/grafana/datasources/prometheus.yml \
  -n kubeadapt
```

2. Create a ConfigMap for the dashboard:
```bash
kubectl create configmap grafana-dashboards \
  --from-file=configs/grafana/dashboards/ebpf-agent-dashboard.json \
  -n kubeadapt
```

3. Mount these ConfigMaps in your Grafana deployment:
```yaml
volumes:
  - name: datasources
    configMap:
      name: grafana-datasources
  - name: dashboards
    configMap:
      name: grafana-dashboards

volumeMounts:
  - name: datasources
    mountPath: /etc/grafana/provisioning/datasources
  - name: dashboards
    mountPath: /etc/grafana/provisioning/dashboards
```

***REMOVED******REMOVED*** 📊 Dashboard Features

***REMOVED******REMOVED******REMOVED*** Network Traffic Rate - Top 50 (Egress Only)
- Real-time bandwidth monitoring (bytes/second)
- Limited to top 50 consumers for performance
- Uses 5m rate window for stable calculations
- Protocol-based filtering (TCP/UDP)

***REMOVED******REMOVED******REMOVED*** BPF Map Utilization
- Gauge showing current map usage (out of 100K max entries)
- Color-coded thresholds: Green (<70%), Yellow (70-85%), Red (>85%)

***REMOVED******REMOVED******REMOVED*** BPF Map Overflow Rate
- Monitors dropped connections due to map overflow
- Uses instant rate (irate) for spike detection
- Should always be zero in healthy systems

***REMOVED******REMOVED******REMOVED*** Active Connections by Protocol
- Real-time count of active TCP/UDP connections
- Useful for capacity planning

***REMOVED******REMOVED******REMOVED*** Collector Error Rate
- Shows error rate (errors/second) not cumulative count
- Tracks errors by type during metric collection
- Helps identify active vs historical issues

***REMOVED******REMOVED******REMOVED*** Top 20 Bandwidth Consumers (Egress)
- Identifies highest bandwidth consumers
- Limited to top 20 for performance
- Shows actual bandwidth rate (bytes/second)

***REMOVED******REMOVED*** 🔧 Customization

***REMOVED******REMOVED******REMOVED*** Changing the Prometheus URL

Edit `datasources/prometheus.yml`:
```yaml
url: http://your-prometheus-url:9090
```

***REMOVED******REMOVED******REMOVED*** Dashboard Datasource References

The dashboard uses `"uid": null` for all datasource references, which automatically uses the default Prometheus datasource.

**Why this works for public sharing:**
- ✅ No UID conflicts when provisioning in new environments
- ✅ Works immediately after copying configuration files
- ✅ Grafana automatically generates a unique UID for the datasource
- ✅ Dashboard queries reference the default datasource via `null`

**Alternative:** If you prefer explicit UIDs, you can manually create the datasource in Grafana first, then reference its UID in the dashboard. However, the `null` approach is simpler and more portable.

***REMOVED******REMOVED******REMOVED*** Time Range

Default: Last 1 hour, auto-refresh every 30 seconds (matches Prometheus scrape interval)

To change, edit the dashboard JSON:
```json
"refresh": "30s",           ***REMOVED*** Auto-refresh interval (matches scrape)
"time": {
  "from": "now-1h",         ***REMOVED*** Start time
  "to": "now"               ***REMOVED*** End time
}
```

**Best Practice:** Refresh interval should match Prometheus scrape interval to prevent unnecessary queries.

***REMOVED******REMOVED*** 🐛 Troubleshooting

***REMOVED******REMOVED******REMOVED*** Dashboard shows "No data"

1. **Check Prometheus is reachable**:
   ```bash
   kubectl port-forward svc/prometheus 9090:9090 -n kubeadapt
   curl http://localhost:9090/api/v1/query?query=up
   ```

2. **Verify metrics are being scraped**:
   ```bash
   curl http://localhost:9090/api/v1/query?query=kubeadapt_connection_traffic_bytes
   ```

3. **Check datasource UID matches**:
   - Open Grafana → Configuration → Data Sources
   - Note the UID of your Prometheus datasource
   - Ensure it matches `uid` in `datasources/prometheus.yml`

***REMOVED******REMOVED******REMOVED*** Datasource provisioning fails

**Error**: `Datasource provisioning error: data source not found`

**Solution**: Delete Grafana's persistent volume to allow fresh provisioning:
```bash
***REMOVED*** Docker Compose
docker compose down -v
docker compose up

***REMOVED*** Kubernetes
kubectl delete pvc grafana-data -n kubeadapt
kubectl rollout restart deployment/grafana -n kubeadapt
```

***REMOVED******REMOVED*** 📝 Notes

- **Metric Naming**: All metrics start with `kubeadapt_`
- **Egress-Only**: Dashboard only tracks egress (outbound) traffic
- **Label Cardinality**: Each unique src_ip/dst_ip/protocol combination creates a new metric series
- **BPF Map Size**: Default 100,000 entries (configurable in agent)
- **Performance Optimizations**: All high-cardinality queries use `topk()` to limit series
- **Rate Windows**: All rate calculations use 5m windows (10× scrape interval)
- **Recent Improvements**: See `DASHBOARD_IMPROVEMENTS.md` for critical fixes applied (2025-10-20)

***REMOVED******REMOVED*** 🔗 Related Documentation

- [eBPF Agent README](../../README.md)
- [Prometheus Configuration](../prometheus.yml)
- [Grafana Provisioning Docs](https://grafana.com/docs/grafana/latest/administration/provisioning/)
