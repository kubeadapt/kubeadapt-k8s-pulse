package collector

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/kubeadapt/ebpf-agent/internal/bpf"
	"github.com/kubeadapt/ebpf-agent/internal/system"
)

// ConnectionCollector collects pod-level network metrics from eBPF connection tracking
//
// ARCHITECTURE NOTES:
//
//  1. Pod-level metrics (NOT container-level): K8s pods share network namespace → all containers
//     in a pod have the same IP address. eBPF captures IPv4/IPv6 addresses and cannot differentiate
//     containers within the same pod.
//
//  2. Aggregation strategy: The BPF map stores per-connection entries (5-tuple with ports).
//     This collector aggregates multiple connections between the same pod IPs into a single metric
//     representing TOTAL traffic between those pods.
//
//  3. NO K8s enrichment: Metrics export only raw IP addresses (src_ip, dst_ip, protocol, direction).
//     Backend service handles ALL metadata enrichment (pod names, namespaces, services, zones, regions)
//     through separate K8s API queries.
//
// Example metric output:
//
//	kubeadapt_connection_traffic_bytes{
//	  src_ip="10.244.1.5", dst_ip="10.244.1.6", protocol="tcp", direction="egress"
//	} 4500  ***REMOVED*** Total bytes from pod A to pod B (sum of all TCP connections)
type ConnectionCollector struct {
	bpfManager *bpf.Manager
	logger     *zap.Logger

	// Metrics
	// Raw pod-level IP metrics (NO K8s enrichment - backend handles all aggregation)
	// Using Gauges to export cumulative snapshots from BPF map (netobserv pattern)
	// Prometheus calculates rates using rate() function - no userspace delta tracking needed
	connectionTrafficBytes   *prometheus.GaugeVec // Labels: src_ip, dst_ip, protocol, direction (aggregated by IP pair)
	connectionTrafficPackets *prometheus.GaugeVec // Labels: src_ip, dst_ip, protocol (aggregated by IP pair)

	// Internal tracking metrics (low cardinality)
	activeConnections      *prometheus.GaugeVec
	connectionTrackingInfo *prometheus.GaugeVec
	mapUtilization         *prometheus.GaugeVec
	overflowFlowsTotal     prometheus.Counter // Overflow ringbuffer flow count

	// Batch size monitoring (single time series - NO overhead!)
	// Tracks number of unique IP pairs processed in current collection batch
	// This is NOT cumulative - just the size of each 25-second collection cycle
	ipPairsBatchSize prometheus.Gauge

	// Configuration
	aggregationInterval time.Duration

	// State tracking
	mu                    sync.RWMutex
	totalConnectionsSeen  uint64
	activeConnectionCount int
}

// NewConnectionCollector creates a new connection collector
func NewConnectionCollector(
	bpfManager *bpf.Manager,
	logger *zap.Logger,
	registry *prometheus.Registry,
) *ConnectionCollector {
	c := &ConnectionCollector{
		bpfManager:          bpfManager,
		logger:              logger,
		aggregationInterval: 25 * time.Second,
	}

	// Initialize metrics
	c.initMetrics(registry)

	return c
}

// initMetrics initializes Prometheus metrics
func (c *ConnectionCollector) initMetrics(registry *prometheus.Registry) {
	// Raw IP-based connection traffic metrics (NO K8s enrichment)
	// Backend will handle ALL aggregation (service, namespace, zone, region)
	// NOTE: Using GaugeVec to export cumulative snapshots from BPF map (netobserv pattern)
	// BPF map maintains cumulative counters in kernel - we just snapshot and export
	// Prometheus calculates rates using rate() function
	c.connectionTrafficBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeadapt_connection_traffic_bytes",
			Help: "Cumulative network traffic bytes between pod IP pairs (aggregates all connections with same src/dst IPs, use rate() for rates)",
		},
		[]string{
			"src_ip",    // Source pod IP address
			"dst_ip",    // Destination pod IP address
			"protocol",  // tcp or udp
			"direction", // egress (bytes sent) or ingress (bytes received)
		},
	)

	c.connectionTrafficPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeadapt_connection_traffic_packets",
			Help: "Cumulative network traffic packets between pod IP pairs (aggregates all connections with same src/dst IPs, use rate() for rates)",
		},
		[]string{
			"src_ip",   // Source pod IP address
			"dst_ip",   // Destination pod IP address
			"protocol", // tcp or udp
		},
	)

	// Active connections gauge (low cardinality)
	c.activeConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeadapt_active_connections",
			Help: "Number of active network connections",
		},
		[]string{"protocol"},
	)

	// Connection tracking info
	c.connectionTrackingInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeadapt_connection_tracking_info",
			Help: "Information about connection tracking (map size, cleanup stats)",
		},
		[]string{"metric"},
	)

	// BPF map utilization
	c.mapUtilization = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeadapt_bpf_map_utilization_percent",
			Help: "BPF map utilization percentage",
		},
		[]string{"map_name"},
	)

	// Overflow flow counter
	c.overflowFlowsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubeadapt_overflow_flows_total",
			Help: "Total number of flows sent to overflow ringbuffer (map full)",
		},
	)

	// Batch size monitoring - single Gauge (NOT GaugeVec!)
	// This creates only ONE time series, not one per IP pair
	// Zero Prometheus overhead - tracks instantaneous batch size per collection cycle
	c.ipPairsBatchSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "kubeadapt_ip_pairs_batch_size",
			Help: "Number of unique IP pairs processed in current collection batch (instantaneous, not cumulative)",
		},
	)

	// Register metrics
	registry.MustRegister(c.connectionTrafficBytes)
	registry.MustRegister(c.connectionTrafficPackets)
	registry.MustRegister(c.activeConnections)
	registry.MustRegister(c.connectionTrackingInfo)
	registry.MustRegister(c.mapUtilization)
	registry.MustRegister(c.overflowFlowsTotal)
	registry.MustRegister(c.ipPairsBatchSize)
}

// Start begins the collection loop
func (c *ConnectionCollector) Start(ctx context.Context) {
	// Log kernel version and capabilities
	kernelVersion, err := system.GetKernelVersion()
	if err != nil {
		c.logger.Warn("Failed to detect kernel version", zap.Error(err))
		c.logger.Info("Starting connection collector (read-then-delete pattern)",
			zap.Duration("aggregation_interval", c.aggregationInterval))
	} else {
		c.logger.Info("Starting connection collector (read-then-delete pattern)",
			zap.Duration("aggregation_interval", c.aggregationInterval),
			zap.String("kernel_version", kernelVersion.String()))
	}

	// Start collection loop
	collectionTicker := time.NewTicker(c.aggregationInterval)
	defer collectionTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Stopping connection collector")
			return
		case <-collectionTicker.C:
			c.collect()
		}
	}
}

// collect gathers connection data from BPF maps and exports aggregated IP-based metrics
// NO K8s enrichment - backend handles ALL aggregation (service, namespace, zone, region)
//
// AGGREGATION STRATEGY (netobserv pattern):
// - BPF map stores per-connection cumulative counters (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
// - We aggregate by (src_ip, dst_ip, protocol) to get TOTAL traffic between pod pairs
// - Export cumulative values as Gauges (snapshots of kernel state)
// - Prometheus calculates rates using rate() function
// - NO Reset() needed - Gauges represent current state
func (c *ConnectionCollector) collect() {
	startTime := time.Now()

	connectionMap := c.bpfManager.GetConnectionMap()
	if connectionMap == nil {
		c.logger.Error("Connection map is nil")
		return
	}

	protocolCounts := make(map[string]int)
	flowCount := 0

	// Aggregation key for grouping connections by IP pair + protocol
	type AggKey struct {
		SrcIP    string
		DstIP    string
		Protocol string
	}

	// Aggregated statistics per IP pair (cumulative totals from BPF map)
	type AggStats struct {
		BytesSent       uint64
		BytesReceived   uint64
		PacketsSent     uint64
		PacketsReceived uint64
	}

	// Map to aggregate multiple connections (same IPs, different ports)
	aggregated := make(map[AggKey]AggStats)

	// Update map utilization BEFORE deletion (captures actual map state before collection)
	// This ensures the metric reflects real map usage when Prometheus scrapes /metrics
	c.updateMapUtilization()

	// STEP 1: Iterate BPF map and aggregate by (src_ip, dst_ip, protocol)
	iter := connectionMap.Iterate()
	var key bpf.ConnectionKey
	var stats bpf.ConnectionStats

	deletedCount := 0

	for iter.Next(&key, &stats) {
		// Extract IPs from connection key
		srcIP, dstIP := ConnectionKeyToIPs(&key)

		// Get protocol as string
		protocol := protocolToString(key.Protocol)

		// Create aggregation key (no ports - just IPs and protocol)
		aggKey := AggKey{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: protocol,
		}

		// Aggregate stats for this IP pair (cumulative values from kernel)
		agg := aggregated[aggKey]
		agg.BytesSent += stats.BytesSent
		agg.BytesReceived += stats.BytesReceived
		agg.PacketsSent += stats.PacketsSent
		agg.PacketsReceived += stats.PacketsReceived
		aggregated[aggKey] = agg

		// Count individual connections by protocol (for internal tracking)
		protocolCounts[protocol]++
		flowCount++

		// Delete immediately after reading to prevent data loss
		// for short-lived connections (map cleared every 10s)
		if err := connectionMap.Delete(&key); err != nil {
			c.logger.Debug("Failed to delete entry after read",
				zap.Error(err))
		} else {
			deletedCount++
		}
	}

	if err := iter.Err(); err != nil {
		c.logger.Error("Error iterating connection map", zap.Error(err))
	}

	// STEP 2: Batch size monitoring (single metric value - NO overhead!)
	// This measures the instantaneous batch size, NOT cumulative cardinality
	batchSize := len(aggregated)
	c.ipPairsBatchSize.Set(float64(batchSize))

	// Log warnings if batch size is large (indicates high per-cycle load)
	// Thresholds based on production scenarios (see CARDINALITY_ANALYSIS.md):
	// - 50K: Normal batch size for large clusters (100+ nodes)
	// - 150K: High density batch (200 nodes, 200 pods/node)
	// - 300K: Critical - single batch processing this many pairs needs major resources
	const (
		batchSizeInfoThreshold = 50_000
		batchSizeWarnThreshold = 150_000
		batchSizeCritThreshold = 300_000
	)

	if batchSize > batchSizeCritThreshold {
		c.logger.Error("CRITICAL: Very large collection batch - immediate action required",
			zap.Int("ip_pairs_in_batch", batchSize),
			zap.Int("critical_threshold", batchSizeCritThreshold),
			zap.String("action", "Scale Prometheus (16GB+ RAM) OR enable sampling/aggregation"),
			zap.String("note", "This is per-batch size, Prometheus cumulative cardinality will be much higher"))
	} else if batchSize > batchSizeWarnThreshold {
		c.logger.Warn("Large collection batch detected - monitor Prometheus resources",
			zap.Int("ip_pairs_in_batch", batchSize),
			zap.Int("warning_threshold", batchSizeWarnThreshold),
			zap.String("impact", "High per-batch load increases Prometheus memory usage"))
	} else if batchSize > batchSizeInfoThreshold {
		c.logger.Info("Collection batch size normal for large clusters",
			zap.Int("ip_pairs_in_batch", batchSize),
			zap.Int("info_threshold", batchSizeInfoThreshold))
	}

	// STEP 3: Export cumulative snapshots (netobserv pattern)
	// NOTE: We do NOT call Reset() - Gauges represent current cumulative state
	// Prometheus calculates rates using rate(metric[1m])
	for aggKey, totals := range aggregated {
		// Export cumulative traffic bytes (lifetime totals from BPF map)
		// Direction: egress = total bytes sent from source pod, ingress = total bytes received at destination pod
		c.connectionTrafficBytes.WithLabelValues(
			aggKey.SrcIP,
			aggKey.DstIP,
			aggKey.Protocol,
			"egress",
		).Set(float64(totals.BytesSent))

		c.connectionTrafficBytes.WithLabelValues(
			aggKey.SrcIP,
			aggKey.DstIP,
			aggKey.Protocol,
			"ingress",
		).Set(float64(totals.BytesReceived))

		// Export cumulative packet counts (no direction split to reduce cardinality)
		totalPackets := totals.PacketsSent + totals.PacketsReceived
		c.connectionTrafficPackets.WithLabelValues(
			aggKey.SrcIP,
			aggKey.DstIP,
			aggKey.Protocol,
		).Set(float64(totalPackets))
	}

	// Update active connection counts (internal tracking)
	for protocol, count := range protocolCounts {
		c.activeConnections.WithLabelValues(protocol).Set(float64(count))
	}

	// Update tracking info
	c.connectionTrackingInfo.WithLabelValues("total_connections_seen").Set(float64(c.totalConnectionsSeen))
	c.connectionTrackingInfo.WithLabelValues("active_connections").Set(float64(flowCount))
	c.connectionTrackingInfo.WithLabelValues("collection_duration_ms").Set(float64(time.Since(startTime).Milliseconds()))

	c.mu.Lock()
	c.activeConnectionCount = flowCount
	c.totalConnectionsSeen += uint64(flowCount)
	c.mu.Unlock()

	c.logger.Debug("Connection collection completed",
		zap.Int("connections_read", flowCount),
		zap.Int("connections_deleted", deletedCount),
		zap.Duration("duration", time.Since(startTime)))
}

// updateMapUtilization calculates and reports BPF map utilization
// Note: This is for monitoring only - overflow ringbuffer handles capacity management when map is full
func (c *ConnectionCollector) updateMapUtilization() {
	connectionMap := c.bpfManager.GetConnectionMap()
	if connectionMap == nil {
		return
	}

	// Get map info to find max entries
	info, err := connectionMap.Info()
	if err != nil {
		c.logger.Debug("Failed to get map info", zap.Error(err))
		return
	}

	// Count current entries
	currentEntries := 0
	iter := connectionMap.Iterate()
	var key bpf.ConnectionKey
	var stats bpf.ConnectionStats

	for iter.Next(&key, &stats) {
		currentEntries++
	}

	// Calculate utilization percentage
	maxEntries := info.MaxEntries
	if maxEntries > 0 {
		utilization := float64(currentEntries) / float64(maxEntries) * 100.0
		c.mapUtilization.WithLabelValues("connection_flows").Set(utilization)

		c.logger.Debug("BPF map utilization (overflow ringbuffer handles capacity)",
			zap.Uint32("current_entries", uint32(currentEntries)),
			zap.Uint32("max_entries", maxEntries),
			zap.Float64("utilization_percent", utilization))
	}
}

// GetStats returns collector statistics
func (c *ConnectionCollector) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"active_connections":     c.activeConnectionCount,
		"total_connections_seen": c.totalConnectionsSeen,
	}
}

// SetAggregationInterval updates the aggregation interval
func (c *ConnectionCollector) SetAggregationInterval(interval time.Duration) {
	c.aggregationInterval = interval
}

// StartOverflowHandler starts the overflow ringbuffer handler
// This reads overflow flow records and updates metrics
func (c *ConnectionCollector) StartOverflowHandler(ctx context.Context) error {
	c.logger.Info("Starting overflow handler")

	// Define handler for flow records
	handler := func(record *bpf.FlowRecord) {
		// Increment overflow counter
		c.overflowFlowsTotal.Inc()

		// Extract IPs from connection key
		srcIP, dstIP := ConnectionKeyToIPs(&record.Key)

		// Log overflow events at debug level (high volume)
		c.logger.Debug("Connection map overflow",
			zap.String("src_ip", srcIP),
			zap.String("dst_ip", dstIP),
			zap.Uint16("src_port", record.Key.SrcPort),
			zap.Uint16("dst_port", record.Key.DstPort),
			zap.Uint8("protocol", record.Key.Protocol),
			zap.Uint8("reason", record.Reason),
			zap.Uint64("bytes_sent", record.Stats.BytesSent),
			zap.Uint64("bytes_received", record.Stats.BytesReceived))

		// NOTE: We don't export overflow flows as high-cardinality metrics
		// Service-level aggregation handles the metrics export
		// This handler only tracks overflow count for monitoring
	}

	// Start ringbuffer reader in goroutine
	go func() {
		if err := c.bpfManager.StartRingbufReader(ctx, handler); err != nil {
			c.logger.Error("Overflow ringbuffer reader error", zap.Error(err))
		}
	}()

	c.logger.Info("Overflow handler started successfully")
	return nil
}

// Helper functions

// uint32ToIPString converts a uint32 to an IP string
// BPF MAP BYTE ORDER FIX:
// - BPF stores IPv4 addresses in network byte order (big endian) in kernel structures
// - cilium/ebpf reads the BPF map and converts to Go's native types using host byte order
// - On little-endian machines (x86/ARM), this means the bytes are already reversed
// - We must use LittleEndian to correctly interpret the host-order uint32 back to IP bytes
func uint32ToIPString(ip uint32) string {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, ip) // ✅ Host byte order (little-endian on x86/ARM)
	return net.IP(bytes).String()
}

// IPv6ToIPString converts IPv6 address from 4 uint32s to string
// BPF MAP BYTE ORDER FIX:
// - BPF reads IPv6 addresses using bpf_probe_read_kernel from kernel structures (network order)
// - The raw bytes are stored in the BPF map in network byte order (big endian)
// - cilium/ebpf reads each uint32 and interprets using host byte order (little-endian on x86/ARM)
// - We must use LittleEndian to convert each uint32 back to bytes in correct order
// - This works for both IPv4-mapped IPv6 (::ffff:x.x.x.x) and native IPv6 addresses
func IPv6ToIPString(ipv6 [4]uint32) string {
	// Create 16-byte array for IPv6
	bytes := make([]byte, 16)

	// Convert each uint32 to bytes using LittleEndian (host byte order)
	// This correctly handles both IPv4-mapped and native IPv6 addresses
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(bytes[i*4:], ipv6[i]) // ✅ Host byte order
	}

	return net.IP(bytes).String()
}

// ConnectionKeyToIPs extracts IP addresses from connection key based on family
func ConnectionKeyToIPs(key *bpf.ConnectionKey) (srcIP, dstIP string) {
	const (
		AF_INET  = 2
		AF_INET6 = 10
	)

	switch key.Family {
	case AF_INET:
		// IPv4 connection - only first 32 bits are used
		srcIP = uint32ToIPString(key.SrcAddr[0])
		dstIP = uint32ToIPString(key.DstAddr[0])
	case AF_INET6:
		// IPv6 connection - all 128 bits are used
		srcIP = IPv6ToIPString(key.SrcAddr)
		dstIP = IPv6ToIPString(key.DstAddr)
	default:
		// Unknown family, try to detect based on non-zero values
		if key.SrcAddr[1] != 0 || key.SrcAddr[2] != 0 || key.SrcAddr[3] != 0 ||
			key.DstAddr[1] != 0 || key.DstAddr[2] != 0 || key.DstAddr[3] != 0 {
			// Has data beyond first 32 bits, likely IPv6
			srcIP = IPv6ToIPString(key.SrcAddr)
			dstIP = IPv6ToIPString(key.DstAddr)
		} else if key.SrcAddr[0] != 0 || key.DstAddr[0] != 0 {
			// Only first 32 bits have data, likely IPv4
			srcIP = uint32ToIPString(key.SrcAddr[0])
			dstIP = uint32ToIPString(key.DstAddr[0])
		} else {
			// All zeros - unknown connection
			srcIP = "0.0.0.0"
			dstIP = "0.0.0.0"
		}
	}

	return srcIP, dstIP
}
