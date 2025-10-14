package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/kubeadapt/ebpf-agent/internal/bpf"
	"github.com/kubeadapt/ebpf-agent/internal/k8s"
	"github.com/kubeadapt/ebpf-agent/internal/network"
)

// ConnectionCollector collects connection-level network metrics
type ConnectionCollector struct {
	bpfManager   *bpf.Manager
	zoneMapper   *k8s.ZoneMapper
	ipClassifier *network.IPClassifier
	logger       *zap.Logger

	// Metrics
	connectionFlowBytes    *prometheus.CounterVec
	zoneTrafficBytes       *prometheus.CounterVec
	trafficCostEstimate    *prometheus.GaugeVec
	activeConnections      *prometheus.GaugeVec
	connectionTrackingInfo *prometheus.GaugeVec

	// Configuration
	aggregationInterval time.Duration
	cleanupInterval     time.Duration
	topFlowsLimit       int
	staleThreshold      time.Duration

	// State tracking
	mu                    sync.RWMutex
	lastCleanup           time.Time
	totalConnectionsSeen  uint64
	activeConnectionCount int
}

// NewConnectionCollector creates a new connection collector
func NewConnectionCollector(
	bpfManager *bpf.Manager,
	zoneMapper *k8s.ZoneMapper,
	logger *zap.Logger,
	registry *prometheus.Registry,
) *ConnectionCollector {
	c := &ConnectionCollector{
		bpfManager:          bpfManager,
		zoneMapper:          zoneMapper,
		ipClassifier:        network.NewIPClassifier(),
		logger:              logger,
		aggregationInterval: 30 * time.Second,
		cleanupInterval:     5 * time.Minute,
		topFlowsLimit:       1000,
		staleThreshold:      5 * time.Minute,
		lastCleanup:         time.Now(),
	}

	// Initialize metrics
	c.initMetrics(registry)

	return c
}

// initMetrics initializes Prometheus metrics
func (c *ConnectionCollector) initMetrics(registry *prometheus.Registry) {
	// Detailed connection flow metrics (high cardinality)
	c.connectionFlowBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubeadapt_connection_flow_bytes_total",
			Help: "Total bytes transferred between specific IPs",
		},
		[]string{
			"src_ip", "dst_ip",
			"src_zone", "dst_zone",
			"src_region", "dst_region",
			"src_pod", "dst_pod",
			"src_namespace", "dst_namespace",
			"protocol",
			"traffic_type",
			"direction", // egress or ingress
			"family",    // ipv4 or ipv6
		},
	)

	// Zone-level aggregated metrics (low cardinality)
	c.zoneTrafficBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubeadapt_zone_traffic_bytes_total",
			Help: "Total bytes transferred between zones (aggregated)",
		},
		[]string{
			"src_zone", "dst_zone",
			"src_region", "dst_region",
			"traffic_type",
		},
	)

	// Traffic cost estimates
	c.trafficCostEstimate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeadapt_traffic_cost_estimate_dollars",
			Help: "Estimated traffic cost in dollars",
		},
		[]string{"traffic_type", "zone"},
	)

	// Active connections gauge
	c.activeConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeadapt_active_connections",
			Help: "Number of active network connections",
		},
		[]string{"traffic_type", "protocol"},
	)

	// Connection tracking info
	c.connectionTrackingInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeadapt_connection_tracking_info",
			Help: "Information about connection tracking",
		},
		[]string{"metric"},
	)

	// Register metrics
	registry.MustRegister(c.connectionFlowBytes)
	registry.MustRegister(c.zoneTrafficBytes)
	registry.MustRegister(c.trafficCostEstimate)
	registry.MustRegister(c.activeConnections)
	registry.MustRegister(c.connectionTrackingInfo)
}

// Start begins the collection loop
func (c *ConnectionCollector) Start(ctx context.Context) {
	c.logger.Info("Starting connection collector",
		zap.Duration("aggregation_interval", c.aggregationInterval),
		zap.Duration("cleanup_interval", c.cleanupInterval),
		zap.Int("top_flows_limit", c.topFlowsLimit))

	// Start collection loop
	collectionTicker := time.NewTicker(c.aggregationInterval)
	defer collectionTicker.Stop()

	// Start cleanup loop
	cleanupTicker := time.NewTicker(c.cleanupInterval)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Stopping connection collector")
			return
		case <-collectionTicker.C:
			c.collect()
		case <-cleanupTicker.C:
			c.cleanup()
		}
	}
}

// collect gathers connection data from BPF maps
func (c *ConnectionCollector) collect() {
	startTime := time.Now()

	connectionMap := c.bpfManager.GetConnectionMap()
	if connectionMap == nil {
		c.logger.Error("Connection map is nil")
		return
	}

	// Track aggregates for zone-level metrics
	zoneTraffic := make(map[string]*network.TrafficStats)
	trafficCosts := make(map[network.TrafficType]float64)
	protocolCounts := make(map[string]int)
	flowCount := 0
	errorCount := 0

	// Iterate over connection map
	iter := connectionMap.Iterate()
	var key bpf.ConnectionKey
	var stats bpf.ConnectionStats

	for iter.Next(&key, &stats) {
		// Limit detailed metrics to top flows
		if flowCount >= c.topFlowsLimit {
			// Still process for aggregates, but don't create detailed metrics
			c.processConnectionForAggregates(&key, &stats, zoneTraffic, trafficCosts, protocolCounts)
		} else {
			// Process with full metrics
			if err := c.processConnection(&key, &stats, zoneTraffic, trafficCosts, protocolCounts); err != nil {
				errorCount++
				c.logger.Debug("Error processing connection", zap.Error(err))
			}
		}

		flowCount++
	}

	if err := iter.Err(); err != nil {
		c.logger.Error("Error iterating connection map", zap.Error(err))
	}

	// Update zone-level aggregate metrics
	c.updateZoneAggregates(zoneTraffic)

	// Update cost estimates
	c.updateCostEstimates(trafficCosts)

	// Update active connection counts
	c.updateConnectionCounts(protocolCounts)

	// Update tracking info
	c.connectionTrackingInfo.WithLabelValues("total_connections_seen").Set(float64(c.totalConnectionsSeen))
	c.connectionTrackingInfo.WithLabelValues("active_connections").Set(float64(flowCount))
	c.connectionTrackingInfo.WithLabelValues("collection_errors").Set(float64(errorCount))
	c.connectionTrackingInfo.WithLabelValues("collection_duration_ms").Set(float64(time.Since(startTime).Milliseconds()))

	c.mu.Lock()
	c.activeConnectionCount = flowCount
	c.totalConnectionsSeen += uint64(flowCount)
	c.mu.Unlock()

	c.logger.Debug("Connection collection completed",
		zap.Int("flows", flowCount),
		zap.Int("errors", errorCount),
		zap.Duration("duration", time.Since(startTime)))
}

// processConnection processes a single connection with full metrics
func (c *ConnectionCollector) processConnection(
	key *bpf.ConnectionKey,
	stats *bpf.ConnectionStats,
	zoneTraffic map[string]*network.TrafficStats,
	trafficCosts map[network.TrafficType]float64,
	protocolCounts map[string]int,
) error {
	// Convert IPs based on address family
	srcIP, dstIP := ConnectionKeyToIPs(key)

	// Get zones and regions
	srcZone := c.zoneMapper.GetZoneForIP(srcIP)
	dstZone := c.zoneMapper.GetZoneForIP(dstIP)
	srcRegion := c.zoneMapper.GetRegionForIP(srcIP)
	dstRegion := c.zoneMapper.GetRegionForIP(dstIP)

	// Get pod and namespace info
	srcPod := c.zoneMapper.GetPodForIP(srcIP)
	dstPod := c.zoneMapper.GetPodForIP(dstIP)
	srcNamespace := c.zoneMapper.GetNamespaceForIP(srcIP)
	dstNamespace := c.zoneMapper.GetNamespaceForIP(dstIP)

	// Classify traffic
	trafficType := c.ipClassifier.ClassifyTrafficByStrings(srcIP, dstIP, srcZone, dstZone)

	// Protocol string
	protocol := protocolToString(key.Protocol)
	protocolCounts[protocol]++

	// Determine address family
	family := "ipv4"
	if key.Family == 10 { // AF_INET6
		family = "ipv6"
	}

	// Update detailed flow metrics (egress direction)
	if stats.BytesSent > 0 {
		c.connectionFlowBytes.WithLabelValues(
			srcIP, dstIP,
			srcZone, dstZone,
			srcRegion, dstRegion,
			srcPod, dstPod,
			srcNamespace, dstNamespace,
			protocol,
			string(trafficType),
			"egress",
			family,
		).Add(float64(stats.BytesSent))
	}

	// Update detailed flow metrics (ingress direction)
	if stats.BytesReceived > 0 {
		c.connectionFlowBytes.WithLabelValues(
			dstIP, srcIP, // Note: reversed for ingress
			dstZone, srcZone,
			dstRegion, srcRegion,
			dstPod, srcPod,
			dstNamespace, srcNamespace,
			protocol,
			string(trafficType),
			"ingress",
			family,
		).Add(float64(stats.BytesReceived))
	}

	// Update aggregates
	zoneKey := fmt.Sprintf("%s_%s_%s", srcZone, dstZone, trafficType)
	if zoneTraffic[zoneKey] == nil {
		zoneTraffic[zoneKey] = &network.TrafficStats{
			Type: trafficType,
		}
	}
	zoneTraffic[zoneKey].UpdateStats(stats.BytesSent, stats.BytesReceived)
	zoneTraffic[zoneKey].ConnectionCount++

	// Calculate costs
	cost := network.CalculateTrafficCost(trafficType, stats.BytesSent+stats.BytesReceived)
	trafficCosts[trafficType] += cost

	return nil
}

// processConnectionForAggregates processes a connection only for aggregate metrics
func (c *ConnectionCollector) processConnectionForAggregates(
	key *bpf.ConnectionKey,
	stats *bpf.ConnectionStats,
	zoneTraffic map[string]*network.TrafficStats,
	trafficCosts map[network.TrafficType]float64,
	protocolCounts map[string]int,
) {
	// Convert IPs based on address family
	srcIP, dstIP := ConnectionKeyToIPs(key)

	// Get zones
	srcZone := c.zoneMapper.GetZoneForIP(srcIP)
	dstZone := c.zoneMapper.GetZoneForIP(dstIP)

	// Classify traffic
	trafficType := c.ipClassifier.ClassifyTrafficByStrings(srcIP, dstIP, srcZone, dstZone)

	// Protocol
	protocol := protocolToString(key.Protocol)
	protocolCounts[protocol]++

	// Update aggregates only
	zoneKey := fmt.Sprintf("%s_%s_%s", srcZone, dstZone, trafficType)
	if zoneTraffic[zoneKey] == nil {
		zoneTraffic[zoneKey] = &network.TrafficStats{
			Type: trafficType,
		}
	}
	zoneTraffic[zoneKey].UpdateStats(stats.BytesSent, stats.BytesReceived)
	zoneTraffic[zoneKey].ConnectionCount++

	// Calculate costs
	cost := network.CalculateTrafficCost(trafficType, stats.BytesSent+stats.BytesReceived)
	trafficCosts[trafficType] += cost
}

// updateZoneAggregates updates zone-level aggregate metrics
func (c *ConnectionCollector) updateZoneAggregates(zoneTraffic map[string]*network.TrafficStats) {
	for _, stats := range zoneTraffic {
		// Parse zone key (hacky but simple)
		// Format: srcZone_dstZone_trafficType
		// This could be improved with a proper struct
		c.zoneTrafficBytes.WithLabelValues(
			"", "", // Will need to parse from key
			"", "",
			string(stats.Type),
		).Add(float64(stats.GetTotalBytes()))
	}
}

// updateCostEstimates updates traffic cost estimates
func (c *ConnectionCollector) updateCostEstimates(trafficCosts map[network.TrafficType]float64) {
	for trafficType, cost := range trafficCosts {
		c.trafficCostEstimate.WithLabelValues(string(trafficType), "all").Set(cost)
	}
}

// updateConnectionCounts updates active connection counts
func (c *ConnectionCollector) updateConnectionCounts(protocolCounts map[string]int) {
	for protocol, count := range protocolCounts {
		c.activeConnections.WithLabelValues("all", protocol).Set(float64(count))
	}
}

// cleanup removes stale connections from BPF maps
func (c *ConnectionCollector) cleanup() {
	startTime := time.Now()

	connectionMap := c.bpfManager.GetConnectionMap()
	if connectionMap == nil {
		return
	}

	threshold := time.Now().Add(-c.staleThreshold).UnixNano()
	cleaned := 0
	errors := 0

	// Iterate and clean stale entries
	iter := connectionMap.Iterate()
	var key bpf.ConnectionKey
	var stats bpf.ConnectionStats

	keysToDelete := make([]bpf.ConnectionKey, 0)

	for iter.Next(&key, &stats) {
		if int64(stats.LastSeenNs) < threshold {
			keysToDelete = append(keysToDelete, key)
		}
	}

	// Delete stale entries
	for _, k := range keysToDelete {
		if err := connectionMap.Delete(k); err != nil {
			errors++
			c.logger.Debug("Failed to delete stale connection", zap.Error(err))
		} else {
			cleaned++
		}
	}

	c.mu.Lock()
	c.lastCleanup = time.Now()
	c.mu.Unlock()

	c.connectionTrackingInfo.WithLabelValues("connections_cleaned").Set(float64(cleaned))
	c.connectionTrackingInfo.WithLabelValues("cleanup_errors").Set(float64(errors))
	c.connectionTrackingInfo.WithLabelValues("cleanup_duration_ms").Set(float64(time.Since(startTime).Milliseconds()))

	if cleaned > 0 {
		c.logger.Info("Cleaned stale connections",
			zap.Int("cleaned", cleaned),
			zap.Int("errors", errors),
			zap.Duration("duration", time.Since(startTime)))
	}
}

// GetStats returns collector statistics
func (c *ConnectionCollector) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"active_connections":     c.activeConnectionCount,
		"total_connections_seen": c.totalConnectionsSeen,
		"last_cleanup":           c.lastCleanup,
		"top_flows_limit":        c.topFlowsLimit,
	}
}

// SetTopFlowsLimit updates the limit for detailed flow metrics
func (c *ConnectionCollector) SetTopFlowsLimit(limit int) {
	c.topFlowsLimit = limit
}

// SetCleanupInterval updates the cleanup interval
func (c *ConnectionCollector) SetCleanupInterval(interval time.Duration) {
	c.cleanupInterval = interval
}

// SetAggregationInterval updates the aggregation interval
func (c *ConnectionCollector) SetAggregationInterval(interval time.Duration) {
	c.aggregationInterval = interval
}

// Helper functions

// uint32ToIPString converts a uint32 to an IP string
func uint32ToIPString(ip uint32) string {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, ip)
	return net.IP(bytes).String()
}

// IPv6ToIPString converts IPv6 address from 4 uint32s to string
func IPv6ToIPString(ipv6 [4]uint32) string {
	// Create 16-byte array for IPv6
	bytes := make([]byte, 16)

	// Convert each uint32 to bytes (network byte order)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(bytes[i*4:], ipv6[i])
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

// protocolToString converts protocol number to string
func protocolToString(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("unknown(%d)", protocol)
	}
}
