package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kubeadapt/ebpf-agent/internal/bpf"
	"github.com/kubeadapt/ebpf-agent/internal/container"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// Collector collects metrics from BPF maps and updates Prometheus metrics
type Collector struct {
	bpfManager      *bpf.Manager
	containerCache  *container.Cache
	metricsRegistry *prometheus.Registry
	logger          *zap.Logger

	// Options
	collectionInterval time.Duration
	batchSize          int

	// Metrics
	rxBytesCounter     *prometheus.CounterVec
	txBytesCounter     *prometheus.CounterVec
	rxPacketsCounter   *prometheus.CounterVec
	txPacketsCounter   *prometheus.CounterVec

	// Internal metrics
	collectionsTotal   prometheus.Counter
	collectionDuration prometheus.Histogram
	mapEntriesGauge    prometheus.Gauge
	containersTracked  prometheus.Gauge
	errorsTotal        prometheus.Counter

	// State
	lastCollectionTime time.Time
	lastValues         map[uint64]*bpf.ContainerNetStats
	mu                 sync.RWMutex
}

// Options contains collector configuration
type Options struct {
	CollectionInterval time.Duration
	BatchSize          int
}

// New creates a new metrics collector
func New(
	bpfManager *bpf.Manager,
	containerCache *container.Cache,
	registry *prometheus.Registry,
	opts Options,
	logger *zap.Logger,
) *Collector {
	if logger == nil {
		logger = zap.NewNop()
	}

	if opts.CollectionInterval == 0 {
		opts.CollectionInterval = 10 * time.Second
	}
	if opts.BatchSize == 0 {
		opts.BatchSize = 100
	}

	c := &Collector{
		bpfManager:         bpfManager,
		containerCache:     containerCache,
		metricsRegistry:    registry,
		logger:             logger,
		collectionInterval: opts.CollectionInterval,
		batchSize:          opts.BatchSize,
		lastValues:         make(map[uint64]*bpf.ContainerNetStats),
	}

	// Initialize Prometheus metrics
	c.initMetrics(registry)

	return c
}

// initMetrics initializes Prometheus metrics
func (c *Collector) initMetrics(registry *prometheus.Registry) {
	// Container network metrics
	c.rxBytesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubeadapt_container_network_receive_bytes_total",
			Help: "Total bytes received by container",
		},
		[]string{"container_id", "container_name", "pod_name", "namespace", "node"},
	)

	c.txBytesCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubeadapt_container_network_transmit_bytes_total",
			Help: "Total bytes transmitted by container",
		},
		[]string{"container_id", "container_name", "pod_name", "namespace", "node"},
	)

	c.rxPacketsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubeadapt_container_network_receive_packets_total",
			Help: "Total packets received by container",
		},
		[]string{"container_id", "container_name", "pod_name", "namespace", "node"},
	)

	c.txPacketsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubeadapt_container_network_transmit_packets_total",
			Help: "Total packets transmitted by container",
		},
		[]string{"container_id", "container_name", "pod_name", "namespace", "node"},
	)

	// Internal metrics
	c.collectionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubeadapt_ebpf_agent_collections_total",
			Help: "Total number of metric collections",
		},
	)

	c.collectionDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "kubeadapt_ebpf_agent_collection_duration_seconds",
			Help:    "Duration of metric collection in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	c.mapEntriesGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "kubeadapt_ebpf_agent_bpf_map_entries",
			Help: "Current number of entries in BPF maps",
		},
	)

	c.containersTracked = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "kubeadapt_ebpf_agent_containers_tracked",
			Help: "Number of containers being tracked",
		},
	)

	c.errorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubeadapt_ebpf_agent_errors_total",
			Help: "Total number of collection errors",
		},
	)

	// Register all metrics
	registry.MustRegister(
		c.rxBytesCounter,
		c.txBytesCounter,
		c.rxPacketsCounter,
		c.txPacketsCounter,
		c.collectionsTotal,
		c.collectionDuration,
		c.mapEntriesGauge,
		c.containersTracked,
		c.errorsTotal,
	)
}

// Start begins the collection loop
func (c *Collector) Start(ctx context.Context) {
	c.logger.Info("Starting metrics collector",
		zap.Duration("interval", c.collectionInterval),
		zap.Int("batch_size", c.batchSize),
	)

	ticker := time.NewTicker(c.collectionInterval)
	defer ticker.Stop()

	// Initial collection
	c.collect()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Stopping metrics collector")
			return
		case <-ticker.C:
			c.collect()
		}
	}
}

// collect performs a single collection cycle
func (c *Collector) collect() {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		c.collectionDuration.Observe(duration)
		c.collectionsTotal.Inc()
		c.lastCollectionTime = time.Now()

		c.logger.Debug("Collection completed",
			zap.Duration("duration", time.Since(start)),
		)
	}()

	// Collect from main stats map
	if err := c.collectFromMap(c.bpfManager.GetContainerStats(), false); err != nil {
		c.logger.Error("Error collecting from main map", zap.Error(err))
		c.errorsTotal.Inc()
	}

	// Collect from per-CPU stats map and aggregate
	if err := c.collectFromMap(c.bpfManager.GetContainerStatsPerCPU(), true); err != nil {
		c.logger.Error("Error collecting from per-CPU map", zap.Error(err))
		c.errorsTotal.Inc()
	}

	// Update internal metrics
	cacheStats := c.containerCache.Stats()
	c.containersTracked.Set(float64(cacheStats.TotalContainers))
}

// collectFromMap collects metrics from a specific BPF map
func (c *Collector) collectFromMap(bpfMap *ebpf.Map, isPerCPU bool) error {
	if bpfMap == nil {
		return fmt.Errorf("BPF map is nil")
	}

	mapEntries := 0
	iter := bpfMap.Iterate()
	var cgroupID uint64

	if isPerCPU {
		// Per-CPU map returns array of values
		var values []bpf.ContainerNetStats
		for iter.Next(&cgroupID, &values) {
			if err := c.processStats(cgroupID, aggregatePerCPUStats(values)); err != nil {
				c.logger.Warn("Error processing per-CPU stats",
					zap.Uint64("cgroup_id", cgroupID),
					zap.Error(err),
				)
			}
			mapEntries++
		}
	} else {
		// Regular map returns single value
		var stats bpf.ContainerNetStats
		for iter.Next(&cgroupID, &stats) {
			if err := c.processStats(cgroupID, &stats); err != nil {
				c.logger.Warn("Error processing stats",
					zap.Uint64("cgroup_id", cgroupID),
					zap.Error(err),
				)
			}
			mapEntries++
		}
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterating BPF map: %w", err)
	}

	c.mapEntriesGauge.Set(float64(mapEntries))

	c.logger.Debug("Collected from BPF map",
		zap.Bool("per_cpu", isPerCPU),
		zap.Int("entries", mapEntries),
	)

	return nil
}

// processStats processes stats for a single container
func (c *Collector) processStats(cgroupID uint64, stats *bpf.ContainerNetStats) error {
	// Skip if no data
	if stats.RxBytes == 0 && stats.TxBytes == 0 {
		return nil
	}

	// Look up container info
	containerInfo, found := c.containerCache.GetByCgroup(cgroupID)
	if !found {
		// Container not found in cache - might be a system process
		c.logger.Debug("Container not found for cgroup",
			zap.Uint64("cgroup_id", cgroupID),
			zap.Uint64("rx_bytes", stats.RxBytes),
			zap.Uint64("tx_bytes", stats.TxBytes),
		)
		return nil
	}

	// Get labels for Prometheus
	labels := prometheus.Labels{
		"container_id":   containerInfo.ContainerID,
		"container_name": containerInfo.ContainerName,
		"pod_name":       containerInfo.PodName,
		"namespace":      containerInfo.Namespace,
		"node":           containerInfo.NodeName,
	}

	// Handle counter resets and calculate deltas
	c.mu.Lock()
	lastStats, hasLast := c.lastValues[cgroupID]
	c.lastValues[cgroupID] = stats
	c.mu.Unlock()

	if hasLast {
		// Calculate deltas (handle counter resets)
		rxDelta := stats.RxBytes
		txDelta := stats.TxBytes
		rxPacketsDelta := stats.RxPackets
		txPacketsDelta := stats.TxPackets

		if stats.RxBytes >= lastStats.RxBytes {
			rxDelta = stats.RxBytes - lastStats.RxBytes
		}
		if stats.TxBytes >= lastStats.TxBytes {
			txDelta = stats.TxBytes - lastStats.TxBytes
		}
		if stats.RxPackets >= lastStats.RxPackets {
			rxPacketsDelta = stats.RxPackets - lastStats.RxPackets
		}
		if stats.TxPackets >= lastStats.TxPackets {
			txPacketsDelta = stats.TxPackets - lastStats.TxPackets
		}

		// Update Prometheus counters with deltas
		if rxDelta > 0 {
			c.rxBytesCounter.With(labels).Add(float64(rxDelta))
		}
		if txDelta > 0 {
			c.txBytesCounter.With(labels).Add(float64(txDelta))
		}
		if rxPacketsDelta > 0 {
			c.rxPacketsCounter.With(labels).Add(float64(rxPacketsDelta))
		}
		if txPacketsDelta > 0 {
			c.txPacketsCounter.With(labels).Add(float64(txPacketsDelta))
		}

		c.logger.Debug("Updated container metrics",
			zap.String("container", containerInfo.ContainerName),
			zap.Uint64("rx_delta", rxDelta),
			zap.Uint64("tx_delta", txDelta),
		)
	} else {
		// First observation - initialize counters
		c.rxBytesCounter.With(labels).Add(float64(stats.RxBytes))
		c.txBytesCounter.With(labels).Add(float64(stats.TxBytes))
		c.rxPacketsCounter.With(labels).Add(float64(stats.RxPackets))
		c.txPacketsCounter.With(labels).Add(float64(stats.TxPackets))
	}

	return nil
}

// aggregatePerCPUStats aggregates per-CPU statistics
func aggregatePerCPUStats(perCPU []bpf.ContainerNetStats) *bpf.ContainerNetStats {
	var aggregate bpf.ContainerNetStats

	for _, stats := range perCPU {
		aggregate.RxBytes += stats.RxBytes
		aggregate.TxBytes += stats.TxBytes
		aggregate.RxPackets += stats.RxPackets
		aggregate.TxPackets += stats.TxPackets

		// Keep the most recent last seen time
		if stats.LastSeenNs > aggregate.LastSeenNs {
			aggregate.LastSeenNs = stats.LastSeenNs
		}
	}

	return &aggregate
}

// GetStats returns collector statistics
func (c *Collector) GetStats() CollectorStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CollectorStats{
		LastCollection: c.lastCollectionTime,
		TrackedCgroups: len(c.lastValues),
		CacheStats:     c.containerCache.Stats(),
	}
}

// CollectorStats represents collector statistics
type CollectorStats struct {
	LastCollection time.Time
	TrackedCgroups int
	CacheStats     container.CacheStats
}

// CleanupStaleEntries removes stale entries from tracking
func (c *Collector) CleanupStaleEntries(maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UnixNano()
	maxAgeNs := uint64(maxAge.Nanoseconds())

	removed := 0
	for cgroupID, stats := range c.lastValues {
		if stats.LastSeenNs > 0 && (uint64(now)-stats.LastSeenNs) > maxAgeNs {
			delete(c.lastValues, cgroupID)
			removed++
		}
	}

	if removed > 0 {
		c.logger.Info("Cleaned up stale entries",
			zap.Int("removed", removed),
			zap.Int("remaining", len(c.lastValues)),
		)
	}
}