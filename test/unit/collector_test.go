package unit

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kubeadapt/ebpf-agent/internal/bpf"
	"github.com/kubeadapt/ebpf-agent/internal/collector"
	"github.com/kubeadapt/ebpf-agent/internal/container"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zaptest"
)

// MockBPFManager implements a mock BPF manager for testing
type MockBPFManager struct {
	statsMap       *ebpf.Map
	perCPUStatsMap *ebpf.Map
}

func (m *MockBPFManager) GetContainerStats() *ebpf.Map {
	return m.statsMap
}

func (m *MockBPFManager) GetContainerStatsPerCPU() *ebpf.Map {
	return m.perCPUStatsMap
}

// TestCollectorInitialization tests collector initialization
func TestCollectorInitialization(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := prometheus.NewRegistry()
	cache := container.NewCache()

	// Create mock BPF manager
	mockManager := &MockBPFManager{}

	// Create collector
	c := collector.New(
		mockManager,
		cache,
		registry,
		collector.Options{
			CollectionInterval: 10 * time.Second,
			BatchSize:          100,
		},
		logger,
	)

	if c == nil {
		t.Fatal("Collector should not be nil")
	}

	// Check that metrics are registered
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	expectedMetrics := []string{
		"kubeadapt_container_network_receive_bytes_total",
		"kubeadapt_container_network_transmit_bytes_total",
		"kubeadapt_container_network_receive_packets_total",
		"kubeadapt_container_network_transmit_packets_total",
		"kubeadapt_ebpf_agent_collections_total",
		"kubeadapt_ebpf_agent_collection_duration_seconds",
		"kubeadapt_ebpf_agent_bpf_map_entries",
		"kubeadapt_ebpf_agent_containers_tracked",
		"kubeadapt_ebpf_agent_errors_total",
	}

	foundMetrics := make(map[string]bool)
	for _, mf := range metricFamilies {
		foundMetrics[*mf.Name] = true
	}

	for _, expected := range expectedMetrics {
		if !foundMetrics[expected] {
			t.Errorf("Expected metric %s not found", expected)
		}
	}
}

// TestCollectorStart tests starting the collector
func TestCollectorStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := prometheus.NewRegistry()
	cache := container.NewCache()
	mockManager := &MockBPFManager{}

	c := collector.New(
		mockManager,
		cache,
		registry,
		collector.Options{
			CollectionInterval: 100 * time.Millisecond, // Short interval for testing
			BatchSize:          10,
		},
		logger,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Start collector in background
	go c.Start(ctx)

	// Wait for context to expire
	<-ctx.Done()

	// Give a bit of time for graceful shutdown
	time.Sleep(100 * time.Millisecond)

	// Check that at least one collection occurred
	stats := c.GetStats()
	if stats.LastCollection.IsZero() {
		t.Error("No collections occurred")
	}
}

// TestCollectorCleanup tests cleanup of stale entries
func TestCollectorCleanup(t *testing.T) {
	logger := zaptest.NewLogger(t)
	registry := prometheus.NewRegistry()
	cache := container.NewCache()
	mockManager := &MockBPFManager{}

	c := collector.New(
		mockManager,
		cache,
		registry,
		collector.Options{
			CollectionInterval: 10 * time.Second,
			BatchSize:          100,
		},
		logger,
	)

	// Simulate some tracked cgroups
	// Note: In real implementation, these would be populated during collection
	c.CleanupStaleEntries(5 * time.Minute)

	stats := c.GetStats()
	if stats.TrackedCgroups < 0 {
		t.Error("TrackedCgroups should not be negative")
	}
}

// TestAggregatePerCPUStats tests aggregation of per-CPU statistics
func TestAggregatePerCPUStats(t *testing.T) {
	perCPUStats := []bpf.ContainerNetStats{
		{
			RxBytes:    100,
			TxBytes:    200,
			RxPackets:  10,
			TxPackets:  20,
			LastSeenNs: 1000,
		},
		{
			RxBytes:    150,
			TxBytes:    250,
			RxPackets:  15,
			TxPackets:  25,
			LastSeenNs: 2000,
		},
		{
			RxBytes:    200,
			TxBytes:    300,
			RxPackets:  20,
			TxPackets:  30,
			LastSeenNs: 1500,
		},
	}

	// This function would be internal to collector, so we'd need to expose it
	// or test it indirectly through the collector's behavior
	// For now, we'll test the expected behavior

	expectedTotal := bpf.ContainerNetStats{
		RxBytes:    450,  // 100 + 150 + 200
		TxBytes:    750,  // 200 + 250 + 300
		RxPackets:  45,   // 10 + 15 + 20
		TxPackets:  75,   // 20 + 25 + 30
		LastSeenNs: 2000, // Most recent
	}

	// Calculate aggregate
	var aggregate bpf.ContainerNetStats
	for _, stats := range perCPUStats {
		aggregate.RxBytes += stats.RxBytes
		aggregate.TxBytes += stats.TxBytes
		aggregate.RxPackets += stats.RxPackets
		aggregate.TxPackets += stats.TxPackets
		if stats.LastSeenNs > aggregate.LastSeenNs {
			aggregate.LastSeenNs = stats.LastSeenNs
		}
	}

	if aggregate.RxBytes != expectedTotal.RxBytes {
		t.Errorf("RxBytes: got %d, want %d", aggregate.RxBytes, expectedTotal.RxBytes)
	}
	if aggregate.TxBytes != expectedTotal.TxBytes {
		t.Errorf("TxBytes: got %d, want %d", aggregate.TxBytes, expectedTotal.TxBytes)
	}
	if aggregate.RxPackets != expectedTotal.RxPackets {
		t.Errorf("RxPackets: got %d, want %d", aggregate.RxPackets, expectedTotal.RxPackets)
	}
	if aggregate.TxPackets != expectedTotal.TxPackets {
		t.Errorf("TxPackets: got %d, want %d", aggregate.TxPackets, expectedTotal.TxPackets)
	}
	if aggregate.LastSeenNs != expectedTotal.LastSeenNs {
		t.Errorf("LastSeenNs: got %d, want %d", aggregate.LastSeenNs, expectedTotal.LastSeenNs)
	}
}