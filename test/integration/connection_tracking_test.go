//go:build integration
// +build integration

package integration

import (
	"context"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/kubeadapt/ebpf-agent/internal/bpf"
	"github.com/kubeadapt/ebpf-agent/internal/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestConnectionTracking tests the full connection tracking pipeline
func TestConnectionTracking(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	logger := zaptest.NewLogger(t)

	// Create BPF manager
	manager, err := bpf.NewManager(logger)
	require.NoError(t, err)
	defer manager.Close()

	// Load and attach BPF programs (use "disabled" mode for tests to track all traffic)
	err = manager.LoadAndAttach("disabled")
	require.NoError(t, err)

	// Create metrics registry
	registry := prometheus.NewRegistry()

	// Create connection collector
	connectionCollector := collector.NewConnectionCollector(
		manager,
		logger,
		registry,
	)

	// Start collector in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go connectionCollector.Start(ctx)

	// Generate test network traffic
	t.Log("Generating test network traffic...")
	generateTestTraffic(t)

	// Wait for BPF to capture and collector to process
	time.Sleep(2 * time.Second)

	// Check connection map
	connMap := manager.GetConnectionMap()
	require.NotNil(t, connMap)

	// Verify we captured connections
	iter := connMap.Iterate()
	var key bpf.ConnectionKey
	var stats bpf.ConnectionStats

	connectionCount := 0
	totalBytesSent := uint64(0)
	totalBytesReceived := uint64(0)

	for iter.Next(&key, &stats) {
		connectionCount++
		totalBytesSent += stats.BytesSent
		totalBytesReceived += stats.BytesReceived

		// Log connection details
		srcIP := bpf.Uint32ToIPString(key.SrcIP)
		dstIP := bpf.Uint32ToIPString(key.DstIP)
		protocol := protocolToString(key.Protocol)

		t.Logf("Connection: %s:%d -> %s:%d (%s) - Sent: %d bytes, Received: %d bytes",
			srcIP, key.SrcPort, dstIP, key.DstPort, protocol,
			stats.BytesSent, stats.BytesReceived)
	}

	require.NoError(t, iter.Err())
	assert.Greater(t, connectionCount, 0, "Should have captured at least one connection")
	assert.Greater(t, totalBytesSent+totalBytesReceived, uint64(0), "Should have captured some traffic")

	// Check metrics
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	// Verify connection tracking metrics exist
	expectedMetrics := []string{
		"kubeadapt_connection_flow_bytes_total",
		"kubeadapt_traffic_cost_estimate_dollars",
		"kubeadapt_active_connections",
		"kubeadapt_connection_tracking_info",
	}

	foundMetrics := make(map[string]bool)
	for _, mf := range metricFamilies {
		foundMetrics[*mf.Name] = true
		t.Logf("Found metric: %s", *mf.Name)
	}

	for _, expected := range expectedMetrics {
		assert.True(t, foundMetrics[expected], "Expected metric %s not found", expected)
	}

	// Check collector stats
	collectorStats := connectionCollector.GetStats()
	assert.NotNil(t, collectorStats)
	t.Logf("Collector stats: %+v", collectorStats)
}

// TestConnectionCleanup tests the cleanup of stale connections
func TestConnectionCleanup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	logger := zaptest.NewLogger(t)

	// Create BPF manager
	manager, err := bpf.NewManager(logger)
	require.NoError(t, err)
	defer manager.Close()

	// Load BPF programs (use "disabled" mode for tests)
	err = manager.LoadAndAttach("disabled")
	require.NoError(t, err)

	// Create connection collector with short cleanup interval
	registry := prometheus.NewRegistry()
	connectionCollector := collector.NewConnectionCollector(
		manager,
		logger,
		registry,
	)

	// Set very short cleanup interval for testing
	connectionCollector.SetCleanupInterval(1 * time.Second)

	// Manually add a connection to the map
	connMap := manager.GetConnectionMap()
	require.NotNil(t, connMap)

	// Create a stale connection entry
	staleKey := bpf.ConnectionKey{
		SrcIP:    ipToUint32("10.0.0.1"),
		DstIP:    ipToUint32("10.0.0.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6, // TCP
	}

	staleStats := bpf.ConnectionStats{
		BytesSent:  1000,
		LastSeenNs: uint64(time.Now().Add(-10 * time.Minute).UnixNano()), // Very old
	}

	err = connMap.Update(&staleKey, &staleStats, ebpf.UpdateAny)
	require.NoError(t, err)

	// Start collector
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	go connectionCollector.Start(ctx)

	// Wait for cleanup to run
	time.Sleep(2 * time.Second)

	// Check if stale entry was removed
	var checkStats bpf.ConnectionStats
	err = connMap.Lookup(&staleKey, &checkStats)
	// Should get an error because the key doesn't exist
	assert.Error(t, err, "Stale connection should have been cleaned up")
}

// TestHighVolumeConnections tests handling of many connections
func TestHighVolumeConnections(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	logger := zaptest.NewLogger(t)

	// Create BPF manager
	manager, err := bpf.NewManager(logger)
	require.NoError(t, err)
	defer manager.Close()

	// Load BPF programs (use "disabled" mode for tests)
	err = manager.LoadAndAttach("disabled")
	require.NoError(t, err)

	// Generate many connections
	t.Log("Generating high volume traffic...")
	for i := 0; i < 100; i++ {
		go func() {
			conn, err := net.Dial("tcp", "google.com:80")
			if err == nil {
				conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
				conn.Close()
			}
		}()
	}

	// Wait for connections to be tracked
	time.Sleep(2 * time.Second)

	// Check connection map
	connMap := manager.GetConnectionMap()
	require.NotNil(t, connMap)

	// Count connections
	iter := connMap.Iterate()
	var key bpf.ConnectionKey
	var stats bpf.ConnectionStats

	connectionCount := 0
	for iter.Next(&key, &stats) {
		connectionCount++
	}

	t.Logf("Tracked %d connections", connectionCount)
	assert.Greater(t, connectionCount, 0, "Should have tracked multiple connections")
}

// Helper functions

func generateTestTraffic(t *testing.T) {
	// HTTP request to generate TCP traffic
	client := &http.Client{
		Timeout: 2 * time.Second,
	}

	// Try multiple endpoints
	endpoints := []string{
		"http://google.com",
		"http://cloudflare.com",
		"http://example.com",
	}

	for _, endpoint := range endpoints {
		resp, err := client.Get(endpoint)
		if err != nil {
			t.Logf("Failed to connect to %s: %v", endpoint, err)
			continue
		}
		resp.Body.Close()
		t.Logf("Generated traffic to %s", endpoint)
	}

	// UDP traffic (DNS)
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err == nil {
		// Simple DNS query
		conn.Write([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00})
		conn.Close()
		t.Log("Generated UDP traffic (DNS)")
	}

	// Local TCP connection
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		go func() {
			conn, _ := listener.Accept()
			if conn != nil {
				conn.Close()
			}
		}()

		conn, err := net.Dial("tcp", listener.Addr().String())
		if err == nil {
			conn.Write([]byte("test"))
			conn.Close()
		}
		listener.Close()
		t.Log("Generated local TCP traffic")
	}
}

func ipToUint32(ip string) uint32 {
	netIP := net.ParseIP(ip).To4()
	if netIP == nil {
		return 0
	}
	return uint32(netIP[0])<<24 | uint32(netIP[1])<<16 | uint32(netIP[2])<<8 | uint32(netIP[3])
}

func protocolToString(protocol uint8) string {
	switch protocol {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "Unknown"
	}
}
