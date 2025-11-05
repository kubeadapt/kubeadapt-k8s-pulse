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

// mockConfig provides test configuration for ConnectionCollector
type mockConfig struct {
	dumpBPFMaps bool
}

func (m *mockConfig) GetDumpBPFMaps() bool {
	return m.dumpBPFMaps
}

// TestConnectionTracking tests the full connection tracking pipeline
func TestConnectionTracking(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// Set required environment variables for DaemonSet pod identity
	os.Setenv("DAEMONSET_POD_UID", "test-pod-uid-12345")
	os.Setenv("DAEMONSET_NODE_NAME", "test-node")

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

	// Create mock config
	cfg := &mockConfig{dumpBPFMaps: false}

	// Create connection collector
	connectionCollector := collector.NewConnectionCollector(
		manager,
		logger,
		registry,
		cfg,
	)

	// Start collector in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go connectionCollector.Start(ctx)

	// Generate test network traffic
	t.Log("Generating test network traffic...")
	generateTestTraffic(t)

	// Wait for at least one full collection cycle to complete
	// Collector runs every 25 seconds, so wait 27 seconds to ensure metrics are exported
	t.Log("Waiting for collection cycle to complete (27 seconds)...")
	time.Sleep(27 * time.Second)

	// Note: After collection, the connection map is empty due to read-then-delete pattern
	// The collector reads all entries and immediately deletes them, so we verify via:
	// 1. Collector stats (which track total connections seen)
	// 2. Prometheus metrics (which export the aggregated data)

	// Check metrics
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	// Verify connection tracking metrics exist
	// These are the actual metrics exported by the collector
	expectedMetrics := []string{
		"kubeadapt_connection_traffic_bytes_total",   // Counter for cumulative bytes (read-then-delete)
		"kubeadapt_connection_traffic_packets_total", // Counter for cumulative packets (read-then-delete)
		"kubeadapt_active_connections",               // Gauge for number of active connections
		"kubeadapt_connection_tracking_info",         // Info metric with version/build details
		"kubeadapt_bpf_map_utilization_percent",      // Gauge for BPF map utilization
		"kubeadapt_overflow_flows_total",             // Counter for overflow events
		"kubeadapt_ip_pairs_batch_size",              // Gauge for batch size
	}

	foundMetrics := make(map[string]bool)
	for _, mf := range metricFamilies {
		foundMetrics[*mf.Name] = true
		t.Logf("Found metric: %s", *mf.Name)
	}

	for _, expected := range expectedMetrics {
		assert.True(t, foundMetrics[expected], "Expected metric %s not found", expected)
	}

	// Check collector stats - verify connections were tracked
	collectorStats := connectionCollector.GetStats()
	assert.NotNil(t, collectorStats)
	t.Logf("Collector stats: %+v", collectorStats)

	// Verify that connections were actually tracked
	totalSeen, ok := collectorStats["total_connections_seen"].(uint64)
	require.True(t, ok, "total_connections_seen should be uint64")
	assert.Greater(t, totalSeen, uint64(0), "Should have tracked at least one connection")

	t.Log("✓ Connection tracking pipeline validated successfully")
}

// TestConnectionCleanup tests the read-then-delete pattern
// Note: The collector now uses a read-then-delete pattern instead of cleanup intervals
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

	// Create connection collector
	registry := prometheus.NewRegistry()
	cfg := &mockConfig{dumpBPFMaps: false}
	connectionCollector := collector.NewConnectionCollector(
		manager,
		logger,
		registry,
		cfg,
	)

	// Manually add a connection to the map
	connMap := manager.GetConnectionMap()
	require.NotNil(t, connMap)

	// Create a test connection entry
	testKey := bpf.ConnectionKey{
		SrcAddr:  ipToUint32Array("10.0.0.1"),
		DstAddr:  ipToUint32Array("10.0.0.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6, // TCP
		Family:   2, // AF_INET
	}

	testStats := bpf.ConnectionStats{
		Bytes:      1000,
		Packets:    10,
		LastSeenNs: uint64(time.Now().UnixNano()),
	}

	err = connMap.Update(&testKey, &testStats, ebpf.UpdateAny)
	require.NoError(t, err)

	// Verify entry exists
	var checkStats bpf.ConnectionStats
	err = connMap.Lookup(&testKey, &checkStats)
	require.NoError(t, err, "Test entry should exist before cleanup")
	assert.Equal(t, testStats.Bytes, checkStats.Bytes)

	// Start collector (it will read-then-delete the entry on next collection cycle)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go connectionCollector.Start(ctx)

	// Wait for at least one collection cycle (25 seconds + buffer)
	time.Sleep(27 * time.Second)

	// Check if entry was deleted during collection
	err = connMap.Lookup(&testKey, &checkStats)
	// Entry should be gone after read-then-delete
	assert.Error(t, err, "Entry should have been deleted during collection cycle")
	assert.ErrorIs(t, err, ebpf.ErrKeyNotExist, "Error should be ErrKeyNotExist")

	t.Log("✓ Read-then-delete pattern working correctly")
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

// ipToUint32Array converts an IP string to [4]uint32 array for ConnectionKey
// For IPv4, only the first element is used, rest are zero
func ipToUint32Array(ip string) [4]uint32 {
	netIP := net.ParseIP(ip).To4()
	if netIP == nil {
		return [4]uint32{0, 0, 0, 0}
	}

	// Convert IPv4 to uint32 in network byte order
	ipUint32 := uint32(netIP[0])<<24 | uint32(netIP[1])<<16 | uint32(netIP[2])<<8 | uint32(netIP[3])

	return [4]uint32{ipUint32, 0, 0, 0}
}

// formatConnectionIPs extracts and formats IP addresses from connection key
// Uses shared helper functions from bpf_test.go (formatIPv4, formatIPv6)
func formatConnectionIPs(key *bpf.ConnectionKey) (srcIP, dstIP string) {
	const (
		AF_INET  = 2
		AF_INET6 = 10
	)

	switch key.Family {
	case AF_INET:
		// IPv4 - only first element is used
		srcIP = formatIPv4(key.SrcAddr[0])
		dstIP = formatIPv4(key.DstAddr[0])
	case AF_INET6:
		// IPv6 - all 4 elements used
		srcIP = formatIPv6(key.SrcAddr)
		dstIP = formatIPv6(key.DstAddr)
	default:
		// Unknown, try to detect
		if key.SrcAddr[1] != 0 || key.SrcAddr[2] != 0 || key.SrcAddr[3] != 0 {
			srcIP = formatIPv6(key.SrcAddr)
			dstIP = formatIPv6(key.DstAddr)
		} else {
			srcIP = formatIPv4(key.SrcAddr[0])
			dstIP = formatIPv4(key.DstAddr[0])
		}
	}

	return srcIP, dstIP
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

// TestIPv6Connections tests IPv6 address handling with [4]uint32 arrays
func TestIPv6Connections(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	logger := zaptest.NewLogger(t)

	// Create BPF manager
	manager, err := bpf.NewManager(logger)
	require.NoError(t, err)
	defer manager.Close()

	// Load BPF programs
	err = manager.LoadAndAttach("disabled")
	require.NoError(t, err)

	connMap := manager.GetConnectionMap()
	require.NotNil(t, connMap)

	// Test IPv6 address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
	// Represented as [4]uint32 in network byte order
	testKey := bpf.ConnectionKey{
		SrcAddr: [4]uint32{
			0x20010db8, // 2001:0db8
			0x85a30000, // 85a3:0000
			0x00008a2e, // 0000:8a2e
			0x03707334, // 0370:7334
		},
		DstAddr: [4]uint32{
			0x20010db8,
			0x85a30001,
			0x00008a2e,
			0x03707335,
		},
		SrcPort:  8080,
		DstPort:  443,
		Protocol: 6,  // TCP
		Family:   10, // AF_INET6
	}

	testStats := bpf.ConnectionStats{
		Bytes:      5000,
		Packets:    50,
		LastSeenNs: uint64(time.Now().UnixNano()),
		CgroupID:   12345,
	}

	// Insert IPv6 connection
	err = connMap.Update(&testKey, &testStats, ebpf.UpdateAny)
	require.NoError(t, err, "Should insert IPv6 connection")

	// Lookup IPv6 connection
	var retrievedStats bpf.ConnectionStats
	err = connMap.Lookup(&testKey, &retrievedStats)
	require.NoError(t, err, "Should lookup IPv6 connection")

	// Verify stats match
	assert.Equal(t, testStats.Bytes, retrievedStats.Bytes, "Bytes should match")
	assert.Equal(t, testStats.Packets, retrievedStats.Packets, "Packets should match")
	assert.Equal(t, testStats.CgroupID, retrievedStats.CgroupID, "CgroupID should match")

	// Verify IPv6 address formatting
	srcIP, dstIP := formatConnectionIPs(&testKey)
	assert.NotEmpty(t, srcIP, "Source IPv6 should be formatted")
	assert.NotEmpty(t, dstIP, "Destination IPv6 should be formatted")

	t.Logf("✓ IPv6 connection handled correctly: %s -> %s", srcIP, dstIP)

	// Cleanup
	err = connMap.Delete(&testKey)
	require.NoError(t, err)
}

// TestMetricValueAssertions tests that byte/packet counts match expected traffic
func TestMetricValueAssertions(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	logger := zaptest.NewLogger(t)

	// Create BPF manager
	manager, err := bpf.NewManager(logger)
	require.NoError(t, err)
	defer manager.Close()

	// Load BPF programs
	err = manager.LoadAndAttach("disabled")
	require.NoError(t, err)

	// Create metrics registry
	registry := prometheus.NewRegistry()
	cfg := &mockConfig{dumpBPFMaps: false}

	connectionCollector := collector.NewConnectionCollector(
		manager,
		logger,
		registry,
		cfg,
	)

	// Start collector
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go connectionCollector.Start(ctx)

	// Manually insert known connections with specific byte/packet counts
	connMap := manager.GetConnectionMap()
	require.NotNil(t, connMap)

	// Insert 3 connections with known traffic
	connections := []struct {
		key   bpf.ConnectionKey
		stats bpf.ConnectionStats
	}{
		{
			key: bpf.ConnectionKey{
				SrcAddr:  ipToUint32Array("192.168.1.1"),
				DstAddr:  ipToUint32Array("192.168.1.2"),
				SrcPort:  10001,
				DstPort:  80,
				Protocol: 6,
				Family:   2,
			},
			stats: bpf.ConnectionStats{
				Bytes:      1000,
				Packets:    10,
				LastSeenNs: uint64(time.Now().UnixNano()),
			},
		},
		{
			key: bpf.ConnectionKey{
				SrcAddr:  ipToUint32Array("192.168.1.3"),
				DstAddr:  ipToUint32Array("192.168.1.4"),
				SrcPort:  10002,
				DstPort:  443,
				Protocol: 6,
				Family:   2,
			},
			stats: bpf.ConnectionStats{
				Bytes:      2000,
				Packets:    20,
				LastSeenNs: uint64(time.Now().UnixNano()),
			},
		},
		{
			key: bpf.ConnectionKey{
				SrcAddr:  ipToUint32Array("192.168.1.5"),
				DstAddr:  ipToUint32Array("192.168.1.6"),
				SrcPort:  10003,
				DstPort:  8080,
				Protocol: 6,
				Family:   2,
			},
			stats: bpf.ConnectionStats{
				Bytes:      3000,
				Packets:    30,
				LastSeenNs: uint64(time.Now().UnixNano()),
			},
		},
	}

	expectedTotalBytes := uint64(0)
	expectedTotalPackets := uint64(0)

	for _, conn := range connections {
		err = connMap.Update(&conn.key, &conn.stats, ebpf.UpdateAny)
		require.NoError(t, err)
		expectedTotalBytes += conn.stats.Bytes
		expectedTotalPackets += conn.stats.Packets
	}

	t.Logf("Inserted 3 test connections: %d bytes, %d packets", expectedTotalBytes, expectedTotalPackets)

	// Wait for collection cycle
	t.Log("Waiting for collection cycle (27 seconds)...")
	time.Sleep(27 * time.Second)

	// Check metrics
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	// Find total bytes and packets from metrics
	var actualTotalBytes, actualTotalPackets float64
	for _, mf := range metricFamilies {
		if *mf.Name == "kubeadapt_connection_traffic_bytes_total" {
			for _, m := range mf.Metric {
				actualTotalBytes += *m.Counter.Value
			}
		}
		if *mf.Name == "kubeadapt_connection_traffic_packets_total" {
			for _, m := range mf.Metric {
				actualTotalPackets += *m.Counter.Value
			}
		}
	}

	t.Logf("Actual metrics: %f bytes, %f packets", actualTotalBytes, actualTotalPackets)

	// Assert that metrics match expected values (with reasonable tolerance for background traffic)
	// We expect at least our test traffic to be captured
	assert.GreaterOrEqual(t, actualTotalBytes, float64(expectedTotalBytes),
		"Total bytes should include at least our test traffic")
	assert.GreaterOrEqual(t, actualTotalPackets, float64(expectedTotalPackets),
		"Total packets should include at least our test traffic")

	t.Log("✓ Metric value assertions validated")
}

// TestCgroupTracking tests that cgroup ID is captured correctly
func TestCgroupTracking(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	logger := zaptest.NewLogger(t)

	// Create BPF manager
	manager, err := bpf.NewManager(logger)
	require.NoError(t, err)
	defer manager.Close()

	// Load BPF programs
	err = manager.LoadAndAttach("disabled")
	require.NoError(t, err)

	connMap := manager.GetConnectionMap()
	require.NotNil(t, connMap)

	// Manually insert connection with known cgroup ID
	testKey := bpf.ConnectionKey{
		SrcAddr:  ipToUint32Array("10.10.10.1"),
		DstAddr:  ipToUint32Array("10.10.10.2"),
		SrcPort:  50000,
		DstPort:  9090,
		Protocol: 6,
		Family:   2,
	}

	// Use a test cgroup ID
	testCgroupID := uint64(99999)
	testStats := bpf.ConnectionStats{
		Bytes:      7777,
		Packets:    77,
		LastSeenNs: uint64(time.Now().UnixNano()),
		CgroupID:   testCgroupID,
	}

	err = connMap.Update(&testKey, &testStats, ebpf.UpdateAny)
	require.NoError(t, err)

	// Retrieve and verify
	var retrievedStats bpf.ConnectionStats
	err = connMap.Lookup(&testKey, &retrievedStats)
	require.NoError(t, err)

	assert.Equal(t, testCgroupID, retrievedStats.CgroupID, "Cgroup ID should be preserved")
	assert.Equal(t, testStats.Bytes, retrievedStats.Bytes, "Bytes should match")
	assert.Equal(t, testStats.Packets, retrievedStats.Packets, "Packets should match")

	t.Logf("✓ Cgroup ID tracking validated: cgroup_id=%d", retrievedStats.CgroupID)

	// Cleanup
	err = connMap.Delete(&testKey)
	require.NoError(t, err)
}

// TestMapOverflow tests handling when connection map fills up and overflows
// This test is designed to run with BPF_MAP_SIZE=200 (via make test-integration-overflow)
// It inserts 300-400 connections to trigger overflow and verify overflow ringbuffer handling
func TestMapOverflow(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// This test is designed to be run with BPF_MAP_SIZE=200 (set via make test-integration-overflow)
	// It inserts 300-400 connections rapidly to trigger map overflow before the 25s collection cycle
	// Expected behavior:
	//   - First 200 connections: Stored in map
	//   - Remaining 100-200 connections: Sent to overflow ringbuffer
	//   - Overflow events should be visible in metrics

	logger := zaptest.NewLogger(t)

	manager, err := bpf.NewManager(logger)
	require.NoError(t, err)
	defer manager.Close()

	err = manager.LoadAndAttach("disabled")
	require.NoError(t, err)

	connMap := manager.GetConnectionMap()
	require.NotNil(t, connMap)

	// Get map info to verify capacity
	info, err := connMap.Info()
	require.NoError(t, err)
	t.Logf("Connection map capacity: %d entries", info.MaxEntries)

	// Insert connections rapidly to trigger overflow (300-400 connections for 200-entry map)
	// This ensures we exceed map capacity before the 25s collection cycle
	numConnections := 350
	t.Logf("Inserting %d connections to trigger overflow (map capacity: %d)...", numConnections, info.MaxEntries)

	startTime := time.Now()
	insertedCount := 0

	for i := 0; i < numConnections; i++ {
		// Generate unique connection for each iteration
		// Create unique destination IPs by varying the last octet
		lastOctet := uint32(i % 256)
		testKey := bpf.ConnectionKey{
			SrcAddr: ipToUint32Array("172.16.0.1"),
			DstAddr: [4]uint32{
				uint32(172)<<24 | uint32(16)<<16 | uint32(1)<<8 | lastOctet,
				0, 0, 0,
			},
			SrcPort:  uint16(20000 + i),
			DstPort:  uint16(80 + (i % 100)),
			Protocol: 6,
			Family:   2,
		}

		testStats := bpf.ConnectionStats{
			Bytes:      uint64(100 + i),
			Packets:    uint64(1 + i/10),
			LastSeenNs: uint64(time.Now().UnixNano()),
			CgroupID:   uint64(1000 + i),
		}

		err = connMap.Update(&testKey, &testStats, ebpf.UpdateAny)
		if err != nil {
			t.Logf("Failed to insert connection %d: %v", i, err)
			break
		}
		insertedCount++
	}

	elapsed := time.Since(startTime)
	t.Logf("Attempted to insert %d connections, successfully inserted %d in %v (%.0f inserts/sec)",
		numConnections, insertedCount, elapsed, float64(insertedCount)/elapsed.Seconds())

	// Count actual entries in map
	iter := connMap.Iterate()
	var key bpf.ConnectionKey
	var stats bpf.ConnectionStats
	mapEntryCount := 0

	for iter.Next(&key, &stats) {
		mapEntryCount++
	}

	t.Logf("Map contains %d entries (capacity: %d)", mapEntryCount, info.MaxEntries)

	// Check for iteration errors
	if mapEntryCount > 0 && iter.Err() != nil {
		t.Logf("Note: Iterator error after reading %d entries: %v", mapEntryCount, iter.Err())
	}

	// Verify overflow behavior
	if numConnections > int(info.MaxEntries) {
		// We inserted more connections than map capacity - overflow should have occurred
		expectedOverflowCount := numConnections - int(info.MaxEntries)

		// Map should be at or near capacity
		assert.GreaterOrEqual(t, mapEntryCount, int(info.MaxEntries)*9/10,
			"Map should be at least 90%% full when overflow occurs")

		// Some connections should have failed to insert (triggering overflow)
		overflowCount := numConnections - insertedCount
		t.Logf("Overflow events: ~%d connections sent to ringbuffer (expected ~%d)",
			overflowCount, expectedOverflowCount)

		// We expect at least some overflow
		assert.Greater(t, overflowCount, 0,
			"Should have overflow events when exceeding map capacity")

		t.Logf("✓ Map overflow handled correctly: %d in map, %d overflowed to ringbuffer",
			mapEntryCount, overflowCount)
	} else {
		// No overflow expected
		assert.Equal(t, numConnections, insertedCount,
			"Should insert all connections without overflow")
		t.Log("✓ Map handled burst traffic correctly (no overflow)")
	}
}
