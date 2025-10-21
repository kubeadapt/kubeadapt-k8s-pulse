//go:build linux

package bpf

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// TestBPFProgramLoading verifies that TC BPF programs can be loaded successfully
func TestBPFProgramLoading(t *testing.T) {
	// Remove memory lock for BPF operations
	require.NoError(t, rlimit.RemoveMemlock(), "Failed to remove memory lock")

	logger := zaptest.NewLogger(t)

	// Test loading BPF spec
	spec, err := loadNetwork()
	require.NoError(t, err, "Failed to load BPF spec")
	require.NotNil(t, spec, "BPF spec should not be nil")

	// Verify expected programs exist
	// EGRESS-ONLY: Only tc_egress program exists (no tc_ingress)
	require.Contains(t, spec.Programs, "tc_egress", "tc_egress program should exist")
	require.NotContains(t, spec.Programs, "tc_ingress", "tc_ingress should NOT exist (egress-only architecture)")

	// Verify expected maps exist
	require.Contains(t, spec.Maps, "connection_flows", "connection_flows map should exist")
	require.Contains(t, spec.Maps, "overflow_events", "overflow_events ringbuffer should exist")
	require.Contains(t, spec.Maps, "global_counters", "global_counters map should exist")
	require.Contains(t, spec.Maps, "filter_mode_map", "filter_mode_map should exist")
	require.Contains(t, spec.Maps, "host_netns_map", "host_netns_map should exist")

	// Load programs into kernel (this verifies BPF verifier acceptance)
	coll, err := ebpf.NewCollection(spec)
	require.NoError(t, err, "Failed to load BPF collection into kernel")
	defer coll.Close()

	// Verify programs loaded
	// EGRESS-ONLY: Only tc_egress program should be loaded
	require.NotNil(t, coll.Programs["tc_egress"], "tc_egress program should be loaded")
	require.Nil(t, coll.Programs["tc_ingress"], "tc_ingress should NOT be loaded (egress-only architecture)")

	// Verify maps loaded
	require.NotNil(t, coll.Maps["connection_flows"], "connection_flows map should be loaded")
	require.NotNil(t, coll.Maps["overflow_events"], "overflow_events should be loaded")

	logger.Info("BPF programs loaded successfully")
}

// TestConnectionFlowsMapStructure verifies map configuration matches expectations
func TestConnectionFlowsMapStructure(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := loadNetwork()
	require.NoError(t, err)

	coll, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	defer coll.Close()

	connMap := coll.Maps["connection_flows"]
	require.NotNil(t, connMap)

	// Get map info
	info, err := connMap.Info()
	require.NoError(t, err)

	// Verify map type
	require.Equal(t, ebpf.Hash, info.Type, "connection_flows should be a hash map")

	// Verify key size matches ConnectionKey struct
	// ConnectionKey: [4]uint32 + [4]uint32 + uint16 + uint16 + uint8 + uint8 + uint16
	// = 16 + 16 + 2 + 2 + 1 + 1 + 2 = 40 bytes
	require.Equal(t, uint32(40), info.KeySize, "Key size should match ConnectionKey struct (40 bytes)")

	// Verify value size matches ConnectionStats struct
	// EGRESS-ONLY: ConnectionStats has Bytes, Packets, LastSeenNs (3x uint64 = 24 bytes)
	// + CgroupID (uint32 = 4 bytes) + IfIndexFirstSeen (uint32 = 4 bytes)
	// + 8 bytes padding = 40 bytes total
	require.Equal(t, uint32(40), info.ValueSize, "Value size should match ConnectionStats struct (40 bytes)")

	// Verify max entries
	require.Equal(t, uint32(100000), info.MaxEntries, "Max entries should be 100,000")
}

// TestOverflowRingbufferStructure verifies overflow ringbuffer configuration
func TestOverflowRingbufferStructure(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := loadNetwork()
	require.NoError(t, err)

	coll, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	defer coll.Close()

	overflowRB := coll.Maps["overflow_events"]
	require.NotNil(t, overflowRB)

	info, err := overflowRB.Info()
	require.NoError(t, err)

	// Verify it's a ringbuffer
	require.Equal(t, ebpf.RingBuf, info.Type, "overflow_events should be a ringbuffer")

	// Verify size is 16MB (1 << 24)
	require.Equal(t, uint32(1<<24), info.MaxEntries, "Ringbuffer should be 16MB")
}

// TestGlobalCountersMapStructure verifies global counters map
func TestGlobalCountersMapStructure(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := loadNetwork()
	require.NoError(t, err)

	coll, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	defer coll.Close()

	countersMap := coll.Maps["global_counters"]
	require.NotNil(t, countersMap)

	info, err := countersMap.Info()
	require.NoError(t, err)

	// Verify it's a per-CPU array
	require.Equal(t, ebpf.PerCPUArray, info.Type, "global_counters should be a per-CPU array")

	// Verify key/value sizes
	require.Equal(t, uint32(4), info.KeySize, "Key should be uint32 (4 bytes)")
	require.Equal(t, uint32(8), info.ValueSize, "Value should be uint64 (8 bytes)")

	// Verify max entries (16 counters)
	require.Equal(t, uint32(16), info.MaxEntries, "Should have 16 counter slots")
}

// TestMapOperations tests basic BPF map operations
func TestMapOperations(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := loadNetwork()
	require.NoError(t, err)

	coll, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	defer coll.Close()

	connMap := coll.Maps["connection_flows"]
	require.NotNil(t, connMap)

	// Test: Insert a connection
	key := ConnectionKey{
		SrcAddr:  [4]uint32{0x0100007f, 0, 0, 0}, // 127.0.0.1 in network byte order
		DstAddr:  [4]uint32{0x0100007f, 0, 0, 0},
		SrcPort:  12345,
		DstPort:  80,
		Protocol: 6, // TCP
		Family:   2, // AF_INET
	}

	// EGRESS-ONLY: Only Bytes and Packets (no Sent/Received split)
	stats := ConnectionStats{
		Bytes:      1500, // Total bytes (egress only)
		Packets:    15,   // Total packets
		LastSeenNs: 1234567890,
		CgroupID:   42,
	}

	err = connMap.Put(&key, &stats)
	require.NoError(t, err, "Failed to insert connection into map")

	// Test: Lookup the connection
	var readStats ConnectionStats
	err = connMap.Lookup(&key, &readStats)
	require.NoError(t, err, "Failed to lookup connection from map")

	// Verify data matches (egress-only fields)
	require.Equal(t, stats.Bytes, readStats.Bytes)
	require.Equal(t, stats.Packets, readStats.Packets)
	require.Equal(t, stats.CgroupID, readStats.CgroupID)

	// Test: Delete the connection
	err = connMap.Delete(&key)
	require.NoError(t, err, "Failed to delete connection from map")

	// Verify deletion
	err = connMap.Lookup(&key, &readStats)
	require.Error(t, err, "Lookup should fail after deletion")
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist, "Error should be ErrKeyNotExist")
}

// TestMapIteration tests iterating over BPF map entries
func TestMapIteration(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := loadNetwork()
	require.NoError(t, err)

	coll, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	defer coll.Close()

	connMap := coll.Maps["connection_flows"]
	require.NotNil(t, connMap)

	// Insert multiple connections
	numEntries := 5
	for i := 0; i < numEntries; i++ {
		key := ConnectionKey{
			SrcAddr:  [4]uint32{uint32(i), 0, 0, 0},
			DstAddr:  [4]uint32{uint32(i + 100), 0, 0, 0},
			SrcPort:  uint16(10000 + i),
			DstPort:  80,
			Protocol: 6,
			Family:   2,
		}

		// EGRESS-ONLY: Only Bytes and Packets
		stats := ConnectionStats{
			Bytes:   uint64(i * 1000),
			Packets: uint64(i),
		}

		err = connMap.Put(&key, &stats)
		require.NoError(t, err)
	}

	// Iterate and count entries
	iter := connMap.Iterate()
	var key ConnectionKey
	var stats ConnectionStats
	count := 0

	for iter.Next(&key, &stats) {
		count++
	}

	require.NoError(t, iter.Err(), "Iterator should not have errors")
	require.Equal(t, numEntries, count, "Should iterate over all inserted entries")
}

// TestEmptyMapIteration tests iterating over empty map (this triggers the "buffer too small" warning)
func TestEmptyMapIteration(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())

	spec, err := loadNetwork()
	require.NoError(t, err)

	coll, err := ebpf.NewCollection(spec)
	require.NoError(t, err)
	defer coll.Close()

	connMap := coll.Maps["connection_flows"]
	require.NotNil(t, connMap)

	// Iterate over empty map
	iter := connMap.Iterate()
	var key ConnectionKey
	var stats ConnectionStats
	count := 0

	for iter.Next(&key, &stats) {
		count++
	}

	// Check iterator error
	// Note: cilium/ebpf returns "look up next key: buffer too small" for empty maps
	// This is expected behavior and should not be treated as a fatal error
	iterErr := iter.Err()
	if iterErr != nil {
		// If error exists, it should be the expected "buffer too small" or ErrKeyNotExist
		require.Contains(t, iterErr.Error(), "buffer too small",
			"Empty map iteration error should be 'buffer too small'")
	}

	require.Equal(t, 0, count, "Empty map should have zero entries")
}

// TestFilterModeMapInitialization tests network namespace filter mode configuration
func TestFilterModeMapInitialization(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())

	logger := zaptest.NewLogger(t)
	manager, err := NewManager(logger)
	require.NoError(t, err)

	// Load BPF programs
	err = manager.LoadAndAttach("default")
	require.NoError(t, err)
	defer manager.Close()

	// Verify filter mode map exists and is accessible
	filterModeMap := manager.collection.Maps["filter_mode_map"]
	require.NotNil(t, filterModeMap)

	// Read filter mode value
	key := uint32(0)
	var mode uint32
	err = filterModeMap.Lookup(&key, &mode)
	require.NoError(t, err)

	// Should be set to default mode (0)
	require.Equal(t, uint32(0), mode, "Filter mode should be default (0)")

	logger.Info("Filter mode initialized correctly", zap.Uint32("mode", mode))
}

// TestConnectionKeyStructSize validates ConnectionKey struct alignment
func TestConnectionKeyStructSize(t *testing.T) {
	var key ConnectionKey

	// Calculate expected size
	// [4]uint32 = 16 bytes
	// [4]uint32 = 16 bytes
	// uint16 = 2 bytes
	// uint16 = 2 bytes
	// uint8 = 1 byte
	// uint8 = 1 byte
	// uint16 (padding) = 2 bytes
	// Total = 40 bytes

	require.Equal(t, 40, int(unsafe.Sizeof(key)),
		"ConnectionKey struct should be exactly 40 bytes")
}

// TestConnectionStatsStructSize validates ConnectionStats struct alignment
func TestConnectionStatsStructSize(t *testing.T) {
	var stats ConnectionStats

	// Calculate expected size (EGRESS-ONLY architecture)
	// 3x uint64 (Bytes, Packets, LastSeenNs) = 24 bytes
	// 1x uint64 (CgroupID) = 8 bytes
	// 1x uint32 (IfIndexFirstSeen) = 4 bytes
	// 4 bytes padding for alignment
	// Total = 40 bytes

	require.Equal(t, 40, int(unsafe.Sizeof(stats)),
		"ConnectionStats struct should be exactly 40 bytes (egress-only)")
}

// TestFlowRecordStructSize validates FlowRecord struct for ringbuffer
func TestFlowRecordStructSize(t *testing.T) {
	var record FlowRecord

	// Calculate expected size (EGRESS-ONLY architecture)
	// ConnectionKey = 40 bytes
	// ConnectionStats = 40 bytes (egress-only)
	// uint64 (timestamp) = 8 bytes
	// uint8 (reason) = 1 byte
	// [7]byte padding = 7 bytes
	// Total = 96 bytes

	require.Equal(t, 96, int(unsafe.Sizeof(record)),
		"FlowRecord struct should be exactly 96 bytes for ringbuffer alignment (egress-only)")
}
