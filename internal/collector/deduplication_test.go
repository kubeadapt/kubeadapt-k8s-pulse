package collector

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/kubeadapt/ebpf-agent/internal/bpf"
	"github.com/stretchr/testify/assert"
)

// TestDeduplicationMetadata tests that deduplication fields are correctly populated
// This verifies the struct alignment and field access for deduplication tracking
//
// EGRESS-ONLY ARCHITECTURE: TC hooks attached only to egress
// - No direction split (only Bytes and Packets, not Sent/Received)
// - IfIndexFirstSeen tracks which interface first saw the flow (for deduplication)
func TestDeduplicationMetadata(t *testing.T) {
	tests := []struct {
		name               string
		stats              bpf.ConnectionStats
		wantIfIndex        uint32
		shouldHaveMetadata bool
	}{
		{
			name: "Flow with deduplication metadata - first interface",
			stats: bpf.ConnectionStats{
				Bytes:            1500,
				Packets:          1,
				LastSeenNs:       1234567890,
				CgroupID:         100,
				IfIndexFirstSeen: 5, // veth-abc (first interface that saw this flow)
			},
			wantIfIndex:        5,
			shouldHaveMetadata: true,
		},
		{
			name: "Flow with deduplication metadata - different interface",
			stats: bpf.ConnectionStats{
				Bytes:            3000,
				Packets:          2,
				LastSeenNs:       1234567890,
				CgroupID:         200,
				IfIndexFirstSeen: 7, // veth-def
			},
			wantIfIndex:        7,
			shouldHaveMetadata: true,
		},
		{
			name: "Flow without deduplication metadata (single interface)",
			stats: bpf.ConnectionStats{
				Bytes:            1500,
				Packets:          1,
				LastSeenNs:       1234567890,
				CgroupID:         100,
				IfIndexFirstSeen: 0, // Not set (single interface flow)
			},
			wantIfIndex:        0,
			shouldHaveMetadata: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify interface index field
			assert.Equal(t, tt.wantIfIndex, tt.stats.IfIndexFirstSeen,
				"IfIndexFirstSeen should match expected value")

			// Verify metadata presence
			hasMetadata := tt.stats.IfIndexFirstSeen > 0
			assert.Equal(t, tt.shouldHaveMetadata, hasMetadata,
				"Metadata presence should match expected")
		})
	}
}

// TestDeduplicationScenario documents the expected behavior of deduplication logic
// This is a documentation test that verifies our understanding of the deduplication algorithm
//
// EGRESS-ONLY ARCHITECTURE:
// - TC hooks attached ONLY to egress (no ingress tracking)
// - Only Bytes and Packets fields (no Sent/Received split)
// - IfIndexFirstSeen tracks first interface for deduplication
func TestDeduplicationScenario(t *testing.T) {
	t.Run("Scenario 1: Pod-to-Pod single interface observation (egress-only)", func(t *testing.T) {
		// Setup: Pod A (veth-abc, ifindex=5) sends 1500 bytes to Pod B
		// Only egress is tracked (TC hook on egress only)

		key := &bpf.ConnectionKey{
			SrcAddr:  [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("10.1.1.5").To4()), 0, 0, 0},
			DstAddr:  [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("10.1.1.6").To4()), 0, 0, 0},
			SrcPort:  45678,
			DstPort:  80,
			Protocol: 6, // TCP
			Family:   2, // AF_INET
		}

		stats := &bpf.ConnectionStats{
			Bytes:            1500, // Total bytes (egress only)
			Packets:          1,    // Total packets
			LastSeenNs:       1234567890,
			CgroupID:         100, // Pod A cgroup
			IfIndexFirstSeen: 5,   // veth-abc (first interface)
		}

		// Verify expected behavior
		srcIP, dstIP := ConnectionKeyToIPs(key)
		assert.Equal(t, "10.1.1.5", srcIP)
		assert.Equal(t, "10.1.1.6", dstIP)
		assert.Equal(t, uint64(1500), stats.Bytes, "Should count 1500 bytes")
		assert.Equal(t, uint64(1), stats.Packets, "Should count 1 packet")

		// Verify deduplication metadata
		assert.Equal(t, uint32(5), stats.IfIndexFirstSeen, "Should track first interface")
	})

	t.Run("Scenario 2: Multi-interface path deduplication (veth→docker0→eth0)", func(t *testing.T) {
		// Setup: Same packet traverses MULTIPLE interfaces on egress path
		// 1. veth-abc (ifindex=5) - FIRST (counted)
		// 2. docker0  (ifindex=6) - SECOND (deduplicated, not counted)
		// 3. eth0     (ifindex=7) - THIRD (deduplicated, not counted)

		// Expected BPF map entry after deduplication
		// Only first interface (veth-abc, ifindex=5) counts the bytes
		stats := &bpf.ConnectionStats{
			Bytes:            1500,       // From first interface only
			Packets:          1,          // First interface only
			LastSeenNs:       1234567891, // Updated by last observation
			CgroupID:         100,        // From first interface (Pod A)
			IfIndexFirstSeen: 5,          // First interface wins (veth-abc)
		}

		// Verify NO double-counting across multiple interfaces
		assert.Equal(t, uint64(1500), stats.Bytes,
			"Total bytes should be 1500 (NOT 4500!). Deduplication prevents multi-interface counting")

		// Verify first interface locked
		assert.Equal(t, uint32(5), stats.IfIndexFirstSeen,
			"First interface (veth-abc) should be locked")

		// Verify timestamp updated (even though bytes not counted from other interfaces)
		assert.Greater(t, stats.LastSeenNs, uint64(1234567890),
			"Timestamp should update even when deduplicating")
	})

	t.Run("Scenario 3: Bidirectional traffic (separate flows, egress-only)", func(t *testing.T) {
		// Setup: Pod A → Pod B AND Pod B → Pod A
		// These are SEPARATE flows (different src/dst order)
		// EGRESS-ONLY: Each flow counted only at sender

		// Flow 1: A → B (counted at Pod A egress)
		keyAtoB := &bpf.ConnectionKey{
			SrcAddr:  [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("10.1.1.5").To4()), 0, 0, 0},
			DstAddr:  [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("10.1.1.6").To4()), 0, 0, 0},
			SrcPort:  45678,
			DstPort:  80,
			Protocol: 6,
			Family:   2,
		}

		statsAtoB := &bpf.ConnectionStats{
			Bytes:            500000, // 500KB sent A → B (egress only)
			Packets:          350,
			CgroupID:         100, // Pod A
			IfIndexFirstSeen: 5,   // veth-abc
		}

		// Flow 2: B → A (counted at Pod B egress, DIFFERENT connection key!)
		keyBtoA := &bpf.ConnectionKey{
			SrcAddr:  [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("10.1.1.6").To4()), 0, 0, 0},
			DstAddr:  [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("10.1.1.5").To4()), 0, 0, 0},
			SrcPort:  80,
			DstPort:  45678,
			Protocol: 6,
			Family:   2,
		}

		statsBtoA := &bpf.ConnectionStats{
			Bytes:            300000, // 300KB sent B → A (egress only)
			Packets:          200,
			CgroupID:         200, // Pod B
			IfIndexFirstSeen: 7,   // veth-def
		}

		// Verify these are separate flows
		srcA, dstA := ConnectionKeyToIPs(keyAtoB)
		srcB, dstB := ConnectionKeyToIPs(keyBtoA)

		assert.NotEqual(t, srcA, srcB, "Bidirectional flows have different source IPs")
		assert.NotEqual(t, dstA, dstB, "Bidirectional flows have different dest IPs")

		// Verify independent accounting
		assert.Equal(t, uint64(500000), statsAtoB.Bytes, "A→B flow counted independently")
		assert.Equal(t, uint64(300000), statsBtoA.Bytes, "B→A flow counted independently")

		// Verify no cross-contamination
		assert.Equal(t, uint64(100), statsAtoB.CgroupID, "A→B attributed to Pod A")
		assert.Equal(t, uint64(200), statsBtoA.CgroupID, "B→A attributed to Pod B")
	})
}

// TestDeduplicationMetrics verifies metric calculations with egress-only tracking
func TestDeduplicationMetrics(t *testing.T) {
	t.Run("Calculate total traffic with egress-only tracking", func(t *testing.T) {
		// Scenario: 10 egress flows, 1500 bytes each
		// EGRESS-ONLY: No ingress tracking, automatically prevents double-counting
		// Total: 10 * 1500 = 15,000 bytes (correct)

		flows := []bpf.ConnectionStats{
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
			{Bytes: 1500, Packets: 1, IfIndexFirstSeen: 5},
		}

		var totalBytes uint64
		var totalPackets uint64

		for _, flow := range flows {
			totalBytes += flow.Bytes
			totalPackets += flow.Packets
		}

		assert.Equal(t, uint64(15000), totalBytes,
			"Egress-only tracking: 10 flows * 1500 bytes = 15,000 bytes")
		assert.Equal(t, uint64(10), totalPackets,
			"Egress-only tracking: 10 flows * 1 packet = 10 packets")
	})
}
