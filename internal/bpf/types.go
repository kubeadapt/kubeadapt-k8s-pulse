package bpf

// ContainerNetStats matches the C struct
type ContainerNetStats struct {
	RxBytes    uint64
	TxBytes    uint64
	RxPackets  uint64
	TxPackets  uint64
	LastSeenNs uint64
}

// ConnectionInfo matches the C struct
type ConnectionInfo struct {
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Protocol uint8
	_        [3]byte // padding
}

// ConnectionKey represents a network connection 5-tuple (matches the C struct)
type ConnectionKey struct {
	// IP addresses - IPv6 size accommodates both IPv4 and IPv6
	// For IPv4: only first 32 bits used, rest are zero
	// For IPv6: all 128 bits used
	SrcAddr  [4]uint32 // Source IP address (IPv4 or IPv6)
	DstAddr  [4]uint32 // Destination IP address (IPv4 or IPv6)
	SrcPort  uint16    // Source port
	DstPort  uint16    // Destination port
	Protocol uint8     // Protocol (TCP=6, UDP=17)
	Family   uint8     // AF_INET (2) or AF_INET6 (10)
	Pad      uint16    // Padding for alignment
}

// ConnectionStats represents statistics for a network connection (matches the C struct)
//
// EGRESS-ONLY TRACKING:
// TC is attached ONLY to egress hooks, which automatically prevents:
// - Same-node Pod-to-Pod duplication (only sender tracked)
// - Cross-node duplication (receiver never tracked)
//
// INTERFACE DEDUPLICATION:
// When a packet traverses multiple interfaces (veth → docker0 → eth0), we track
// the first interface and only count packets from that interface.
type ConnectionStats struct {
	Bytes            uint64  // Total bytes (egress only, no direction split)
	Packets          uint64  // Total packets (egress only)
	LastSeenNs       uint64  // Last activity timestamp
	CgroupID         uint64  // Pod cgroup ID (from first interface)
	IfIndexFirstSeen uint32  // First interface where flow was observed (deduplication key)
	Padding          [4]byte // Alignment padding
}

// FlowRecord represents an overflow flow record from the ringbuffer (matches the C struct)
type FlowRecord struct {
	Key         ConnectionKey   // Connection 5-tuple
	Stats       ConnectionStats // Connection statistics
	TimestampNs uint64          // Timestamp when overflow occurred
	Reason      uint8           // 0=map_full, 2=explicit (reason 1 unused with standard HASH)
	Padding     [7]byte         // Padding for alignment
}

// Overflow reason constants (match BPF definitions)
// Note: With standard HASH (not LRU_HASH), only map_full reason is used
// OverflowReasonEviction was previously used with LRU maps but is no longer relevant
const (
	OverflowReasonMapFull  = 0 // Map reached max_entries capacity
	OverflowReasonExplicit = 2 // Explicit overflow event (future use)
)
