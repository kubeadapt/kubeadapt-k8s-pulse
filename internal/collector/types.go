package collector

// AggKey represents an aggregation key for grouping connections by IP pair and protocol.
// Used to aggregate multiple connections (with different ports) into pod-to-pod traffic flows.
//
// In Kubernetes environments, we're primarily interested in pod-to-pod communication patterns
// rather than individual connection tuples. This key groups all connections between the same
// source and destination IPs using the same protocol, regardless of port numbers.
//
// Example: TCP connections from 10.244.1.5:* to 10.244.1.6:* are aggregated into a single
// flow with SrcIP="10.244.1.5", DstIP="10.244.1.6", Protocol="tcp".
type AggKey struct {
	SrcIP    string // Source IP address (IPv4 or IPv6)
	DstIP    string // Destination IP address (IPv4 or IPv6)
	Protocol string // Protocol: "tcp" or "udp"
}

// AggStats represents aggregated traffic statistics for a connection flow.
// Sums all connections with the same source/destination IPs and protocol.
//
// Note: These stats represent EGRESS-ONLY traffic (outbound from the monitored pod).
// The eBPF agent uses TC egress hooks, so we only capture outgoing packets.
type AggStats struct {
	Bytes   uint64 // Total cumulative bytes transmitted (egress only)
	Packets uint64 // Total cumulative packets transmitted (egress only)
}

// NewAggKey creates a new aggregation key from IP addresses and protocol.
// This constructor ensures consistent key creation across the collector.
func NewAggKey(srcIP, dstIP, protocol string) AggKey {
	return AggKey{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: protocol,
	}
}

// Add accumulates stats from another AggStats into this one.
// Used for merging multiple connections into a single aggregated flow.
func (a *AggStats) Add(other AggStats) {
	a.Bytes += other.Bytes
	a.Packets += other.Packets
}
