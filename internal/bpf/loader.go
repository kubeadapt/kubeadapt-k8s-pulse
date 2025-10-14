package bpf

import (
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 network ../../bpf/network_monitor.c -- -I../../bpf/headers

// Manager handles eBPF program lifecycle
type Manager struct {
	collection *ebpf.Collection
	links      []link.Link
	logger     *zap.Logger

	// Maps for easy access
	containerStats       *ebpf.Map
	containerStatsPerCPU *ebpf.Map
	socketToCgroup       *ebpf.Map
	connectionFlows      *ebpf.Map // Connection tracking map
}

// NewManager creates a new BPF manager
func NewManager(logger *zap.Logger) (*Manager, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	// Remove memory lock limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	return &Manager{
		logger: logger,
		links:  make([]link.Link, 0),
	}, nil
}

// LoadAndAttach loads BPF programs and attaches them to kernel hooks
func (m *Manager) LoadAndAttach() error {
	m.logger.Info("Loading BPF objects")

	// Load pre-compiled BPF programs
	spec, err := loadNetwork()
	if err != nil {
		return fmt.Errorf("loading BPF spec: %w", err)
	}

	// Create collection from spec
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 2, // LogLevelInfo equivalent
			LogSize:  64 * 1024, // Default verifier log size
		},
	})
	if err != nil {
		return fmt.Errorf("creating BPF collection: %w", err)
	}
	m.collection = coll

	// Store map references
	m.containerStats = coll.Maps["container_stats"]
	m.containerStatsPerCPU = coll.Maps["container_stats_percpu"]
	m.socketToCgroup = coll.Maps["socket_to_cgroup"]
	m.connectionFlows = coll.Maps["connection_flows"] // Connection tracking map

	// Attach kprobes for TCP
	if err := m.attachTCPProbes(coll); err != nil {
		return fmt.Errorf("attaching TCP probes: %w", err)
	}

	// Attach kprobes for UDP
	if err := m.attachUDPProbes(coll); err != nil {
		return fmt.Errorf("attaching UDP probes: %w", err)
	}

	// Attach connection tracking probes
	if err := m.attachConnectionProbes(coll); err != nil {
		return fmt.Errorf("attaching connection probes: %w", err)
	}

	m.logger.Info("BPF programs attached successfully",
		zap.Int("programs", len(coll.Programs)),
		zap.Int("maps", len(coll.Maps)),
		zap.Int("links", len(m.links)),
	)

	return nil
}

// attachTCPProbes attaches TCP-related kprobes
func (m *Manager) attachTCPProbes(coll *ebpf.Collection) error {
	// TCP send
	prog := coll.Programs["trace_tcp_sendmsg"]
	if prog == nil {
		return fmt.Errorf("trace_tcp_sendmsg program not found")
	}
	l, err := link.Kprobe("tcp_sendmsg", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching tcp_sendmsg kprobe: %w", err)
	}
	m.links = append(m.links, l)
	m.logger.Debug("Attached tcp_sendmsg kprobe")

	// TCP receive
	prog = coll.Programs["trace_tcp_recvmsg"]
	if prog == nil {
		return fmt.Errorf("trace_tcp_recvmsg program not found")
	}
	l, err = link.Kprobe("tcp_recvmsg", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching tcp_recvmsg kprobe: %w", err)
	}
	m.links = append(m.links, l)

	// TCP receive return
	prog = coll.Programs["trace_tcp_recvmsg_ret"]
	if prog == nil {
		return fmt.Errorf("trace_tcp_recvmsg_ret program not found")
	}
	l, err = link.Kretprobe("tcp_recvmsg", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching tcp_recvmsg kretprobe: %w", err)
	}
	m.links = append(m.links, l)
	m.logger.Debug("Attached TCP probes")

	return nil
}

// attachUDPProbes attaches UDP-related kprobes
func (m *Manager) attachUDPProbes(coll *ebpf.Collection) error {
	// UDP send
	prog := coll.Programs["trace_udp_sendmsg"]
	if prog == nil {
		return fmt.Errorf("trace_udp_sendmsg program not found")
	}
	l, err := link.Kprobe("udp_sendmsg", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching udp_sendmsg kprobe: %w", err)
	}
	m.links = append(m.links, l)

	// UDP receive
	prog = coll.Programs["trace_udp_recvmsg"]
	if prog == nil {
		return fmt.Errorf("trace_udp_recvmsg program not found")
	}
	l, err = link.Kprobe("udp_recvmsg", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching udp_recvmsg kprobe: %w", err)
	}
	m.links = append(m.links, l)

	// UDP receive return
	prog = coll.Programs["trace_udp_recvmsg_ret"]
	if prog == nil {
		return fmt.Errorf("trace_udp_recvmsg_ret program not found")
	}
	l, err = link.Kretprobe("udp_recvmsg", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching udp_recvmsg kretprobe: %w", err)
	}
	m.links = append(m.links, l)
	m.logger.Debug("Attached UDP probes")

	return nil
}

// attachConnectionProbes attaches connection tracking probes
func (m *Manager) attachConnectionProbes(coll *ebpf.Collection) error {
	// TCP connect
	prog := coll.Programs["trace_tcp_connect"]
	if prog == nil {
		return fmt.Errorf("trace_tcp_connect program not found")
	}
	l, err := link.Kprobe("tcp_connect", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching tcp_connect kprobe: %w", err)
	}
	m.links = append(m.links, l)

	// Accept
	prog = coll.Programs["trace_accept"]
	if prog == nil {
		return fmt.Errorf("trace_accept program not found")
	}
	l, err = link.Kprobe("inet_csk_accept", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching inet_csk_accept kprobe: %w", err)
	}
	m.links = append(m.links, l)
	m.logger.Debug("Attached connection tracking probes")

	return nil
}

// GetContainerStats returns the container stats map
func (m *Manager) GetContainerStats() *ebpf.Map {
	return m.containerStats
}

// GetContainerStatsPerCPU returns the per-CPU container stats map
func (m *Manager) GetContainerStatsPerCPU() *ebpf.Map {
	return m.containerStatsPerCPU
}

// GetSocketToCgroup returns the socket to cgroup map
func (m *Manager) GetSocketToCgroup() *ebpf.Map {
	return m.socketToCgroup
}

// GetConnectionMap returns the connection flows map
func (m *Manager) GetConnectionMap() *ebpf.Map {
	return m.connectionFlows
}

// DumpMaps dumps all BPF maps for debugging
func (m *Manager) DumpMaps() (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Dump container stats
	if m.containerStats != nil {
		stats := make(map[uint64]ContainerNetStats)
		iter := m.containerStats.Iterate()
		var key uint64
		var value ContainerNetStats
		for iter.Next(&key, &value) {
			stats[key] = value
		}
		if err := iter.Err(); err != nil {
			m.logger.Warn("Error iterating container_stats", zap.Error(err))
		}
		result["container_stats"] = stats
	}

	// Get map info
	if m.containerStats != nil {
		info, _ := m.containerStats.Info()
		if info != nil {
			result["container_stats_info"] = map[string]interface{}{
				"type":        info.Type.String(),
				"max_entries": info.MaxEntries,
				"key_size":    info.KeySize,
				"value_size":  info.ValueSize,
			}
		}
	}

	return result, nil
}

// Close cleans up all BPF resources
func (m *Manager) Close() error {
	m.logger.Info("Cleaning up BPF resources")

	// Close all links
	for _, l := range m.links {
		if err := l.Close(); err != nil {
			m.logger.Warn("Error closing link", zap.Error(err))
		}
	}
	m.links = nil

	// Close collection
	if m.collection != nil {
		m.collection.Close()
		m.collection = nil
	}

	m.logger.Info("BPF resources cleaned up")
	return nil
}

// ContainerNetStats matches the C struct
type ContainerNetStats struct {
	RxBytes     uint64
	TxBytes     uint64
	RxPackets   uint64
	TxPackets   uint64
	LastSeenNs  uint64
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
type ConnectionStats struct {
	BytesSent       uint64 // Total bytes sent
	BytesReceived   uint64 // Total bytes received
	PacketsSent     uint64 // Total packets sent
	PacketsReceived uint64 // Total packets received
	LastSeenNs      uint64 // Last activity timestamp
	CgroupID        uint64 // Container cgroup ID
}