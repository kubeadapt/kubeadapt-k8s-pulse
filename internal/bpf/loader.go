package bpf

import (
	"context"
	_ "embed"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kubeadapt/ebpf-agent/internal/config"
	"github.com/kubeadapt/ebpf-agent/internal/system"
	"go.uber.org/zap"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -Wall -Werror" -target amd64 network ../../bpf/network_monitor.c -- -I../../bpf/headers

// Manager handles eBPF program lifecycle
type Manager struct {
	collection *ebpf.Collection
	links      []link.Link
	logger     *zap.Logger

	// Maps for easy access
	// NOTE: container_stats (non-per-CPU) has been removed - only using per-CPU version
	containerStatsPerCPU *ebpf.Map
	socketToCgroup       *ebpf.Map
	connectionFlows      *ebpf.Map // Connection tracking map
	overflowRingbuf      *ebpf.Map // Overflow ringbuffer for flow records
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

// getKernelVersionUint32 returns the kernel version encoded as uint32
// Format: (MAJOR << 16) | (MINOR << 8) | PATCH
// This avoids vDSO-based detection which fails in some container environments
func (m *Manager) getKernelVersionUint32() (uint32, error) {
	kv, err := system.GetKernelVersion()
	if err != nil {
		return 0, fmt.Errorf("getting kernel version: %w", err)
	}

	// Encode as: (MAJOR << 16) | (MINOR << 8) | PATCH
	version := uint32(kv.Major<<16 | kv.Minor<<8 | kv.Patch)
	return version, nil
}

// LoadAndAttach loads BPF programs and attaches them to kernel hooks
// filterMode: Network namespace filtering mode ("default", "strict", or "disabled")
func (m *Manager) LoadAndAttach(filterMode string) error {
	m.logger.Info("Loading BPF objects")

	// Detect network namespace offsets if strict mode is requested
	// This must be done BEFORE loading BPF programs so we can decide whether to use strict mode
	var offsets *NetnsOffsets
	if filterMode == "strict" {
		detectedOffsets, err := DetectNetnsOffsets(m.logger)
		if err != nil {
			m.logger.Warn("Failed to detect network namespace offsets, falling back to default mode",
				zap.Error(err),
				zap.String("original_mode", filterMode))
			// Fall back to default mode if offset detection fails
			filterMode = "default"
		} else {
			// Validate offsets before using them
			if err := detectedOffsets.ValidateOffsets(); err != nil {
				m.logger.Warn("Invalid network namespace offsets detected, falling back to default mode",
					zap.Error(err),
					zap.String("original_mode", filterMode))
				filterMode = "default"
			} else {
				offsets = detectedOffsets
				m.logger.Info("Network namespace offsets detected successfully, strict mode enabled")
			}
		}
	}

	// Load pre-compiled BPF programs
	spec, err := loadNetwork()
	if err != nil {
		return fmt.Errorf("loading BPF spec: %w", err)
	}

	// Set kernel version explicitly on all program specs to avoid vDSO detection
	// This is required for containers where vDSO might be disabled or unavailable
	// Kernel version format: (MAJOR << 16) | (MINOR << 8) | PATCH
	kernelVersion, err := m.getKernelVersionUint32()
	if err != nil {
		m.logger.Warn("Failed to get kernel version, will use auto-detection", zap.Error(err))
	} else {
		m.logger.Info("Setting kernel version on program specs",
			zap.Uint32("kernel_version", kernelVersion))
		for name, progSpec := range spec.Programs {
			progSpec.KernelVersion = kernelVersion
			m.logger.Debug("Set kernel version for program",
				zap.String("program", name),
				zap.Uint32("version", kernelVersion))
		}
	}

	// Create collection from spec
	// BTF is auto-detected from the running kernel (not from host)
	// We only set the kernel version explicitly to avoid vDSO detection issues
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: config.BPFVerifierLogLevel, // Info level - shows program loading details
			LogSize:  config.BPFVerifierLogSize,  // 64KB buffer for verifier logs
			// KernelTypes is not set - let cilium/ebpf auto-detect BTF from the running kernel
		},
	})
	if err != nil {
		return fmt.Errorf("creating BPF collection: %w", err)
	}
	m.collection = coll

	// Store map references
	// NOTE: "container_stats" (non-per-CPU) has been removed - only using per-CPU version
	m.containerStatsPerCPU = coll.Maps["container_stats_percpu"]
	m.socketToCgroup = coll.Maps["socket_to_cgroup"]
	m.connectionFlows = coll.Maps["connection_flows"] // Connection tracking map
	m.overflowRingbuf = coll.Maps["overflow_flows"]   // Overflow ringbuffer

	// Log actual loaded map sizes for debugging
	if m.connectionFlows != nil {
		info, err := m.connectionFlows.Info()
		if err != nil {
			m.logger.Warn("Failed to get connection_flows map info", zap.Error(err))
		} else {
			m.logger.Info("Loaded connection_flows map",
				zap.Uint32("max_entries", info.MaxEntries),
				zap.Uint32("key_size", info.KeySize),
				zap.Uint32("value_size", info.ValueSize),
				zap.String("type", info.Type.String()))
		}
	}

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

	// Initialize host network namespace filtering
	// This MUST be called after BPF programs are loaded so the maps exist
	if err := m.InitializeHostNetnsMap(filterMode); err != nil {
		// Log warning but don't fail - BPF will use default mode (cgroup check)
		m.logger.Warn("Failed to initialize network namespace filtering",
			zap.Error(err),
			zap.String("filter_mode", filterMode))
	}

	// Initialize offset configuration if strict mode with valid offsets
	if filterMode == "strict" && offsets != nil {
		if err := m.InitializeOffsetConfig(offsets); err != nil {
			m.logger.Warn("Failed to initialize offset configuration, strict mode may not work",
				zap.Error(err))
		}
	}

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

	prog = coll.Programs["trace_tcp_close"]
	if prog == nil {
		return fmt.Errorf("trace_tcp_close program not found")
	}
	l, err = link.Kprobe("tcp_close", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching tcp_close kprobe: %w", err)
	}
	m.links = append(m.links, l)

	// UDP destroy - deletes UDP "connection" entry on socket destruction
	prog = coll.Programs["trace_udp_destroy_sock"]
	if prog == nil {
		return fmt.Errorf("trace_udp_destroy_sock program not found")
	}
	l, err = link.Kprobe("udp_destroy_sock", prog, nil)
	if err != nil {
		return fmt.Errorf("attaching udp_destroy_sock kprobe: %w", err)
	}
	m.links = append(m.links, l)

	m.logger.Debug("Attached connection tracking probes (including close/destroy handlers)")

	return nil
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

// GetOverflowRingbuf returns the overflow ringbuffer
func (m *Manager) GetOverflowRingbuf() *ebpf.Map {
	return m.overflowRingbuf
}

// StartRingbufReader starts reading overflow flow records from the ringbuffer
// The handler callback is called for each flow record read from the ringbuffer
func (m *Manager) StartRingbufReader(ctx context.Context, handler func(*FlowRecord)) error {
	if m.overflowRingbuf == nil {
		return fmt.Errorf("overflow ringbuffer not initialized")
	}

	// Create ringbuffer reader using ringbuf package
	reader, err := ringbuf.NewReader(m.overflowRingbuf)
	if err != nil {
		return fmt.Errorf("creating ringbuffer reader: %w", err)
	}
	defer func() {
		// Always close reader on function exit
		if err := reader.Close(); err != nil {
			m.logger.Error("Error closing ringbuffer reader", zap.Error(err))
		}
	}()

	m.logger.Info("Starting overflow ringbuffer reader")

	// Read loop
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Stopping overflow ringbuffer reader")
			return nil
		default:
			// Read next record from ringbuffer (blocks until data available)
			record, err := reader.Read()
			if err != nil {
				m.logger.Error("Error reading from ringbuffer", zap.Error(err))
				continue
			}

			// Parse flow record from raw bytes
			if len(record.RawSample) < int(unsafe.Sizeof(FlowRecord{})) {
				m.logger.Warn("Invalid flow record size",
					zap.Int("got", len(record.RawSample)),
					zap.Int("expected", int(unsafe.Sizeof(FlowRecord{}))))
				continue
			}

			// Cast bytes to FlowRecord struct
			flowRecord := (*FlowRecord)(unsafe.Pointer(&record.RawSample[0]))

			// Call handler with the flow record
			handler(flowRecord)
		}
	}
}

// DumpMaps dumps all BPF maps for debugging
// This is useful for e2e tests to verify data collection before deletion
func (m *Manager) DumpMaps() (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Dump connection_flows map (actual connection data)
	if m.connectionFlows != nil {
		info, _ := m.connectionFlows.Info()
		if info != nil {
			result["connection_flows_info"] = map[string]interface{}{
				"type":        info.Type.String(),
				"max_entries": info.MaxEntries,
				"key_size":    info.KeySize,
				"value_size":  info.ValueSize,
			}
		}

		// Dump actual connection entries (useful for debugging)
		connections := make([]map[string]interface{}, 0)
		iter := m.connectionFlows.Iterate()
		var key ConnectionKey
		var stats ConnectionStats
		count := 0

		for iter.Next(&key, &stats) {
			count++
			// Limit output to first 10 connections to avoid log spam
			if count <= 10 {
				connections = append(connections, map[string]interface{}{
					"src_port":         key.SrcPort,
					"dst_port":         key.DstPort,
					"protocol":         key.Protocol,
					"family":           key.Family,
					"bytes_sent":       stats.BytesSent,
					"bytes_received":   stats.BytesReceived,
					"packets_sent":     stats.PacketsSent,
					"packets_received": stats.PacketsReceived,
					"cgroup_id":        stats.CgroupID,
				})
			}
		}

		result["connection_flows_entries"] = connections
		result["connection_flows_count"] = count

		if err := iter.Err(); err != nil {
			m.logger.Warn("Error iterating connection_flows map", zap.Error(err))
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
type ConnectionStats struct {
	BytesSent       uint64 // Total bytes sent
	BytesReceived   uint64 // Total bytes received
	PacketsSent     uint64 // Total packets sent
	PacketsReceived uint64 // Total packets received
	LastSeenNs      uint64 // Last activity timestamp
	CgroupID        uint64 // Container cgroup ID
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
