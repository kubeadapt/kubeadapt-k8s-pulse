//go:build linux

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
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

// NOTE: go:generate directive REMOVED - use generate.go instead
// BPF compilation is handled by internal/bpf/generate.go to avoid duplicate compilation
// To regenerate BPF: run `make generate` (not `go generate`)

// tcFilter holds information needed for TC filter cleanup
type tcFilter struct {
	link      netlink.Link
	filter    *netlink.BpfFilter
	isIngress bool
}

// Manager handles eBPF program lifecycle
type Manager struct {
	collection *ebpf.Collection
	links      []link.Link
	tcFilters  []tcFilter // TC filters for cleanup (classic TC)
	logger     *zap.Logger

	// Maps for easy access
	// TC implementation uses connection_flows for tracking, overflow_events for overflow events,
	// and global_counters for observability. Network namespace filtering uses filter_mode_map.
	connectionFlows *ebpf.Map // Connection tracking map
	overflowRingbuf *ebpf.Map // Overflow ringbuffer for flow records
	globalCounters  *ebpf.Map // eBPF observability counters
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
			LogLevel:     config.BPFVerifierLogLevel, // Info level - shows program loading details
			LogSizeStart: config.BPFVerifierLogSize,  // 64KB starting buffer for verifier logs
			// KernelTypes is not set - let cilium/ebpf auto-detect BTF from the running kernel
		},
	})
	if err != nil {
		return fmt.Errorf("creating BPF collection: %w", err)
	}
	m.collection = coll

	// Store map references for TC eBPF implementation
	m.connectionFlows = coll.Maps["connection_flows"] // Connection tracking map
	m.overflowRingbuf = coll.Maps["overflow_events"]  // Overflow ringbuffer for flow records
	m.globalCounters = coll.Maps["global_counters"]   // eBPF observability counters

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

	// Attach TC hooks for network monitoring
	if err := m.attachTCHooks(coll); err != nil {
		return fmt.Errorf("attaching TC hooks: %w", err)
	}

	m.logger.Info("TC BPF programs attached successfully",
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

	return nil
}

// attachTCHooks attaches classic TC (Traffic Control) hooks to network interfaces
// EGRESS-ONLY: Only attaches egress hooks to prevent double-counting
// Cross-node and same-node deduplication handled automatically by egress-only capture
// Note: This uses the classic TC attachment method compatible with SEC("classifier/egress")
func (m *Manager) attachTCHooks(coll *ebpf.Collection) error {
	// Get egress program (ingress removed - egress-only tracking)
	egressProg := coll.Programs["tc_egress"]
	if egressProg == nil {
		return fmt.Errorf("tc_egress program not found")
	}

	// Get all network interfaces
	interfaces, err := system.GetNetworkInterfaces()
	if err != nil {
		return fmt.Errorf("getting network interfaces: %w", err)
	}

	m.logger.Info("Attaching TC hooks to network interfaces",
		zap.Int("interface_count", len(interfaces)))

	// Attach to each interface
	for _, iface := range interfaces {
		// Skip loopback interface
		if iface.Name == "lo" {
			m.logger.Debug("Skipping loopback interface", zap.String("interface", iface.Name))
			continue
		}

		// Get netlink.Link for the interface
		link, err := netlink.LinkByIndex(iface.Index)
		if err != nil {
			m.logger.Warn("Failed to get netlink link",
				zap.String("interface", iface.Name),
				zap.Int("index", iface.Index),
				zap.Error(err))
			continue
		}

		// Ensure clsact qdisc exists on the interface
		// clsact is a special qdisc that provides both ingress and egress hooks
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: iface.Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}

		// Use QdiscReplace for idempotent qdisc setup (creates if not exists, replaces if exists)
		// This is cleaner than QdiscAdd + EEXIST handling and matches TC filter pattern
		if err := netlink.QdiscReplace(qdisc); err != nil {
			m.logger.Warn("Failed to setup clsact qdisc",
				zap.String("interface", iface.Name),
				zap.Error(err))
			continue
		}
		m.logger.Debug("Clsact qdisc configured",
			zap.String("interface", iface.Name))

		// Attach egress filter ONLY (no ingress - prevents double-counting)
		egressFilter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: iface.Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    1,
				Protocol:  3, // ETH_P_ALL
				Priority:  1,
			},
			Fd:           egressProg.FD(),
			Name:         "tc_egress",
			DirectAction: true,
		}

		// Use FilterReplace to atomically replace existing filters from crashed pods
		// This prevents stale BPF programs from previous runs from remaining attached
		if err := netlink.FilterReplace(egressFilter); err != nil {
			m.logger.Warn("Failed to attach TC egress filter",
				zap.String("interface", iface.Name),
				zap.Error(err))
			continue
		}

		m.tcFilters = append(m.tcFilters, tcFilter{
			link:      link,
			filter:    egressFilter,
			isIngress: false,
		})

		m.logger.Debug("Attached TC egress filter to interface",
			zap.String("interface", iface.Name),
			zap.Int("index", iface.Index))
	}

	if len(m.tcFilters) == 0 {
		return fmt.Errorf("failed to attach TC hooks to any network interface")
	}

	m.logger.Info("TC hooks attached successfully",
		zap.Int("total_filters", len(m.tcFilters)))

	return nil
}

// GetConnectionMap returns the connection flows map
func (m *Manager) GetConnectionMap() *ebpf.Map {
	return m.connectionFlows
}

// GetOverflowRingbuf returns the overflow ringbuffer
func (m *Manager) GetOverflowRingbuf() *ebpf.Map {
	return m.overflowRingbuf
}

// GetGlobalCounters returns the global counters map for observability
func (m *Manager) GetGlobalCounters() *ebpf.Map {
	return m.globalCounters
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

	// IMPORTANT: handler() is called synchronously in the read loop.
	// Ring buffer reading will BLOCK if handler takes too long.
	// Keep handler lightweight to prevent overflow loss.
	//
	// This synchronous design is optimal for OVERFLOW events (rare).

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
					"src_port":  key.SrcPort,
					"dst_port":  key.DstPort,
					"protocol":  key.Protocol,
					"family":    key.Family,
					"bytes":     stats.Bytes,
					"packets":   stats.Packets,
					"cgroup_id": stats.CgroupID,
				})
			}
		}

		result["connection_flows_entries"] = connections
		result["connection_flows_count"] = count

		// Check for iteration errors
		// Note: cilium/ebpf returns "buffer too small" when iterating empty maps
		// This is expected behavior and should not be logged as a warning
		if err := iter.Err(); err != nil {
			// Only log if map is NOT empty (count > 0)
			// Empty map iteration error is expected and harmless
			if count > 0 {
				m.logger.Warn("Error iterating connection_flows map", zap.Error(err))
			}
		}
	}

	return result, nil
}

// Close cleans up all BPF resources
func (m *Manager) Close() error {
	m.logger.Info("Cleaning up BPF resources")

	// Close all TC filters (classic TC)
	for _, tcf := range m.tcFilters {
		if err := netlink.FilterDel(tcf.filter); err != nil {
			direction := "egress"
			if tcf.isIngress {
				direction = "ingress"
			}
			m.logger.Warn("Error deleting TC filter",
				zap.String("interface", tcf.link.Attrs().Name),
				zap.String("direction", direction),
				zap.Error(err))
		}
	}
	m.tcFilters = nil

	// Close all links (other types)
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
