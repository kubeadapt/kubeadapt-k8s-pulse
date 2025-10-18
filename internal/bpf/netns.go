package bpf

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/kubeadapt/ebpf-agent/internal/config"
)

// GetHostNetNSInode reads the host network namespace inode from /proc/1/ns/net
// This is used to distinguish between host processes and containerized processes
//
// Network namespace filtering logic:
// - Host processes (kubelet, containerd, sshd): share init process netns (pid 1)
// - Container/pod processes: have their own network namespaces
// - Reading /proc/1/ns/net gives us the host's network namespace inode number
//
// Returns:
//   - uint64: Host network namespace inode number (e.g., 4026531840)
//   - error: If reading or parsing fails
func GetHostNetNSInode() (uint64, error) {
	// Try /host/proc first (production DaemonSet mount)
	// Falls back to /proc (development or non-containerized)
	paths := []string{
		"/host/proc/1/ns/net", // Production: host /proc mounted at /host/proc
		"/proc/1/ns/net",      // Development: direct /proc access
	}

	var lastErr error
	for _, path := range paths {
		linkTarget, err := os.Readlink(path)
		if err != nil {
			lastErr = err
			continue
		}

		// Parse "net:[4026531840]" to extract inode number
		// Format: net:[<inode>]
		if !strings.HasPrefix(linkTarget, "net:[") {
			return 0, fmt.Errorf("unexpected netns symlink format: %s", linkTarget)
		}

		linkTarget = strings.TrimPrefix(linkTarget, "net:[")
		linkTarget = strings.TrimSuffix(linkTarget, "]")

		inode, err := strconv.ParseUint(linkTarget, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse netns inode from %s: %w", linkTarget, err)
		}

		return inode, nil
	}

	return 0, fmt.Errorf("failed to read host netns from any path: %w", lastErr)
}

// FilterModeToInt converts string filter mode to BPF map value
// Returns:
//   - 0 for "default"  (track all K8s pods, filter host processes)
//   - 1 for "strict"   (track only non-hostNetwork pods)
//   - 2 for "disabled" (no filtering, track everything)
func FilterModeToInt(mode string) uint32 {
	switch mode {
	case config.NetnsFilterModeDefault, "":
		return 0 // default mode
	case config.NetnsFilterModeStrict:
		return 1 // strict mode
	case config.NetnsFilterModeDisabled:
		return 2 // disabled mode
	default:
		return 0 // fallback to default
	}
}

// InitializeHostNetnsMap populates the host_netns_map and filter_mode_map
// This configures the BPF program's network namespace filtering behavior
//
// IMPORTANT: This must be called AFTER LoadAndAttach() so that the BPF maps are initialized
//
// How it works:
// 1. Populate filter_mode_map with the configured mode (default/strict/disabled)
// 2. If strict mode: populate host_netns_map with host netns inode
// 3. BPF programs use filter mode to decide filtering strategy
//
// Filtering modes:
//   - default:  Track all K8s pods (cgroup check), filter only host processes
//   - strict:   Track only non-hostNetwork pods (netns comparison)
//   - disabled: Track everything (no filtering)
func (m *Manager) InitializeHostNetnsMap(filterMode string) error {
	// Get the BPF maps from collection
	if m.collection == nil {
		return fmt.Errorf("BPF collection not initialized - call LoadAndAttach() first")
	}

	filterModeMap := m.collection.Maps["filter_mode_map"]
	if filterModeMap == nil {
		return fmt.Errorf("filter_mode_map not found in BPF collection")
	}

	hostNetnsMap := m.collection.Maps["host_netns_map"]
	if hostNetnsMap == nil {
		return fmt.Errorf("host_netns_map not found in BPF collection")
	}

	// Populate filter mode map
	key := uint32(0)
	modeValue := FilterModeToInt(filterMode)

	if err := filterModeMap.Put(&key, &modeValue); err != nil {
		return fmt.Errorf("failed to populate filter_mode_map: %w", err)
	}

	// If strict mode, populate host netns map for netns comparison
	// For default/disabled modes, this map is optional (not used)
	if filterMode == config.NetnsFilterModeStrict {
		hostNetnsInode, err := GetHostNetNSInode()
		if err != nil {
			return fmt.Errorf("failed to get host netns inode for strict mode: %w", err)
		}

		if err := hostNetnsMap.Put(&key, &hostNetnsInode); err != nil {
			return fmt.Errorf("failed to populate host_netns_map: %w", err)
		}

		m.logger.Info("Initialized network namespace filtering",
			zap.String("mode", filterMode),
			zap.Uint32("mode_value", modeValue),
			zap.Uint64("host_netns_inode", hostNetnsInode))
	} else {
		m.logger.Info("Initialized network namespace filtering",
			zap.String("mode", filterMode),
			zap.Uint32("mode_value", modeValue))
	}

	return nil
}

// InitializeOffsetConfig writes runtime-detected struct offsets to the BPF map
// This allows MODE 1 (strict) filtering to work without CO-RE compilation dependencies
//
// IMPORTANT: This must be called AFTER LoadAndAttach() so that the BPF maps are initialized
//
// Parameters:
//   - offsets: Network namespace offsets detected via BTF
//
// Returns:
//   - error: If writing to BPF map fails
func (m *Manager) InitializeOffsetConfig(offsets *NetnsOffsets) error {
	if m.collection == nil {
		return fmt.Errorf("BPF collection not initialized - call LoadAndAttach() first")
	}

	offsetConfigMap := m.collection.Maps["offset_config"]
	if offsetConfigMap == nil {
		return fmt.Errorf("offset_config map not found in BPF collection")
	}

	// Prepare offset configuration structure to match BPF map layout
	type offsetConfig struct {
		TaskNsproxy  uint32
		NsproxyNetNs uint32
		NetNsInum    uint32
	}

	config := offsetConfig{
		TaskNsproxy:  offsets.TaskNsproxy,
		NsproxyNetNs: offsets.NsproxyNetNs,
		NetNsInum:    offsets.NetNsInum,
	}

	// Write offsets to BPF map
	key := uint32(0)
	if err := offsetConfigMap.Put(&key, &config); err != nil {
		return fmt.Errorf("failed to populate offset_config map: %w", err)
	}

	m.logger.Info("Initialized network namespace offset configuration",
		zap.Uint32("task_nsproxy", config.TaskNsproxy),
		zap.Uint32("nsproxy_net_ns", config.NsproxyNetNs),
		zap.Uint32("net_ns_inum", config.NetNsInum))

	return nil
}
