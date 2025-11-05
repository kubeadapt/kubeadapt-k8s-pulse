//go:build linux

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
//   - 1 for "disabled" (no filtering, track everything)
func FilterModeToInt(mode string) uint32 {
	switch mode {
	case config.NetnsFilterModeDefault, "":
		return 0 // default mode
	case config.NetnsFilterModeDisabled:
		return 1 // disabled mode
	default:
		return 0 // fallback to default
	}
}

// InitializeHostNetnsMap populates the filter_mode_map
// This configures the BPF program's network namespace filtering behavior
//
// IMPORTANT: This must be called AFTER LoadAndAttach() so that the BPF maps are initialized
//
// How it works:
// 1. Populate filter_mode_map with the configured mode (default/disabled)
// 2. BPF programs use filter mode to decide filtering strategy
//
// Filtering modes:
//   - default:  Track all K8s pods (cgroup check), filter only host processes
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

	// Populate filter mode map
	key := uint32(0)
	modeValue := FilterModeToInt(filterMode)

	if err := filterModeMap.Put(&key, &modeValue); err != nil {
		return fmt.Errorf("failed to populate filter_mode_map: %w", err)
	}

	m.logger.Info("Initialized network namespace filtering",
		zap.String("mode", filterMode),
		zap.Uint32("mode_value", modeValue))

	return nil
}
