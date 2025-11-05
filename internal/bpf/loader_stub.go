//go:build !linux

package bpf

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// Manager is a stub for non-Linux platforms
// The actual implementation is in loader_linux.go
type Manager struct {
	_ *zap.Logger // unused, just for interface compatibility
}

// NewManager returns an error on non-Linux platforms
func NewManager(logger *zap.Logger) (*Manager, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}

// LoadAndAttach returns an error on non-Linux platforms
func (m *Manager) LoadAndAttach(filterMode string) error {
	return fmt.Errorf("eBPF is only supported on Linux")
}

// GetConnectionMap returns nil on non-Linux platforms
func (m *Manager) GetConnectionMap() *ebpf.Map {
	return nil
}

// GetOverflowRingbuf returns nil on non-Linux platforms
func (m *Manager) GetOverflowRingbuf() *ebpf.Map {
	return nil
}

// GetGlobalCounters returns nil on non-Linux platforms
func (m *Manager) GetGlobalCounters() *ebpf.Map {
	return nil
}

// StartRingbufReader returns an error on non-Linux platforms
func (m *Manager) StartRingbufReader(ctx context.Context, handler func(*FlowRecord)) error {
	return fmt.Errorf("eBPF is only supported on Linux")
}

// DumpMaps returns an error on non-Linux platforms
func (m *Manager) DumpMaps() (map[string]interface{}, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}

// Close does nothing on non-Linux platforms
func (m *Manager) Close() error {
	return nil
}

// InitializeHostNetnsMap returns an error on non-Linux platforms
func (m *Manager) InitializeHostNetnsMap(filterMode string) error {
	return fmt.Errorf("eBPF is only supported on Linux")
}
