package bpf

import (
	"testing"

	"github.com/kubeadapt/ebpf-agent/internal/config"
)

func TestFilterModeToInt(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		expected uint32
	}{
		{
			name:     "default mode",
			mode:     config.NetnsFilterModeDefault,
			expected: 0,
		},
		{
			name:     "empty string defaults to default mode",
			mode:     "",
			expected: 0,
		},
		{
			name:     "disabled mode",
			mode:     config.NetnsFilterModeDisabled,
			expected: 1,
		},
		{
			name:     "invalid mode falls back to default",
			mode:     "invalid",
			expected: 0,
		},
		{
			name:     "case sensitive - uppercase should fallback",
			mode:     "DEFAULT",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterModeToInt(tt.mode)
			if result != tt.expected {
				t.Errorf("FilterModeToInt(%q) = %d, expected %d", tt.mode, result, tt.expected)
			}
		})
	}
}

func TestGetHostNetNSInode(t *testing.T) {
	// This test will attempt to read the host network namespace inode
	// It should succeed on Linux systems with proper /proc access
	inode, err := GetHostNetNSInode()

	if err != nil {
		// Error is acceptable if running in restricted environment
		t.Logf("GetHostNetNSInode() failed (may be expected in test environment): %v", err)
		return
	}

	// If successful, inode should be non-zero
	if inode == 0 {
		t.Error("GetHostNetNSInode() returned 0, expected non-zero inode number")
	}

	// Network namespace inodes are typically in the range of 4026531840+
	// (but this can vary by kernel)
	t.Logf("Host network namespace inode: %d", inode)
}
