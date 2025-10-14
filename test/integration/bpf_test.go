// +build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kubeadapt/ebpf-agent/internal/bpf"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// TestBPFManagerLoadAndAttach tests loading and attaching BPF programs
// This test requires root or CAP_BPF capabilities
func TestBPFManagerLoadAndAttach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	logger := zaptest.NewLogger(t)

	// Create BPF manager
	manager, err := bpf.NewManager(logger)
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Errorf("Failed to close BPF manager: %v", err)
		}
	}()

	// Load and attach BPF programs
	if err := manager.LoadAndAttach(); err != nil {
		t.Fatalf("Failed to load and attach BPF programs: %v", err)
	}

	// Give some time for the programs to collect data
	time.Sleep(2 * time.Second)

	// Check if we can retrieve stats map
	statsMap := manager.GetContainerStats()
	if statsMap == nil {
		t.Fatal("Stats map is nil")
	}

	// Try to iterate over the map (may be empty if no network activity)
	iter := statsMap.Iterate()
	var cgroupID uint64
	var stats bpf.ContainerNetStats

	hasEntries := false
	for iter.Next(&cgroupID, &stats) {
		hasEntries = true
		t.Logf("Found stats for cgroup %d: RX=%d bytes, TX=%d bytes",
			cgroupID, stats.RxBytes, stats.TxBytes)
	}

	if err := iter.Err(); err != nil {
		t.Errorf("Error iterating stats map: %v", err)
	}

	if !hasEntries {
		t.Log("No entries found in stats map (this is normal if no network activity)")
	}
}

// TestBPFManagerConcurrentAccess tests concurrent access to BPF maps
func TestBPFManagerConcurrentAccess(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	logger := zaptest.NewLogger(t)

	manager, err := bpf.NewManager(logger)
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer manager.Close()

	if err := manager.LoadAndAttach(); err != nil {
		t.Fatalf("Failed to load and attach BPF programs: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start multiple goroutines accessing the maps
	errChan := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					statsMap := manager.GetContainerStats()
					if statsMap == nil {
						errChan <- err
						return
					}

					// Try to iterate
					iter := statsMap.Iterate()
					var cgroupID uint64
					var stats bpf.ContainerNetStats

					for iter.Next(&cgroupID, &stats) {
						// Just iterate, don't need to do anything
					}

					if err := iter.Err(); err != nil {
						errChan <- err
						return
					}

					time.Sleep(100 * time.Millisecond)
				}
			}
		}(i)
	}

	// Wait for completion
	<-ctx.Done()

	// Check for errors
	select {
	case err := <-errChan:
		t.Fatalf("Concurrent access error: %v", err)
	default:
		// No errors
	}
}

// TestKernelCompatibility tests kernel compatibility checks
func TestKernelCompatibility(t *testing.T) {
	// Check BPF filesystem
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		t.Skip("BPF filesystem not mounted")
	}

	// Check for tracing support
	if _, err := os.Stat("/sys/kernel/debug/tracing"); os.IsNotExist(err) {
		t.Log("Warning: Tracing not available at /sys/kernel/debug/tracing")
	}

	// Try to create a simple BPF map to test BPF support
	logger := zaptest.NewLogger(t)
	manager, err := bpf.NewManager(logger)
	if err != nil {
		if os.Getuid() != 0 {
			t.Skip("Cannot test BPF support without root privileges")
		}
		t.Fatalf("Kernel may not support required BPF features: %v", err)
	}
	manager.Close()

	t.Log("Kernel compatibility check passed")
}