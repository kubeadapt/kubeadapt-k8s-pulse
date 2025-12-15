//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kubeadapt/ebpf-agent/internal/bpf"
	"go.uber.org/zap/zaptest"
)

// TestBPFManagerLoadAndAttach tests loading and attaching BPF programs
// This test requires root or CAP_BPF capabilities
func TestBPFManagerLoadAndAttach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	// Ensure a veth interface exists for TC hook attachment
	cleanupVeth := EnsureTestVethExists(t)
	defer cleanupVeth()

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

	// Load and attach BPF programs (use "disabled" mode for tests to track all traffic)
	if err := manager.LoadAndAttach("disabled"); err != nil {
		t.Fatalf("Failed to load and attach BPF programs: %v", err)
	}

	// Give some time for the programs to collect data
	time.Sleep(2 * time.Second)

	// Check if we can retrieve connection map
	connMap := manager.GetConnectionMap()
	if connMap == nil {
		t.Fatal("Connection map is nil")
	}

	// Try to iterate over the map (may be empty if no network activity)
	iter := connMap.Iterate()
	var key bpf.ConnectionKey
	var stats bpf.ConnectionStats

	hasEntries := false
	for iter.Next(&key, &stats) {
		hasEntries = true
		t.Logf("Found connection: %v:%d -> %v:%d, Bytes=%d, Packets=%d",
			formatAddr(key.SrcAddr), key.SrcPort,
			formatAddr(key.DstAddr), key.DstPort,
			stats.Bytes, stats.Packets)
	}

	if err := iter.Err(); err != nil {
		t.Errorf("Error iterating connection map: %v", err)
	}

	if !hasEntries {
		t.Log("No entries found in connection map (this is normal if no network activity)")
	}
}

// TestBPFManagerConcurrentAccess tests concurrent access to BPF maps
func TestBPFManagerConcurrentAccess(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges")
	}

	cleanupVeth := EnsureTestVethExists(t)
	defer cleanupVeth()

	logger := zaptest.NewLogger(t)

	manager, err := bpf.NewManager(logger)
	if err != nil {
		t.Fatalf("Failed to create BPF manager: %v", err)
	}
	defer manager.Close()

	if err := manager.LoadAndAttach("disabled"); err != nil {
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
					connMap := manager.GetConnectionMap()
					if connMap == nil {
						errChan <- err
						return
					}

					// Try to iterate
					iter := connMap.Iterate()
					var key bpf.ConnectionKey
					var stats bpf.ConnectionStats

					for iter.Next(&key, &stats) {
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

// Helper function to format IP address from [4]uint32 array
func formatAddr(addr [4]uint32) string {
	// For IPv4 (only first uint32 is used)
	if addr[1] == 0 && addr[2] == 0 && addr[3] == 0 {
		// Convert network byte order to host byte order
		ip := addr[0]
		return formatIPv4(uint32(ip))
	}
	// For IPv6, format all 4 uint32s
	return formatIPv6(addr)
}

func formatIPv4(ip uint32) string {
	return formatUint32ToIPv4(ip)
}

func formatIPv6(addr [4]uint32) string {
	// Simplified IPv6 formatting
	return "ipv6_address"
}

func formatUint32ToIPv4(ip uint32) string {
	// Network byte order conversion
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}
