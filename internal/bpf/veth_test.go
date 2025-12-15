//go:build linux

package bpf

import (
	"testing"

	"github.com/vishvananda/netlink"
)

// ensureTestVethExists creates a test veth pair if no veth interfaces exist.
// This is needed for tests that attach TC hooks, which require veth interfaces.
// Returns a cleanup function that removes the created veth pair.
func ensureTestVethExists(t *testing.T) func() {
	t.Helper()

	// Check if any veth interface already exists
	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("Failed to list network interfaces: %v", err)
	}

	for _, link := range links {
		name := link.Attrs().Name
		if len(name) >= 4 && name[:4] == "veth" {
			t.Logf("Found existing veth interface: %s", name)
			return func() {} // No cleanup needed
		}
		if len(name) >= 3 && name[:3] == "lxc" {
			t.Logf("Found existing lxc interface: %s", name)
			return func() {} // No cleanup needed
		}
	}

	// No veth found, create one for testing
	t.Log("No veth interface found, creating test veth pair...")
	return createTestVethPair(t)
}

// createTestVethPair creates a veth pair for testing TC hooks.
// Returns a cleanup function that removes the veth pair.
func createTestVethPair(t *testing.T) func() {
	t.Helper()

	hostName := "veth-bpf-host"
	peerName := "veth-bpf-peer"

	// Create veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostName,
		},
		PeerName: peerName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("Failed to create veth pair: %v", err)
	}

	// Get the created links
	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		netlink.LinkDel(veth)
		t.Fatalf("Failed to get host veth: %v", err)
	}

	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		netlink.LinkDel(veth)
		t.Fatalf("Failed to get peer veth: %v", err)
	}

	// Bring up both interfaces
	if err := netlink.LinkSetUp(hostLink); err != nil {
		netlink.LinkDel(veth)
		t.Fatalf("Failed to bring up host veth: %v", err)
	}

	if err := netlink.LinkSetUp(peerLink); err != nil {
		netlink.LinkDel(veth)
		t.Fatalf("Failed to bring up peer veth: %v", err)
	}

	t.Logf("Created test veth pair: %s <-> %s", hostName, peerName)

	// Return cleanup function
	return func() {
		if err := netlink.LinkDel(hostLink); err != nil {
			t.Logf("Warning: Failed to delete veth pair: %v", err)
		} else {
			t.Logf("Cleaned up test veth pair: %s", hostName)
		}
	}
}
