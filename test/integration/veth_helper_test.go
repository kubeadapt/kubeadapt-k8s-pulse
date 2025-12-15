//go:build integration
// +build integration

package integration

import (
	"fmt"
	"testing"

	"github.com/vishvananda/netlink"
)

// VethPair holds the veth pair links for cleanup
type VethPair struct {
	Host netlink.Link
	Peer netlink.Link
}

// CreateTestVethPair creates a veth pair for testing TC hooks
// This simulates the pod veth interface that would exist in a real Kubernetes environment
// Returns the veth pair and a cleanup function
func CreateTestVethPair(t *testing.T) (*VethPair, func()) {
	t.Helper()

	hostName := "veth-test-host"
	peerName := "veth-test-peer"

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
	cleanup := func() {
		if err := netlink.LinkDel(hostLink); err != nil {
			t.Logf("Warning: Failed to delete veth pair: %v", err)
		} else {
			t.Logf("Cleaned up test veth pair: %s", hostName)
		}
	}

	return &VethPair{
		Host: hostLink,
		Peer: peerLink,
	}, cleanup
}

// EnsureTestVethExists creates a test veth pair if no container interfaces exist
// This is useful for running integration tests in environments without Kubernetes
// Supported interface prefixes: veth (standard CNI), lxc (LXC/LXD), eni (AWS VPC CNI)
func EnsureTestVethExists(t *testing.T) func() {
	t.Helper()

	// Check if any container interface already exists
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
		if len(name) >= 3 && name[:3] == "eni" {
			t.Logf("Found existing eni interface (AWS VPC CNI): %s", name)
			return func() {} // No cleanup needed
		}
	}

	// No container interface found, create one for testing
	t.Log("No container interface found (veth/lxc/eni), creating test veth pair...")
	_, cleanup := CreateTestVethPair(t)
	return cleanup
}

// ListContainerInterfaces returns all container interfaces (veth, lxc, eni)
func ListContainerInterfaces(t *testing.T) []string {
	t.Helper()

	links, err := netlink.LinkList()
	if err != nil {
		t.Fatalf("Failed to list network interfaces: %v", err)
	}

	var interfaces []string
	for _, link := range links {
		name := link.Attrs().Name
		if len(name) >= 4 && name[:4] == "veth" {
			interfaces = append(interfaces, name)
		}
		if len(name) >= 3 && name[:3] == "lxc" {
			interfaces = append(interfaces, name)
		}
		if len(name) >= 3 && name[:3] == "eni" {
			interfaces = append(interfaces, name)
		}
	}

	return interfaces
}

// ListVethInterfaces is an alias for ListContainerInterfaces for backward compatibility
func ListVethInterfaces(t *testing.T) []string {
	return ListContainerInterfaces(t)
}

// TestVethPairCreation tests that we can create veth pairs for testing
func TestVethPairCreation(t *testing.T) {
	veth, cleanup := CreateTestVethPair(t)
	defer cleanup()

	if veth.Host == nil {
		t.Fatal("Host veth is nil")
	}
	if veth.Peer == nil {
		t.Fatal("Peer veth is nil")
	}

	t.Logf("Host veth: %s (index %d)", veth.Host.Attrs().Name, veth.Host.Attrs().Index)
	t.Logf("Peer veth: %s (index %d)", veth.Peer.Attrs().Name, veth.Peer.Attrs().Index)

	// Verify interfaces are in the list
	veths := ListVethInterfaces(t)
	found := false
	for _, v := range veths {
		if v == "veth-test-host" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Created veth not found in interface list: %v", veths)
	}

	fmt.Printf("Test veth interfaces: %v\n", veths)
}
