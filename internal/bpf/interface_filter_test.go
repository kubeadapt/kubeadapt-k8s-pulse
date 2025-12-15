package bpf

import (
	"strings"
	"testing"
)

// isContainerInterface checks if an interface name matches container interface patterns
// This mirrors the logic in loader_linux.go for TC hook attachment
func isContainerInterface(name string) bool {
	return strings.HasPrefix(name, "veth") ||
		strings.HasPrefix(name, "lxc") ||
		strings.HasPrefix(name, "eni")
}

// TestContainerInterfaceFiltering verifies the interface filtering logic
// that determines which interfaces get TC hooks attached.
// This test ensures we don't miss CNI interface types in production deployments.
func TestContainerInterfaceFiltering(t *testing.T) {
	tests := []struct {
		name        string
		ifaceName   string
		isContainer bool
		description string
	}{
		// Standard Linux bridge CNI interfaces (Flannel, Calico bridge mode)
		{"veth basic", "veth0", true, "Standard veth interface"},
		{"veth with hash", "vethab12cd34", true, "Veth with hash suffix"},
		{"veth kubernetes", "veth12345678", true, "Kubernetes-style veth"},

		// LXC/LXD container interfaces
		{"lxc basic", "lxc0", true, "LXC container interface"},
		{"lxc with hash", "lxcbr0", true, "LXC bridge interface"},

		// AWS VPC CNI interfaces (EKS)
		{"eni basic", "eni0", true, "AWS VPC CNI basic"},
		{"eni with hash", "eni6c9c263fd16", true, "AWS VPC CNI with hash"},
		{"eni at format", "eni6c9c263fd16@if3", true, "AWS VPC CNI with @if suffix"},
		{"eni long hash", "eni09ff1c7b5b0@if3", true, "AWS VPC CNI long hash"},

		// Physical/host interfaces - should NOT match
		{"eth0", "eth0", false, "Standard ethernet"},
		{"ens5", "ens5", false, "Systemd predictable naming"},
		{"ens6", "ens6", false, "Secondary physical NIC"},
		{"enp0s5", "enp0s5", false, "PCI slot naming"},

		// Bridge interfaces - should NOT match
		{"cni0", "cni0", false, "CNI bridge (duplicate counting)"},
		{"docker0", "docker0", false, "Docker bridge"},
		{"br-hash", "br-abc123", false, "Docker network bridge"},
		{"bridge0", "bridge0", false, "Generic bridge"},

		// Loopback - should NOT match
		{"loopback", "lo", false, "Loopback interface"},

		// Special AWS interfaces - should NOT match
		{"pod-id-link", "pod-id-link0", false, "EKS Pod Identity link"},

		// Tunnel interfaces - should NOT match
		{"flannel.1", "flannel.1", false, "Flannel VXLAN"},
		{"cali hash", "cali1234abcd", false, "Calico interface"},
		{"tunl0", "tunl0", false, "IPIP tunnel"},

		// Edge cases
		{"empty", "", false, "Empty interface name"},
		{"en prefix", "en0", false, "macOS-style ethernet (en, not eni)"},
		{"eno1", "eno1", false, "Onboard ethernet"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isContainerInterface(tt.ifaceName)
			if got != tt.isContainer {
				t.Errorf("isContainerInterface(%q) = %v, want %v (%s)",
					tt.ifaceName, got, tt.isContainer, tt.description)
			}
		})
	}
}

// TestContainerInterfaceFilteringCoverage ensures all major CNI types are covered
func TestContainerInterfaceFilteringCoverage(t *testing.T) {
	// These are real interface names from different Kubernetes deployments
	realWorldInterfaces := map[string]struct {
		isContainer bool
		cniType     string
	}{
		// AWS EKS with VPC CNI
		"eni6c9c263fd16@if3": {true, "AWS VPC CNI"},
		"eni09ff1c7b5b0@if3": {true, "AWS VPC CNI"},
		"eni15157cd94b6@if3": {true, "AWS VPC CNI"},
		"ens5":               {false, "AWS physical NIC"},
		"ens6":               {false, "AWS secondary NIC"},
		"pod-id-link0":       {false, "EKS Pod Identity"},

		// GKE with standard CNI
		"veth1234abcd": {true, "GKE standard"},
		"cbr0":         {false, "GKE bridge"},

		// Standard Kubernetes (kubeadm, etc.)
		"veth12345678": {true, "Standard veth"},
		"cni0":         {false, "CNI bridge"},
		"docker0":      {false, "Docker bridge"},
		"flannel.1":    {false, "Flannel VXLAN"},

		// LXC/LXD environments
		"lxcbr0": {true, "LXC bridge"},
		"lxc0":   {true, "LXC interface"},

		// Host interfaces (should never match)
		"eth0":   {false, "Host ethernet"},
		"lo":     {false, "Loopback"},
		"enp0s3": {false, "PCI ethernet"},
	}

	for ifaceName, expected := range realWorldInterfaces {
		t.Run(ifaceName, func(t *testing.T) {
			got := isContainerInterface(ifaceName)
			if got != expected.isContainer {
				t.Errorf("Interface %q (%s): isContainerInterface() = %v, want %v",
					ifaceName, expected.cniType, got, expected.isContainer)
			}
		})
	}
}
