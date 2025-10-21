package system

import (
	"fmt"
	"net"
)

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Index int
	Name  string
	Flags net.Flags
}

// GetNetworkInterfaces returns all network interfaces on the system
func GetNetworkInterfaces() ([]NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("getting network interfaces: %w", err)
	}

	result := make([]NetworkInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		// Only include UP interfaces (skip DOWN interfaces)
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		result = append(result, NetworkInterface{
			Index: iface.Index,
			Name:  iface.Name,
			Flags: iface.Flags,
		})
	}

	return result, nil
}
