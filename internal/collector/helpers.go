package collector

import "fmt"

// protocolToString converts protocol number to string
func protocolToString(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("unknown(%d)", protocol)
	}
}
