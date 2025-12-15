package collector

import "fmt"

// IANA Protocol Numbers
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
const (
	ProtoICMP   = 1  // Internet Control Message Protocol
	ProtoTCP    = 6  // Transmission Control Protocol
	ProtoUDP    = 17 // User Datagram Protocol
	ProtoICMPv6 = 58 // ICMP for IPv6
)

// protocolToString converts protocol number to string
func protocolToString(protocol uint8) string {
	switch protocol {
	case ProtoICMP:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv6:
		return "icmpv6"
	default:
		return fmt.Sprintf("unknown(%d)", protocol)
	}
}
