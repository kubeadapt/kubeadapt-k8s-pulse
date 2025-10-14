package network

import (
	"net"
)

// TrafficType represents the type of network traffic
type TrafficType string

const (
	// TrafficTypeInternal represents traffic within the same zone
	TrafficTypeInternal TrafficType = "internal"
	// TrafficTypeCrossAZ represents traffic between different zones
	TrafficTypeCrossAZ TrafficType = "cross_az"
	// TrafficTypeExternal represents traffic to external IPs
	TrafficTypeExternal TrafficType = "external"
	// TrafficTypeUnknown represents unclassified traffic
	TrafficTypeUnknown TrafficType = "unknown"
)

// IPClassifier classifies IP addresses and traffic types
type IPClassifier struct {
	privateRanges []*net.IPNet
}

// NewIPClassifier creates a new IP classifier
func NewIPClassifier() *IPClassifier {
	privateRanges := make([]*net.IPNet, 0, 6)

	// RFC1918 private ranges
	ranges := []string{
		"10.0.0.0/8",      // Class A private
		"172.16.0.0/12",   // Class B private
		"192.168.0.0/16",  // Class C private
		"100.64.0.0/10",   // Carrier Grade NAT (RFC6598)
		"127.0.0.0/8",     // Localhost
		"169.254.0.0/16",  // Link-local
	}

	for _, cidr := range ranges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// This should never happen with hardcoded CIDRs
			continue
		}
		privateRanges = append(privateRanges, ipNet)
	}

	return &IPClassifier{
		privateRanges: privateRanges,
	}
}

// IsPrivateIP checks if an IP address is in a private range
func (c *IPClassifier) IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Convert to IPv4
	ip = ip.To4()
	if ip == nil {
		// IPv6 not supported yet
		return false
	}

	// Check against all private ranges
	for _, cidr := range c.privateRanges {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// IsPrivateIPString checks if an IP address string is in a private range
func (c *IPClassifier) IsPrivateIPString(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return c.IsPrivateIP(ip)
}

// ClassifyTraffic determines the type of traffic based on IPs and zones
func (c *IPClassifier) ClassifyTraffic(srcIP, dstIP net.IP, srcZone, dstZone string) TrafficType {
	// Check if IPs are valid
	if srcIP == nil || dstIP == nil {
		return TrafficTypeUnknown
	}

	srcPrivate := c.IsPrivateIP(srcIP)
	dstPrivate := c.IsPrivateIP(dstIP)

	// External traffic - destination is public IP
	if !dstPrivate {
		return TrafficTypeExternal
	}

	// Both are private IPs
	if srcPrivate && dstPrivate {
		// Check zones
		if srcZone == "" || dstZone == "" {
			// Unknown zones, but both private - assume internal
			return TrafficTypeInternal
		}

		if srcZone == "unknown" || dstZone == "unknown" {
			// Can't determine zone relationship
			return TrafficTypeInternal
		}

		if srcZone != dstZone {
			// Different zones - cross-AZ traffic
			return TrafficTypeCrossAZ
		}

		// Same zone - internal traffic
		return TrafficTypeInternal
	}

	// Source is public, destination is private (ingress)
	// We classify this as external for cost tracking purposes
	if !srcPrivate && dstPrivate {
		return TrafficTypeExternal
	}

	return TrafficTypeUnknown
}

// ClassifyTrafficByStrings is a convenience method that takes string IPs
func (c *IPClassifier) ClassifyTrafficByStrings(srcIPStr, dstIPStr, srcZone, dstZone string) TrafficType {
	srcIP := net.ParseIP(srcIPStr)
	dstIP := net.ParseIP(dstIPStr)
	return c.ClassifyTraffic(srcIP, dstIP, srcZone, dstZone)
}

// GetTrafficCostPerGB returns the cost per GB for a traffic type (in dollars)
func GetTrafficCostPerGB(trafficType TrafficType) float64 {
	switch trafficType {
	case TrafficTypeCrossAZ:
		return 0.01 // $0.01 per GB for cross-AZ traffic
	case TrafficTypeExternal:
		return 0.09 // $0.09 per GB for external egress
	case TrafficTypeInternal:
		return 0.0 // No cost for same-zone traffic
	default:
		return 0.0
	}
}

// CalculateTrafficCost calculates the cost for a given amount of traffic
func CalculateTrafficCost(trafficType TrafficType, bytes uint64) float64 {
	// Convert bytes to GB
	gb := float64(bytes) / (1024 * 1024 * 1024)

	// Get cost per GB
	costPerGB := GetTrafficCostPerGB(trafficType)

	// Calculate total cost
	return gb * costPerGB
}

// IPRangeClassifier provides more detailed IP classification
type IPRangeClassifier struct {
	*IPClassifier
	customRanges map[string][]*net.IPNet // Custom ranges for specific classifications
}

// NewIPRangeClassifier creates a classifier with custom ranges
func NewIPRangeClassifier() *IPRangeClassifier {
	return &IPRangeClassifier{
		IPClassifier: NewIPClassifier(),
		customRanges: make(map[string][]*net.IPNet),
	}
}

// AddCustomRange adds a custom IP range with a label
func (c *IPRangeClassifier) AddCustomRange(label string, cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	if c.customRanges[label] == nil {
		c.customRanges[label] = make([]*net.IPNet, 0)
	}
	c.customRanges[label] = append(c.customRanges[label], ipNet)

	return nil
}

// GetIPClassification returns the classification label for an IP
func (c *IPRangeClassifier) GetIPClassification(ip net.IP) string {
	// Check custom ranges first
	for label, ranges := range c.customRanges {
		for _, cidr := range ranges {
			if cidr.Contains(ip) {
				return label
			}
		}
	}

	// Check standard private ranges
	if c.IsPrivateIP(ip) {
		return "private"
	}

	return "public"
}

// TrafficStats holds statistics for a specific traffic type
type TrafficStats struct {
	Type            TrafficType
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	EstimatedCost   float64
	ConnectionCount int
}

// UpdateStats updates the traffic statistics
func (ts *TrafficStats) UpdateStats(bytesSent, bytesReceived uint64) {
	ts.BytesSent += bytesSent
	ts.BytesReceived += bytesReceived
	ts.EstimatedCost = CalculateTrafficCost(ts.Type, ts.BytesSent+ts.BytesReceived)
}

// GetTotalBytes returns the total bytes for this traffic type
func (ts *TrafficStats) GetTotalBytes() uint64 {
	return ts.BytesSent + ts.BytesReceived
}

// GetTotalPackets returns the total packets for this traffic type
func (ts *TrafficStats) GetTotalPackets() uint64 {
	return ts.PacketsSent + ts.PacketsReceived
}