package unit

import (
	"net"
	"testing"

	"github.com/kubeadapt/ebpf-agent/internal/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPClassifier_IsPrivateIP(t *testing.T) {
	classifier := network.NewIPClassifier()

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Private ranges
		{"Private 10.x", "10.0.0.1", true},
		{"Private 10.x end", "10.255.255.255", true},
		{"Private 172.16.x", "172.16.0.1", true},
		{"Private 172.31.x", "172.31.255.255", true},
		{"Private 192.168.x", "192.168.1.1", true},
		{"Private 192.168.x end", "192.168.255.255", true},
		{"Carrier Grade NAT", "100.64.0.1", true},
		{"Carrier Grade NAT end", "100.127.255.255", true},
		{"Localhost", "127.0.0.1", true},
		{"Localhost range", "127.0.0.255", true},
		{"Link-local", "169.254.0.1", true},
		{"Link-local end", "169.254.255.255", true},

		// Public IPs
		{"Public Google DNS", "8.8.8.8", false},
		{"Public Cloudflare DNS", "1.1.1.1", false},
		{"Public AWS", "54.239.28.85", false},
		{"Public Azure", "40.112.72.205", false},
		{"Public GCP", "35.235.240.1", false},

		// Edge cases
		{"Just before 10.x", "9.255.255.255", false},
		{"Just after 10.x", "11.0.0.0", false},
		{"Just before 172.16", "172.15.255.255", false},
		{"Just after 172.31", "172.32.0.0", false},
		{"Just before 192.168", "192.167.255.255", false},
		{"Just after 192.168", "192.169.0.0", false},

		// Invalid IPs
		{"Empty string", "", false},
		{"Invalid IP", "not.an.ip", false},
		{"IPv6", "2001:db8::1", false}, // IPv6 not supported yet
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := classifier.IsPrivateIP(ip)
			assert.Equal(t, tt.expected, result, "IP: %s", tt.ip)
		})
	}
}

func TestIPClassifier_ClassifyTraffic(t *testing.T) {
	classifier := network.NewIPClassifier()

	tests := []struct {
		name     string
		srcIP    string
		dstIP    string
		srcZone  string
		dstZone  string
		expected network.TrafficType
	}{
		// Same zone traffic
		{
			name:     "Same zone private IPs",
			srcIP:    "10.0.1.1",
			dstIP:    "10.0.1.2",
			srcZone:  "us-east-1a",
			dstZone:  "us-east-1a",
			expected: network.TrafficTypeInternal,
		},
		// Cross-AZ traffic
		{
			name:     "Cross-AZ private IPs",
			srcIP:    "10.0.1.1",
			dstIP:    "10.0.2.1",
			srcZone:  "us-east-1a",
			dstZone:  "us-east-1b",
			expected: network.TrafficTypeCrossAZ,
		},
		// External egress
		{
			name:     "External egress to public IP",
			srcIP:    "10.0.1.1",
			dstIP:    "8.8.8.8",
			srcZone:  "us-east-1a",
			dstZone:  "external",
			expected: network.TrafficTypeExternal,
		},
		// External ingress (treated as external)
		{
			name:     "External ingress from public IP",
			srcIP:    "8.8.8.8",
			dstIP:    "10.0.1.1",
			srcZone:  "external",
			dstZone:  "us-east-1a",
			expected: network.TrafficTypeExternal,
		},
		// Unknown zones
		{
			name:     "Unknown source zone",
			srcIP:    "10.0.1.1",
			dstIP:    "10.0.2.1",
			srcZone:  "unknown",
			dstZone:  "us-east-1b",
			expected: network.TrafficTypeInternal,
		},
		{
			name:     "Both zones unknown",
			srcIP:    "10.0.1.1",
			dstIP:    "10.0.2.1",
			srcZone:  "unknown",
			dstZone:  "unknown",
			expected: network.TrafficTypeInternal,
		},
		{
			name:     "Empty zones",
			srcIP:    "10.0.1.1",
			dstIP:    "10.0.2.1",
			srcZone:  "",
			dstZone:  "",
			expected: network.TrafficTypeInternal,
		},
		// Invalid IPs
		{
			name:     "Invalid source IP",
			srcIP:    "not.an.ip",
			dstIP:    "10.0.1.1",
			srcZone:  "us-east-1a",
			dstZone:  "us-east-1a",
			expected: network.TrafficTypeUnknown,
		},
		{
			name:     "Invalid destination IP",
			srcIP:    "10.0.1.1",
			dstIP:    "not.an.ip",
			srcZone:  "us-east-1a",
			dstZone:  "us-east-1a",
			expected: network.TrafficTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcIP := net.ParseIP(tt.srcIP)
			dstIP := net.ParseIP(tt.dstIP)
			result := classifier.ClassifyTraffic(srcIP, dstIP, tt.srcZone, tt.dstZone)
			assert.Equal(t, tt.expected, result,
				"srcIP: %s, dstIP: %s, srcZone: %s, dstZone: %s",
				tt.srcIP, tt.dstIP, tt.srcZone, tt.dstZone)
		})
	}
}

func TestTrafficCostCalculation(t *testing.T) {
	tests := []struct {
		name         string
		trafficType  network.TrafficType
		bytes        uint64
		expectedCost float64
	}{
		{
			name:         "Cross-AZ 1GB",
			trafficType:  network.TrafficTypeCrossAZ,
			bytes:        1024 * 1024 * 1024, // 1GB
			expectedCost: 0.01,                // $0.01 per GB
		},
		{
			name:         "Cross-AZ 100GB",
			trafficType:  network.TrafficTypeCrossAZ,
			bytes:        100 * 1024 * 1024 * 1024, // 100GB
			expectedCost: 1.0,                      // $1.00
		},
		{
			name:         "External egress 1GB",
			trafficType:  network.TrafficTypeExternal,
			bytes:        1024 * 1024 * 1024, // 1GB
			expectedCost: 0.09,                // $0.09 per GB
		},
		{
			name:         "External egress 100GB",
			trafficType:  network.TrafficTypeExternal,
			bytes:        100 * 1024 * 1024 * 1024, // 100GB
			expectedCost: 9.0,                      // $9.00
		},
		{
			name:         "Internal traffic 1TB",
			trafficType:  network.TrafficTypeInternal,
			bytes:        1024 * 1024 * 1024 * 1024, // 1TB
			expectedCost: 0.0,                       // No cost
		},
		{
			name:         "Unknown traffic",
			trafficType:  network.TrafficTypeUnknown,
			bytes:        1024 * 1024 * 1024,
			expectedCost: 0.0,
		},
		{
			name:         "Small amount",
			trafficType:  network.TrafficTypeCrossAZ,
			bytes:        1024 * 1024, // 1MB
			expectedCost: 0.00001,     // Very small cost
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := network.CalculateTrafficCost(tt.trafficType, tt.bytes)
			// Use approximate comparison for floating point
			assert.InDelta(t, tt.expectedCost, cost, 0.000001,
				"Traffic type: %s, Bytes: %d", tt.trafficType, tt.bytes)
		})
	}
}

func TestIPRangeClassifier(t *testing.T) {
	classifier := network.NewIPRangeClassifier()

	// Add custom ranges
	err := classifier.AddCustomRange("aws-vpc", "10.0.0.0/16")
	require.NoError(t, err)

	err = classifier.AddCustomRange("gcp-vpc", "10.1.0.0/16")
	require.NoError(t, err)

	err = classifier.AddCustomRange("azure-vpc", "10.2.0.0/16")
	require.NoError(t, err)

	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"AWS VPC IP", "10.0.1.1", "aws-vpc"},
		{"GCP VPC IP", "10.1.1.1", "gcp-vpc"},
		{"Azure VPC IP", "10.2.1.1", "azure-vpc"},
		{"Other private IP", "192.168.1.1", "private"},
		{"Public IP", "8.8.8.8", "public"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := classifier.GetIPClassification(ip)
			assert.Equal(t, tt.expected, result, "IP: %s", tt.ip)
		})
	}
}

func TestTrafficStats(t *testing.T) {
	stats := &network.TrafficStats{
		Type: network.TrafficTypeCrossAZ,
	}

	// Initial state
	assert.Equal(t, uint64(0), stats.GetTotalBytes())
	assert.Equal(t, uint64(0), stats.GetTotalPackets())
	assert.Equal(t, float64(0), stats.EstimatedCost)

	// Update stats
	stats.UpdateStats(1024*1024*1024, 512*1024*1024) // 1GB sent, 512MB received

	assert.Equal(t, uint64(1024*1024*1024), stats.BytesSent)
	assert.Equal(t, uint64(512*1024*1024), stats.BytesReceived)
	assert.Equal(t, uint64(1536*1024*1024), stats.GetTotalBytes())

	// Check cost calculation (1.5GB * $0.01/GB)
	assert.InDelta(t, 0.015, stats.EstimatedCost, 0.0001)

	// Add more traffic
	stats.UpdateStats(1024*1024*1024, 1024*1024*1024) // Another 1GB each direction

	assert.Equal(t, uint64(2*1024*1024*1024), stats.BytesSent)
	assert.Equal(t, uint64(1536*1024*1024), stats.BytesReceived)
	assert.InDelta(t, 0.035, stats.EstimatedCost, 0.0001) // 3.5GB total
}

func BenchmarkIPClassification(b *testing.B) {
	classifier := network.NewIPClassifier()
	ips := []string{
		"10.0.1.1",
		"192.168.1.1",
		"8.8.8.8",
		"172.16.0.1",
		"54.239.28.85",
		"100.64.0.1",
		"169.254.0.1",
		"127.0.0.1",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := ips[i%len(ips)]
		_ = classifier.IsPrivateIP(net.ParseIP(ip))
	}
}

func BenchmarkTrafficClassification(b *testing.B) {
	classifier := network.NewIPClassifier()

	testCases := []struct {
		srcIP   net.IP
		dstIP   net.IP
		srcZone string
		dstZone string
	}{
		{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.2"), "us-east-1a", "us-east-1a"},
		{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.2.1"), "us-east-1a", "us-east-1b"},
		{net.ParseIP("10.0.1.1"), net.ParseIP("8.8.8.8"), "us-east-1a", "external"},
		{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"), "us-west-2a", "us-west-2a"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tc := testCases[i%len(testCases)]
		_ = classifier.ClassifyTraffic(tc.srcIP, tc.dstIP, tc.srcZone, tc.dstZone)
	}
}