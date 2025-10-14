package unit

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"github.com/kubeadapt/ebpf-agent/internal/bpf"
)

// TestIPv4ToString validates IPv4 address conversion
func TestIPv4ToString(t *testing.T) {
	tests := []struct {
		name     string
		ip       uint32
		expected string
	}{
		{
			name:     "localhost",
			ip:       0x7f000001, // 127.0.0.1 in network byte order (big-endian)
			expected: "127.0.0.1",
		},
		{
			name:     "google dns",
			ip:       0x08080808, // 8.8.8.8 in network byte order
			expected: "8.8.8.8",
		},
		{
			name:     "private network",
			ip:       0x0a00000a, // 10.0.0.10 in network byte order
			expected: "10.0.0.10",
		},
		{
			name:     "zero address",
			ip:       0x00000000,
			expected: "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IPv4ToString(tt.ip)
			if result != tt.expected {
				t.Errorf("IPv4ToString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestIPv6ToString validates IPv6 address conversion
func TestIPv6ToString(t *testing.T) {
	tests := []struct {
		name     string
		ipv6     [4]uint32
		expected string
	}{
		{
			name:     "localhost",
			ipv6:     [4]uint32{0, 0, 0, 0x00000001}, // ::1 in network byte order (big-endian)
			expected: "::1",
		},
		{
			name:     "documentation prefix",
			ipv6:     [4]uint32{0x20010db8, 0, 0, 0x00000001}, // 2001:db8::1
			expected: "2001:db8::1",
		},
		{
			name:     "full address",
			ipv6:     [4]uint32{0x20010db8, 0x00008a2e, 0x03707334, 0x0a44a2b1}, // 2001:db8:0:8a2e:370:7334:a44:a2b1
			expected: "2001:db8:0:8a2e:370:7334:a44:a2b1",
		},
		{
			name:     "zero address",
			ipv6:     [4]uint32{0, 0, 0, 0}, // ::
			expected: "::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IPv6ToString(tt.ipv6)

			// Parse both as net.IP for comparison (handles different representations)
			resultIP := net.ParseIP(result)
			expectedIP := net.ParseIP(tt.expected)

			if resultIP == nil || expectedIP == nil {
				t.Fatalf("Failed to parse IPs: result=%v, expected=%v", result, tt.expected)
			}

			if !resultIP.Equal(expectedIP) {
				t.Errorf("IPv6ToString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestConnectionKeyToIPs validates dual-stack IP conversion
func TestConnectionKeyToIPs(t *testing.T) {
	tests := []struct {
		name      string
		key       bpf.ConnectionKey
		expectedSrc string
		expectedDst string
	}{
		{
			name: "IPv4 connection",
			key: bpf.ConnectionKey{
				SrcAddr:  [4]uint32{0x0a000001, 0, 0, 0}, // 10.0.0.1
				DstAddr:  [4]uint32{0x0a000002, 0, 0, 0}, // 10.0.0.2
				SrcPort:  12345,
				DstPort:  80,
				Protocol: 6, // TCP
				Family:   2, // AF_INET
			},
			expectedSrc: "10.0.0.1",
			expectedDst: "10.0.0.2",
		},
		{
			name: "IPv6 connection",
			key: bpf.ConnectionKey{
				SrcAddr:  [4]uint32{0x20010db8, 0, 0, 0x00000001}, // 2001:db8::1 (network byte order)
				DstAddr:  [4]uint32{0x20010db8, 0, 0, 0x00000002}, // 2001:db8::2
				SrcPort:  54321,
				DstPort:  443,
				Protocol: 6,  // TCP
				Family:   10, // AF_INET6
			},
			expectedSrc: "2001:db8::1",
			expectedDst: "2001:db8::2",
		},
		{
			name: "localhost IPv4",
			key: bpf.ConnectionKey{
				SrcAddr:  [4]uint32{0x7f000001, 0, 0, 0}, // 127.0.0.1 (network byte order)
				DstAddr:  [4]uint32{0x7f000001, 0, 0, 0}, // 127.0.0.1
				SrcPort:  8080,
				DstPort:  9090,
				Protocol: 6, // TCP
				Family:   2, // AF_INET
			},
			expectedSrc: "127.0.0.1",
			expectedDst: "127.0.0.1",
		},
		{
			name: "localhost IPv6",
			key: bpf.ConnectionKey{
				SrcAddr:  [4]uint32{0, 0, 0, 0x00000001}, // ::1 (network byte order)
				DstAddr:  [4]uint32{0, 0, 0, 0x00000001}, // ::1
				SrcPort:  8080,
				DstPort:  9090,
				Protocol: 6,  // TCP
				Family:   10, // AF_INET6
			},
			expectedSrc: "::1",
			expectedDst: "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcIP, dstIP := ConnectionKeyToIPs(tt.key)

			// Parse as net.IP for proper comparison
			srcParsed := net.ParseIP(srcIP)
			dstParsed := net.ParseIP(dstIP)
			expectedSrcParsed := net.ParseIP(tt.expectedSrc)
			expectedDstParsed := net.ParseIP(tt.expectedDst)

			if !srcParsed.Equal(expectedSrcParsed) {
				t.Errorf("Source IP = %v, want %v", srcIP, tt.expectedSrc)
			}
			if !dstParsed.Equal(expectedDstParsed) {
				t.Errorf("Destination IP = %v, want %v", dstIP, tt.expectedDst)
			}
		})
	}
}

// TestConnectionKeyStructSize validates struct alignment with C
func TestConnectionKeyStructSize(t *testing.T) {
	var key bpf.ConnectionKey

	// Connection key should be exactly 40 bytes:
	// - SrcAddr: 16 bytes (4 * 4)
	// - DstAddr: 16 bytes (4 * 4)
	// - SrcPort: 2 bytes
	// - DstPort: 2 bytes
	// - Protocol: 1 byte
	// - Family: 1 byte
	// - Pad: 2 bytes
	// Total: 40 bytes

	expectedSize := 40
	actualSize := int(unsafe.Sizeof(key))

	if actualSize != expectedSize {
		t.Errorf("ConnectionKey size = %d bytes, want %d bytes", actualSize, expectedSize)
	}
}

// TestFamilyConstants validates AF_INET and AF_INET6 constants
func TestFamilyConstants(t *testing.T) {
	const (
		AF_INET  = 2
		AF_INET6 = 10
	)

	tests := []struct {
		name     string
		family   uint8
		expected string
	}{
		{"IPv4 family", AF_INET, "ipv4"},
		{"IPv6 family", AF_INET6, "ipv6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var familyStr string
			if tt.family == AF_INET {
				familyStr = "ipv4"
			} else if tt.family == AF_INET6 {
				familyStr = "ipv6"
			}

			if familyStr != tt.expected {
				t.Errorf("Family mapping = %v, want %v", familyStr, tt.expected)
			}
		})
	}
}

// Helper functions (these should match your implementation)

func IPv4ToString(ip uint32) string {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, ip)
	return net.IP(bytes).String()
}

func IPv6ToString(ipv6 [4]uint32) string {
	bytes := make([]byte, 16)
	binary.BigEndian.PutUint32(bytes[0:4], ipv6[0])
	binary.BigEndian.PutUint32(bytes[4:8], ipv6[1])
	binary.BigEndian.PutUint32(bytes[8:12], ipv6[2])
	binary.BigEndian.PutUint32(bytes[12:16], ipv6[3])
	return net.IP(bytes).String()
}

func ConnectionKeyToIPs(key bpf.ConnectionKey) (srcIP, dstIP string) {
	if key.Family == 2 { // AF_INET (IPv4)
		srcIP = IPv4ToString(key.SrcAddr[0])
		dstIP = IPv4ToString(key.DstAddr[0])
	} else if key.Family == 10 { // AF_INET6
		srcIP = IPv6ToString(key.SrcAddr)
		dstIP = IPv6ToString(key.DstAddr)
	} else {
		srcIP = "unknown"
		dstIP = "unknown"
	}
	return
}
