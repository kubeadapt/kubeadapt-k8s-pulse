package collector

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/kubeadapt/kubeadapt-k8s-pulse/internal/bpf"
	"github.com/stretchr/testify/assert"
)

// TestProtocolToString tests protocol number to string conversion
func TestProtocolToString(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint8
		want     string
	}{
		{"ICMP", 1, "icmp"},
		{"TCP", 6, "tcp"},
		{"UDP", 17, "udp"},
		{"ICMPv6", 58, "icmpv6"},
		{"Unknown zero", 0, "unknown(0)"},
		{"Unknown 255", 255, "unknown(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protocolToString(tt.protocol)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestConnectionKeyToIPs tests IP address extraction from connection keys
func TestConnectionKeyToIPs(t *testing.T) {
	tests := []struct {
		name    string
		key     *bpf.ConnectionKey
		wantSrc string
		wantDst string
	}{
		{
			name: "IPv4 private addresses",
			key: &bpf.ConnectionKey{
				SrcAddr: [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("192.168.1.10").To4()), 0, 0, 0},
				DstAddr: [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("10.0.2.20").To4()), 0, 0, 0},
				Family:  2, // AF_INET
			},
			wantSrc: "192.168.1.10",
			wantDst: "10.0.2.20",
		},
		{
			name: "IPv4 public addresses",
			key: &bpf.ConnectionKey{
				SrcAddr: [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("8.8.8.8").To4()), 0, 0, 0},
				DstAddr: [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("1.1.1.1").To4()), 0, 0, 0},
				Family:  2,
			},
			wantSrc: "8.8.8.8",
			wantDst: "1.1.1.1",
		},
		{
			name: "IPv6 addresses",
			key: &bpf.ConnectionKey{
				// IPv6 addresses as they would be read by cilium/ebpf from network-order bytes
				// 2001:db8::1 in network order bytes [0x20,0x01,0x0d,0xb8,...,0x00,0x01]
				// cilium/ebpf reads as little-endian uint32s: 0xb80d0120, 0, 0, 0x01000000
				SrcAddr: [4]uint32{0xb80d0120, 0, 0, 0x01000000},
				DstAddr: [4]uint32{0xb80d0120, 0, 0, 0x02000000},
				Family:  10, // AF_INET6
			},
			wantSrc: "2001:db8::1",
			wantDst: "2001:db8::2",
		},
		{
			name: "Unknown family with IPv4 data",
			key: &bpf.ConnectionKey{
				SrcAddr: [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("172.16.1.1").To4()), 0, 0, 0},
				DstAddr: [4]uint32{binary.LittleEndian.Uint32(net.ParseIP("172.16.1.2").To4()), 0, 0, 0},
				Family:  0,
			},
			wantSrc: "172.16.1.1",
			wantDst: "172.16.1.2",
		},
		{
			name: "All zeros",
			key: &bpf.ConnectionKey{
				SrcAddr: [4]uint32{0, 0, 0, 0},
				DstAddr: [4]uint32{0, 0, 0, 0},
				Family:  0,
			},
			wantSrc: "0.0.0.0",
			wantDst: "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcIP, dstIP := ConnectionKeyToIPs(tt.key)
			assert.Equal(t, tt.wantSrc, srcIP)
			assert.Equal(t, tt.wantDst, dstIP)
		})
	}
}

// TestIPv6ToIPString tests IPv6 address conversion
func TestIPv6ToIPString(t *testing.T) {
	tests := []struct {
		name string
		ipv6 [4]uint32
		want string
	}{
		{
			name: "IPv6 localhost",
			// ::1 in network order [0x00,...,0x01], read as little-endian uint32s
			ipv6: [4]uint32{0, 0, 0, 0x01000000},
			want: "::1",
		},
		{
			name: "IPv6 documentation prefix",
			// 2001:db8::1 in network order [0x20,0x01,0x0d,0xb8,...,0x01]
			// read as little-endian uint32s: 0xb80d0120, 0, 0, 0x01000000
			ipv6: [4]uint32{0xb80d0120, 0, 0, 0x01000000},
			want: "2001:db8::1",
		},
		{
			name: "All zeros (IPv6 any)",
			ipv6: [4]uint32{0, 0, 0, 0},
			want: "::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IPv6ToIPString(tt.ipv6)
			// Parse both to normalize representation
			wantIP := net.ParseIP(tt.want)
			gotIP := net.ParseIP(got)
			assert.True(t, wantIP.Equal(gotIP), "want %s, got %s", tt.want, got)
		})
	}
}

// TestUint32ToIPString tests IPv4 uint32 to string conversion
func TestUint32ToIPString(t *testing.T) {
	tests := []struct {
		name string
		ip   uint32
		want string
	}{
		{
			name: "Private IP 192.168.1.1",
			ip:   binary.LittleEndian.Uint32(net.ParseIP("192.168.1.1").To4()),
			want: "192.168.1.1",
		},
		{
			name: "Private IP 10.0.0.1",
			ip:   binary.LittleEndian.Uint32(net.ParseIP("10.0.0.1").To4()),
			want: "10.0.0.1",
		},
		{
			name: "Public IP 8.8.8.8",
			ip:   binary.LittleEndian.Uint32(net.ParseIP("8.8.8.8").To4()),
			want: "8.8.8.8",
		},
		{
			name: "Zero address",
			ip:   0,
			want: "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uint32ToIPString(tt.ip)
			assert.Equal(t, tt.want, got)
		})
	}
}
