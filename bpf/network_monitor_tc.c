// go:build ignore

// TC eBPF Program for Network Traffic Observation
// ───────────────────────────────────────────────────────────────────────────
// This program uses TC (Traffic Control) hooks to observe network traffic
// at the packet level for accurate bandwidth measurement and analysis.
//
// Key Features:
// - Measures PACKET bytes (includes IP/TCP/UDP headers)
// - Tracks retransmissions and all network activity
// - Provides accurate ingress/egress bandwidth metrics
// - Full IPv4 and IPv6 dual-stack support
//
// Kernel Compatibility (5.10+):
// - IPv6 parsing uses bpf_skb_load_bytes() instead of direct packet pointer
//   arithmetic. This avoids BPF verifier precision tracking limitations with
//   variable offsets through loop iterations (IPv6 extension header parsing).
//   This pattern is inspired by Cilium's ctx_load_bytes() approach.
// ───────────────────────────────────────────────────────────────────────────

// Standard kernel type definitions
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

// BPF helpers
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// ===== CONSTANTS =====

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

// IPv6 Extension Header Types (RFC 8200)
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif

#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif

#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif

#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif

#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS 60
#endif

#ifndef IPPROTO_NONE
#define IPPROTO_NONE 59
#endif

// Maximum IPv6 extension headers to process (BPF verifier requirement)
#define IPV6_MAX_HEADERS 4

// IPv6 extension header lengths
#define IPV6_FRAGLEN 8 // Fragment header is always 8 bytes

// IPv6 Fragment Header structure (RFC 8200 Section 4.5)
struct ipv6_frag_hdr {
  __u8 nexthdr;        // Next header protocol
  __u8 reserved;       // Must be zero
  __be16 frag_off;     // 13-bit offset (in 8-byte units) + 2 reserved bits + MF flag
  __be32 identification; // Fragment identification
};

// Fragment offset mask and flags
#define IPV6_FRAG_OFF_MASK 0xFFF8  // Bits 15-3: fragment offset (in 8-byte units)
#define IPV6_FRAG_MF 0x0001         // Bit 0: More Fragments flag

// TC return codes
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

// Parse results
#define PARSE_OK 0
#define PARSE_DISCARD 1

// Overflow event reasons
#define OVERFLOW_REASON_MAP_FULL 0       // Map reached max_entries
#define OVERFLOW_REASON_RACE_CONDITION 1 // EEXIST + re-lookup failed
#define OVERFLOW_REASON_EXPLICIT 2       // Explicit overflow (future use)

// ===== INTERNAL COUNTERS =====

// Counter types for observability
#define COUNTER_OVERFLOW_EVENTS 0
#define COUNTER_RACE_CONDITIONS 1
#define COUNTER_PARSE_ERRORS 2
#define COUNTER_HOST_FILTERED 3
#define COUNTER_IPV4_FRAGMENTS 4
#define COUNTER_IPV6_FRAGMENTS 5
#define MAX_COUNTERS 16

// BPF map size (should match network_monitor.c)
#ifndef BPF_MAP_SIZE
#define BPF_MAP_SIZE 100000
#endif

// ===== DATA STRUCTURES =====
// These MUST match network_monitor.c for compatibility!

// Connection key - identifies unique network flows
struct connection_key {
  __u32 src_addr[4]; // IPv4 uses only [0], IPv6 uses all 4
  __u32 dst_addr[4];
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol; // TCP=6, UDP=17
  __u8 family;   // AF_INET=2, AF_INET6=10
  __u16 pad;     // Alignment
};

// Connection statistics
// Note: bytes include full IP packet (headers + payload), matching cloud
// provider billing
//
// EGRESS-ONLY TRACKING STRATEGY:
// TC programs attach ONLY to egress hooks (no ingress), which automatically
// prevents:
// 1. Same-node Pod-to-Pod duplication (only sender's egress is captured)
// 2. Cross-node duplication (receiver's ingress is never captured)
//
// INTERFACE DEDUPLICATION:
// When same packet traverses multiple interfaces (e.g., veth → docker0 → eth0),
// we track the FIRST interface where flow was seen and only count packets/bytes
// from that interface. This prevents multi-interface path duplication.
//
// This ensures:
// - Each packet is counted exactly ONCE across all nodes and interfaces
// - Accurate bandwidth measurement aligned with cloud provider egress billing
// - Simpler code with no direction split needed
struct connection_stats {
  __u64 bytes;               // Total bytes (egress only, no direction split)
  __u64 packets;             // Total packets (egress only)
  __u64 last_seen_ns;        // Last activity timestamp
  __u64 cgroup_id;           // Pod attribution (from first interface)
  __u32 if_index_first_seen; // First interface where flow was observed
                             // (deduplication key)
  __u8 padding[4];           // Alignment padding
};

// Overflow event (when map is full)
struct overflow_event {
  struct connection_key key;
  struct connection_stats stats;
  __u64 timestamp_ns;
  __u8 reason;
  __u8 padding[7];
};

// ===== BPF MAPS =====

// Main connection tracking map
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(struct connection_key));
  __uint(value_size, sizeof(struct connection_stats));
  __uint(max_entries, BPF_MAP_SIZE);
} connection_flows SEC(".maps");

// Overflow ringbuffer (when map is full)
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB (not 256KB!)
} overflow_events SEC(".maps");

// ===== NETWORK NAMESPACE FILTERING MAPS =====

// Host network namespace inode (from /proc/1/ns/net)
// Used in "strict" filtering mode for netns comparison
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, 1);
} host_netns_map SEC(".maps");

// Filter mode selection (populated by userspace from EBPF_NETNS_FILTER_MODE)
// Key: always 0 (single entry map)
// Value: filter mode
//   0 = default  (track all K8s pods via cgroup check, filter host processes)
//   1 = disabled (no filtering, track everything)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 1);
} filter_mode_map SEC(".maps");

// Global counters map (per-CPU for performance)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, MAX_COUNTERS);
} global_counters SEC(".maps");

// ===== HELPER FUNCTIONS =====

// Helper function to increment counters
static __always_inline void increase_counter(__u32 counter_type) {
  __u64 *counter = bpf_map_lookup_elem(&global_counters, &counter_type);
  if (counter) {
    __sync_fetch_and_add(counter, 1);
  }
}

// IPv6 extension header structure (RFC 8200)
// Note: This is already defined in <linux/ipv6.h>, but we'll use it directly
// struct ipv6_opt_hdr {
//     __u8 nexthdr;
//     __u8 hdrlen;  // Length in 8-byte units, NOT including first 8 bytes
// } __attribute__((packed));

// Helper: Calculate length of standard extension headers (Hop-by-Hop, Routing,
// Destination Options) Returns length in bytes
static __always_inline __u32 ipv6_optlen(const struct ipv6_opt_hdr *opthdr) {
  // Formula: (hdrlen + 1) * 8
  // Example: hdrlen=0 → (0+1)*8 = 8 bytes (minimum)
  //          hdrlen=1 → (1+1)*8 = 16 bytes
  return (__u32)(opthdr->hdrlen + 1) << 3;
}

// Helper: Calculate length of Authentication Header (AH)
// Returns length in bytes
static __always_inline __u32 ipv6_authlen(const struct ipv6_opt_hdr *opthdr) {
  // Formula: (hdrlen + 2) * 4
  // AH uses 4-byte units instead of 8-byte
  return (__u32)(opthdr->hdrlen + 2) << 2;
}

// Skip IPv6 extension headers to find transport layer protocol
// ───────────────────────────────────────────────────────────────────────
// Uses bpf_skb_load_bytes() for kernel 5.15+ compatibility
// The BPF verifier on older kernels can't track variable offsets through
// packet pointer arithmetic. bpf_skb_load_bytes() performs bounds checking
// internally, avoiding the verifier's precision tracking limitations.
//
// Inspired by Cilium's ctx_load_bytes() pattern for kernel compatibility.
//
// Parameters:
//   - skb: pointer to __sk_buff (needed for bpf_skb_load_bytes)
//   - l3_offset: offset from packet start to IPv6 header (typically 14 for Ethernet)
//   - nexthdr: pointer to nexthdr field (updated in-place)
//   - l4_offset: pointer to L4 header offset from packet start (output)
//
// Returns:
//   - 0 on success (found transport protocol, first fragment or non-fragmented)
//   - -1 on error (invalid header, truncated packet, exceeded max headers)
//   - 1 on non-first fragment (middle/last fragment - no transport header present)
//
// Fragmentation Handling:
//   - First fragments (offset=0): Returns 0, transport header accessible
//   - Middle/last fragments (offset>0): Returns 1, NO transport header
//
// Safety:
//   - Uses #pragma unroll for BPF verifier
//   - Bounded to IPV6_MAX_HEADERS iterations
//   - bpf_skb_load_bytes() handles all bounds checking internally
//
static __always_inline int ipv6_skip_exthdr(struct __sk_buff *skb,
                                            __u32 l3_offset, __u8 *nexthdr,
                                            __u32 *l4_offset) {
  struct ipv6_opt_hdr opthdr;
  __u8 nh = *nexthdr;
  // Start after IPv6 fixed header (40 bytes)
  __u32 off = l3_offset + sizeof(struct ipv6hdr);

// Bounded loop with #pragma unroll for BPF verifier
#pragma unroll
  for (int i = 0; i < IPV6_MAX_HEADERS; i++) {
    // Check if current header type is an extension header
    switch (nh) {
    case IPPROTO_NONE:
      // No Next Header - invalid for our use case
      return -1;

    case IPPROTO_FRAGMENT:
    case IPPROTO_AH:
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_DSTOPTS:
      // Extension header - need to read and skip it
      break;

    default:
      // Transport layer protocol (TCP, UDP, ICMP, etc.) - success!
      *nexthdr = nh;
      *l4_offset = off;
      return 0;
    }

    // Read extension header using bpf_skb_load_bytes (handles bounds checking)
    if (bpf_skb_load_bytes(skb, off, &opthdr, sizeof(opthdr)) < 0) {
      return -1; // Truncated packet or invalid offset
    }

    // Calculate header length based on CURRENT header type (before updating nh)
    __u32 hdrlen = 0;
    __u8 current_hdr = nh; // Save current header type

    switch (current_hdr) {
    case IPPROTO_FRAGMENT: {
      // Fragment header - check if this is a non-first fragment
      struct ipv6_frag_hdr frag_hdr;
      if (bpf_skb_load_bytes(skb, off, &frag_hdr, sizeof(frag_hdr)) < 0) {
        return -1; // Truncated fragment header
      }

      // Extract fragment offset (bits 15-3, in 8-byte units)
      // Network byte order: must convert to host byte order first
      __u16 frag_off_field = bpf_ntohs(frag_hdr.frag_off);
      __u16 frag_offset = (frag_off_field & IPV6_FRAG_OFF_MASK) >> 3;

      // Non-first fragment detection
      if (frag_offset != 0) {
        // Middle or last fragment - NO transport header present
        // Return special code to discard packet from parsing
        return 1; // Signal: non-first fragment
      }

      // First fragment (offset=0) - transport header IS present after this header
      // Continue parsing to find transport protocol
      hdrlen = IPV6_FRAGLEN; // Always 8 bytes
      break;
    }
    case IPPROTO_AH:
      hdrlen = ipv6_authlen(&opthdr);
      break;
    default: // HOPOPTS, ROUTING, DSTOPTS
      hdrlen = ipv6_optlen(&opthdr);
      break;
    }

    // Update nexthdr for next iteration
    nh = opthdr.nexthdr;

    // Advance offset by header length
    off += hdrlen;
  }

  // Exceeded maximum headers - give up
  return -1;
}

// Parse IPv4 packet headers
static __always_inline int
parse_ipv4(struct iphdr *ip, void *data_end, struct connection_key *key,
           __u64 *packet_bytes) { // ← ADD THIS PARAMETER
  // Bounds check
  if ((void *)(ip + 1) > data_end) {
    return PARSE_DISCARD;
  }

  // Extract IP packet size for bandwidth measurement
  // tot_len includes IP header + TCP/UDP header + payload
  *packet_bytes = bpf_ntohs(ip->tot_len);

  // Extract IP addresses (store in first __u32 of array)
  key->src_addr[0] = ip->saddr;
  key->dst_addr[0] = ip->daddr;
  key->src_addr[1] = 0;
  key->src_addr[2] = 0;
  key->src_addr[3] = 0;
  key->dst_addr[1] = 0;
  key->dst_addr[2] = 0;
  key->dst_addr[3] = 0;
  key->family = AF_INET;
  key->protocol = ip->protocol;

  // IPv4 Fragmentation Detection
  // ────────────────────────────────────────────────────────────────────
  // The frag_off field contains:
  //   Bit 15: Reserved (must be 0)
  //   Bit 14: DF (Don't Fragment) flag
  //   Bit 13: MF (More Fragments) flag
  //   Bits 12-0: Fragment Offset (in 8-byte units)
  //
  // Fragment offset = 0 means:
  //   - Non-fragmented packet (MF=0, offset=0), OR
  //   - First fragment (MF=1, offset=0)
  //   → Transport header IS present
  //
  // Fragment offset > 0 means:
  //   - Middle fragment (MF=1, offset>0), OR
  //   - Last fragment (MF=0, offset>0)
  //   → Transport header NOT present
  __u16 frag_off = bpf_ntohs(ip->frag_off);
  __u16 frag_offset = (frag_off & 0x1FFF); // Mask bits 12-0 (fragment offset in 8-byte units)

  if (frag_offset != 0) {
    // Non-first fragment (middle or last) - NO transport header present
    // We cannot extract ports, but we CAN still track this packet for billing
    // Strategy: Use protocol-only tracking with port=0
    increase_counter(COUNTER_IPV4_FRAGMENTS);
    key->src_port = 0;
    key->dst_port = 0;
    return PARSE_OK; // Track fragment payload bytes for billing
  }

  // First fragment or non-fragmented packet - transport header IS present

  // Calculate L4 header position (IP header length is variable)
  void *l4_hdr = (void *)ip + (ip->ihl * 4);

  // Parse TCP
  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = l4_hdr;
    if ((void *)(tcp + 1) > data_end) {
      return PARSE_DISCARD;
    }
    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);
    return PARSE_OK;
  }

  // Parse UDP
  if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = l4_hdr;
    if ((void *)(udp + 1) > data_end) {
      return PARSE_DISCARD;
    }
    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);
    return PARSE_OK;
  }

  // Parse ICMP (use type/code as pseudo-ports for aggregation)
  if (ip->protocol == IPPROTO_ICMP) {
    // ICMP header: type (1B), code (1B), checksum (2B), ...
    if (l4_hdr + 4 > data_end) {
      return PARSE_DISCARD;
    }
    __u8 *icmp = (__u8 *)l4_hdr;
    key->src_port = icmp[0]; // ICMP type
    key->dst_port = icmp[1]; // ICMP code
    return PARSE_OK;
  }

  // Other protocols - discard
  return PARSE_DISCARD;
}

// Parse IPv6 packet headers (WITH extension header support!)
// ───────────────────────────────────────────────────────────────────────
// Uses bpf_skb_load_bytes() for L4 header access to avoid BPF verifier
// issues with variable offset packet pointer arithmetic on kernels 5.10-6.6.
// This approach is inspired by Cilium's ctx_load_bytes() pattern.
// ───────────────────────────────────────────────────────────────────────
static __always_inline int parse_ipv6(struct __sk_buff *skb, __u32 l3_offset,
                                      struct connection_key *key,
                                      __u64 *packet_bytes) {
  // Read IPv6 header using bpf_skb_load_bytes
  struct ipv6hdr ip6;
  if (bpf_skb_load_bytes(skb, l3_offset, &ip6, sizeof(ip6)) < 0) {
    return PARSE_DISCARD;
  }

  // IPv6 packet size = payload_len + 40-byte fixed header
  // Note: payload_len includes extension headers AND transport layer
  *packet_bytes = bpf_ntohs(ip6.payload_len) + 40;

  // Extract IPv6 addresses (copy all 128 bits)
  __builtin_memcpy(key->src_addr, &ip6.saddr.in6_u.u6_addr32, 16);
  __builtin_memcpy(key->dst_addr, &ip6.daddr.in6_u.u6_addr32, 16);
  key->family = AF_INET6;

  // Skip extension headers to find transport protocol
  // Start with nexthdr from IPv6 fixed header
  __u8 nexthdr = ip6.nexthdr;
  __u32 l4_offset = 0; // Will be set by ipv6_skip_exthdr

  int ret = ipv6_skip_exthdr(skb, l3_offset, &nexthdr, &l4_offset);

  if (ret < 0) {
    // Failed to parse extension headers (truncated, too many headers, etc.)
    return PARSE_DISCARD;
  }

  if (ret == 1) {
    // Non-first fragment (middle/last) - no transport header present
    // We cannot extract ports, but we CAN still track this packet for billing
    // Strategy: Use protocol-only tracking with port=0
    increase_counter(COUNTER_IPV6_FRAGMENTS);
    key->protocol = nexthdr;
    key->src_port = 0;
    key->dst_port = 0;
    return PARSE_OK; // Track fragment payload bytes for billing
  }

  // Now nexthdr contains the transport protocol (TCP, UDP, ICMP, etc.)
  // and l4_offset points to the start of transport header from packet start
  key->protocol = nexthdr;

  // Parse TCP using bpf_skb_load_bytes (avoids variable offset issues)
  if (nexthdr == IPPROTO_TCP) {
    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0) {
      return PARSE_DISCARD;
    }
    key->src_port = bpf_ntohs(tcp.source);
    key->dst_port = bpf_ntohs(tcp.dest);
    return PARSE_OK;
  }

  // Parse UDP using bpf_skb_load_bytes
  if (nexthdr == IPPROTO_UDP) {
    struct udphdr udp;
    if (bpf_skb_load_bytes(skb, l4_offset, &udp, sizeof(udp)) < 0) {
      return PARSE_DISCARD;
    }
    key->src_port = bpf_ntohs(udp.source);
    key->dst_port = bpf_ntohs(udp.dest);
    return PARSE_OK;
  }

  // Parse ICMPv6 using bpf_skb_load_bytes (type/code as pseudo-ports)
  if (nexthdr == IPPROTO_ICMPV6) {
    // ICMPv6 header: type (1B), code (1B), checksum (2B), ...
    __u8 icmp6_hdr[4];
    if (bpf_skb_load_bytes(skb, l4_offset, icmp6_hdr, sizeof(icmp6_hdr)) < 0) {
      return PARSE_DISCARD;
    }
    key->src_port = icmp6_hdr[0]; // ICMPv6 type
    key->dst_port = icmp6_hdr[1]; // ICMPv6 code
    return PARSE_OK;
  }

  // Other protocols - discard
  return PARSE_DISCARD;
}

// Parse packet and extract connection key
static __always_inline int
parse_packet(struct __sk_buff *skb, struct connection_key *key,
             __u64 *packet_bytes) { // ← ADD THIS PARAMETER
  // Initialize key to zero
  __builtin_memset(key, 0, sizeof(*key));
  *packet_bytes = 0; // ← Initialize output

  // Get packet data pointers
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  // Parse Ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return PARSE_DISCARD;
  }

  __u16 eth_proto = bpf_ntohs(eth->h_proto);
  void *l3_hdr = (void *)(eth + 1);

  // Parse based on EtherType (now with packet_bytes output)
  if (eth_proto == ETH_P_IP) {
    return parse_ipv4((struct iphdr *)l3_hdr, data_end, key, packet_bytes);
  } else if (eth_proto == ETH_P_IPV6) {
    // IPv6 uses bpf_skb_load_bytes() for kernel 5.10+ verifier compatibility
    // Pass skb and L3 offset (Ethernet header size = 14 bytes)
    __u32 l3_offset = sizeof(struct ethhdr);
    return parse_ipv6(skb, l3_offset, key, packet_bytes);
  }

  // Non-IP traffic
  return PARSE_DISCARD;
}

// Get cgroup ID from skb
// This is critical for pod attribution in Kubernetes!
static __always_inline __u64 get_cgroup_id(struct __sk_buff *skb) {
  // In TC context, cgroup_id is not directly accessible via skb->cgroup_id
  // We need to use the bpf_skb_cgroup_id() helper (available since Linux 4.18)
  //
  // Note: This requires:
  // - Linux kernel 4.18+
  // - CONFIG_SOCK_CGROUP_DATA=y
  // - sk_buff must have an associated socket (skb->sk != NULL)
  //
  // For packets without an associated socket (e.g., forwarded packets),
  // this will return 0, which we'll filter out in the collector.

  __u64 cgroup_id = bpf_skb_cgroup_id(skb);
  return cgroup_id;
}

// NETWORK NAMESPACE FILTERING - TC Version
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Check if packet should be filtered (skipped) or tracked
// Returns: true if should SKIP tracking, false if should TRACK
//
// CONFIGURABLE FILTERING MODES (set via EBPF_NETNS_FILTER_MODE):
//
// MODE 0 - "default" (RECOMMENDED):
//   - Track: All Kubernetes pods (including hostNetwork:true)
//   - Filter: Host system processes only
//   - Method: Simple cgroup check (cgroup_id != 0 && cgroup_id != 1)
//
// MODE 1 - "disabled":
//   - Track: Everything (no filtering)
//   - Filter: Nothing
//
static __always_inline int is_host_network_namespace_tc(struct __sk_buff *skb) {
  // Get filter mode from map (populated by userspace)
  __u32 key = 0;
  __u32 *mode_ptr = bpf_map_lookup_elem(&filter_mode_map, &key);

  // Default to MODE 0 if map not initialized
  __u32 mode = mode_ptr ? *mode_ptr : 0;

  // MODE 1: DISABLED - Track everything (no filtering)
  if (mode == 1) {
    return 0; // Never filter - track all traffic (0 = false)
  }

  // MODE 0: DEFAULT - Simple cgroup-based filtering (RECOMMENDED)
  // Track all Kubernetes pods (including hostNetwork), filter only host
  // processes
  __u64 cgroup_id = bpf_skb_cgroup_id(skb);

  // Root cgroup (cgroup_id == 1) or invalid (0) = host system process → filter
  // it Non-root cgroup = containerized process (K8s pod) → track it
  if (cgroup_id == 0 || cgroup_id == 1) {
    increase_counter(COUNTER_HOST_FILTERED);
    return 1; // Host process - skip tracking (1 = true)
  }

  return 0; // K8s pod (any network mode) - track it (0 = false)
}

// Update connection statistics with interface deduplication
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// EGRESS-ONLY + INTERFACE DEDUPLICATION:
// Since TC is attached ONLY to egress hooks, we automatically avoid Pod-to-Pod
// and cross-node duplication. However, we still need interface deduplication
// for packets traversing multiple interfaces on the same path (e.g., veth →
// docker0 → eth0).
//
// Strategy: "First interface wins"
//   1. When a new flow is created, record which interface saw it first
//   (if_index_first_seen)
//   2. For subsequent packets:
//      - If seen on SAME interface → COUNT bytes/packets (normal update)
//      - If seen on DIFFERENT interface → SKIP counting (multi-interface path
//      deduplication)
//
// This ensures each packet is counted exactly ONCE, even when traversing
// multiple interfaces.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
static __always_inline void update_stats(struct connection_key *key,
                                         __u64 bytes, __u64 cgroup_id,
                                         __u32 if_index) {
  // Look up existing connection
  struct connection_stats *stats = bpf_map_lookup_elem(&connection_flows, key);

  if (stats) {
    // Existing connection - check if this is the same interface
    if (stats->if_index_first_seen == if_index) {
      // ✅ SAME INTERFACE - Count this packet
      __sync_fetch_and_add(&stats->bytes, bytes);
      __sync_fetch_and_add(&stats->packets, 1);
      stats->last_seen_ns = bpf_ktime_get_ns();

    } else if (if_index != 0) {
      // ⚠️ DIFFERENT INTERFACE - Skip counting (multi-interface deduplication)
      // Only update timestamp to keep flow alive
      // Example: veth (counted) → docker0 (skipped) → eth0 (skipped)
      stats->last_seen_ns = bpf_ktime_get_ns();
    }
    // If if_index == 0 (invalid), skip to be safe

  } else {
    // Create new connection entry
    // This is the FIRST time we see this flow, so record the interface
    struct connection_stats new_stats = {
        .bytes = bytes,
        .packets = 1,
        .last_seen_ns = bpf_ktime_get_ns(),
        .cgroup_id = cgroup_id,
        .if_index_first_seen = if_index, // ✅ Lock to first interface
        .padding = {0},
    };

    long ret =
        bpf_map_update_elem(&connection_flows, key, &new_stats, BPF_NOEXIST);

    // Handle map full condition
    if (ret != 0 && ret != -17) { // -17 = EEXIST (concurrent insert)
      // Map is full or busy - send to overflow ringbuffer
      struct overflow_event *event = bpf_ringbuf_reserve(
          &overflow_events, sizeof(struct overflow_event), 0);
      if (event) {
        event->key = *key;
        event->stats = new_stats;
        event->timestamp_ns = bpf_ktime_get_ns();
        event->reason = OVERFLOW_REASON_MAP_FULL;
        __builtin_memset(event->padding, 0,
                         sizeof(event->padding)); // ✅ FIX: Initialize padding
        bpf_ringbuf_submit(event, 0);
        increase_counter(COUNTER_OVERFLOW_EVENTS);
      }
      // Note: If ringbuf reservation fails, we drop the packet
      // This is acceptable as the collector will notice missing data
    } else if (ret == -17) {
      // Concurrent insertion - retry lookup and update
      stats = bpf_map_lookup_elem(&connection_flows, key);
      if (stats) {
        // Successfully found entry - update it
        __sync_fetch_and_add(&stats->bytes, bytes);
        __sync_fetch_and_add(&stats->packets, 1);
        stats->last_seen_ns = bpf_ktime_get_ns();
      } else {
        // ✅ ADD THIS: Re-lookup failed (rare race condition)
        // Entry was deleted between EEXIST and re-lookup
        // Send to overflow ringbuffer for observability
        struct overflow_event *event = bpf_ringbuf_reserve(
            &overflow_events, sizeof(struct overflow_event), 0);
        if (event) {
          event->key = *key;
          event->stats = new_stats;
          event->timestamp_ns = bpf_ktime_get_ns();
          event->reason = OVERFLOW_REASON_RACE_CONDITION;
          __builtin_memset(event->padding, 0, sizeof(event->padding));
          bpf_ringbuf_submit(event, 0);
          increase_counter(COUNTER_RACE_CONDITIONS); // ← ADD THIS
        }
        // Note: If ringbuf reservation fails, packet is dropped
        // This is acceptable as it means extreme memory pressure
      }
    }
  }
}

// ===== TC HOOK PROGRAM =====

// TC Egress Hook (packets leaving the interface)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CLASSIC TC ATTACHMENT:
// - Uses netlink.FilterReplace (classic TC API) for Linux 5.8+ compatibility
// - Section name "classifier/egress" is for classic TC (not TCX)
// - Attached to clsact qdisc egress hook on all network interfaces
//
// EGRESS-ONLY TRACKING:
// This is the ONLY TC hook we attach (no ingress). This automatically prevents:
// - Same-node Pod-to-Pod duplication (only sender tracked)
// - Cross-node duplication (receiver never tracked)
//
// Interface deduplication (veth → docker0 → eth0) is handled by update_stats()
// using if_index_first_seen to count packets only from the first interface.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SEC("classifier/egress")
int tc_egress(struct __sk_buff *skb) {
  // ✅ NETWORK NAMESPACE FILTERING - Skip host traffic
  if (is_host_network_namespace_tc(skb)) {
    return TC_ACT_OK; // Skip host processes and optionally hostNetwork pods
  }

  struct connection_key key;
  __u64 bytes = 0;

  // Parse packet headers AND extract correct IP packet size
  if (parse_packet(skb, &key, &bytes) != PARSE_OK) {
    increase_counter(COUNTER_PARSE_ERRORS);
    return TC_ACT_OK;
  }

  // Get cgroup ID for pod attribution
  __u64 cgroup_id = get_cgroup_id(skb);

  // Get interface index for deduplication (veth → docker0 → eth0)
  __u32 if_index = skb->ifindex;

  // bytes contains IP packet size (IP header + TCP/UDP header + payload)
  // Excludes Ethernet header (14 bytes) - aligns with cloud provider billing

  // Update statistics with interface deduplication
  update_stats(&key, bytes, cgroup_id, if_index);

  return TC_ACT_OK;
}

// ===== PROGRAM ATTACHMENT NOTES =====
//
// EGRESS-ONLY ARCHITECTURE:
// This TC program (tc_egress) is attached ONLY to egress hooks using classic
// TC attachment (netlink.FilterReplace) in loader.go. There is NO ingress hook,
// which automatically prevents bidirectional duplication.
//
// Why Classic TC instead of TCX?
// - TCX requires Linux 6.6+ (too new for many production clusters)
// - Classic TC works on Linux 5.8+ (wider compatibility)
// - Section name "classifier/egress" is compatible with classic TC
// - Full helper support (bpf_skb_cgroup_id, etc.)
//
// DEDUPLICATION STRATEGY:
// - Pod-to-Pod (same node): Prevented by egress-only (only sender tracked)
// - Cross-node: Prevented by egress-only (receiver never tracked)
// - Multi-interface paths: Prevented by if_index_first_seen (handled in update_stats)

char LICENSE[] SEC("license") = "GPL";
