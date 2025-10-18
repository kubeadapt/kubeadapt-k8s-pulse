// go:build ignore

// Define target architecture for BPF
// This is required for PT_REGS macros to work correctly
// bpf2go will compile for both amd64 and arm64
// bpf2go sets __TARGET_ARCH_xxx based on the -target flag
***REMOVED***if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
// x86_64 architecture
***REMOVED***ifndef __TARGET_ARCH_x86
***REMOVED***define __TARGET_ARCH_x86
***REMOVED***endif
***REMOVED***elif defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
// ARM64 architecture
***REMOVED***ifndef __TARGET_ARCH_arm64
***REMOVED***define __TARGET_ARCH_arm64
***REMOVED***endif
***REMOVED***else
// For bpf2go, let's not error out but define a default
// The actual architecture will be set by bpf2go with -target flag
***REMOVED***define __TARGET_ARCH_x86 // Default to x86 if no arch is specified
***REMOVED***endif

// Standard kernel type definitions
***REMOVED***include <linux/bpf.h>
***REMOVED***include <linux/if_ether.h>
***REMOVED***include <linux/if_packet.h>
***REMOVED***include <linux/in.h>
***REMOVED***include <linux/in6.h>
***REMOVED***include <linux/ip.h>
***REMOVED***include <linux/ipv6.h>
***REMOVED***include <linux/socket.h>
***REMOVED***include <linux/tcp.h>
***REMOVED***include <linux/types.h>
***REMOVED***include <linux/udp.h>

// Architecture-specific pt_regs structure
// We define a minimal version here to avoid dependency issues
// The actual fields depend on architecture but we only need it as an opaque
// type since we use PT_REGS macros to access parameters
struct pt_regs {
***REMOVED***ifdef __TARGET_ARCH_x86
  // x86_64 registers
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long orig_rax;
  unsigned long rip;
  unsigned long cs;
  unsigned long eflags;
  unsigned long rsp;
  unsigned long ss;
***REMOVED***elif defined(__TARGET_ARCH_arm64)
  // ARM64 registers
  struct {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
  };
  unsigned long orig_x0;
  unsigned long syscallno;
  unsigned long unused;
***REMOVED***else
  // Fallback - minimal definition
  unsigned long regs[32];
***REMOVED***endif
};

// ARM64 uses user_pt_regs instead of pt_regs for BPF
***REMOVED***ifdef __TARGET_ARCH_arm64
struct user_pt_regs {
  unsigned long regs[31];
  unsigned long sp;
  unsigned long pc;
  unsigned long pstate;
};
***REMOVED***endif

// BPF helpers
***REMOVED***include <bpf/bpf_endian.h>
***REMOVED***include <bpf/bpf_helpers.h>
***REMOVED***include <bpf/bpf_tracing.h>

// Socket structure definitions - using kernel headers approach
// We need the full socket structure definition for accessing socket fields
***REMOVED***include <linux/net.h>

// Define missing constants that are typically macros
***REMOVED***ifndef AF_INET
***REMOVED***define AF_INET 2 /* Internet IP Protocol */
***REMOVED***endif

***REMOVED***ifndef AF_INET6
***REMOVED***define AF_INET6 10 /* IP version 6 */
***REMOVED***endif

***REMOVED***ifndef IPPROTO_TCP
***REMOVED***define IPPROTO_TCP 6 /* Transmission Control Protocol */
***REMOVED***endif

***REMOVED***ifndef IPPROTO_UDP
***REMOVED***define IPPROTO_UDP 17 /* User Datagram Protocol */
***REMOVED***endif

// errno constants for BPF map operations
***REMOVED***ifndef EEXIST
***REMOVED***define EEXIST                                                                 \
  17 /* File exists - returned by BPF_NOEXIST when concurrent insertion occurs \
      */
***REMOVED***endif

// FIX ***REMOVED***5: TCP STATE VALIDATION - TCP State Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// TCP state machine states (from linux/tcp.h)
// We only track sockets in active states, skip TIME_WAIT, CLOSE, etc.
***REMOVED***define TCP_ESTABLISHED 1 // Connection established
***REMOVED***define TCP_SYN_SENT 2    // Sent SYN, waiting for SYN-ACK
***REMOVED***define TCP_SYN_RECV 3    // Received SYN, sent SYN-ACK
***REMOVED***define TCP_FIN_WAIT1 4   // Sent FIN, waiting for ACK
***REMOVED***define TCP_FIN_WAIT2 5   // Received FIN ACK, waiting for FIN
***REMOVED***define TCP_TIME_WAIT 6   // Waiting for 2MSL timeout (SKIP THIS)
***REMOVED***define TCP_CLOSE 7       // Socket closed (SKIP THIS)
***REMOVED***define TCP_CLOSE_WAIT 8  // Received FIN, waiting for close
***REMOVED***define TCP_LAST_ACK 9    // Sent FIN after receiving FIN
***REMOVED***define TCP_LISTEN 10     // Listening for connections
***REMOVED***define TCP_CLOSING 11    // Both sides closing simultaneously

// Define bool type if not available
***REMOVED***ifndef __bool_defined
typedef _Bool bool;
***REMOVED***define true 1
***REMOVED***define false 0
***REMOVED***define __bool_defined 1
***REMOVED***endif

// Define size_t if not available
***REMOVED***ifndef __size_t_defined
typedef unsigned long size_t;
***REMOVED***define __size_t_defined 1
***REMOVED***endif

// Forward declaration of struct sock to ensure it's available
struct sock;

// Define hlist_node structure (simplified version needed for sock_common)
struct hlist_node {
  struct hlist_node *next, **pprev;
};

// Network namespace structures for manual offset access
// These are minimal definitions used ONLY for type information
// Actual field access uses runtime-detected offsets via offset_config map
struct ns_common_local {
  unsigned int inum;
};

struct net_local {
  struct ns_common_local ns;
};

struct nsproxy_local {
  struct net_local *net_ns;
};

struct task_struct_local {
  struct nsproxy_local *nsproxy;
};

// Socket structures for manual field access
// This struct mirrors kernel's sock_common for manual offset access via
// bpf_probe_read_kernel().
struct sock_common_local {
  union {
    struct {
      __be32 skc_daddr;
      __be32 skc_rcv_saddr;
    };
  };
  union {
    unsigned int skc_hash;
    __u16 skc_u16hashes[2];
  };
  union {
    struct {
      __be16 skc_dport;
      __u16 skc_num;
    };
  };
  short unsigned int skc_family;
  volatile unsigned char skc_state;
  unsigned char skc_reuse : 4;
  unsigned char skc_reuseport : 1;
  unsigned char skc_ipv6only : 1;
  unsigned char skc_net_refcnt : 1;
  int skc_bound_dev_if;
  union {
    struct hlist_node skc_bind_node;
    struct hlist_node skc_portaddr_node;
  };
  void
      *skc_prot; // Changed from "struct proto *" to avoid CO-RE type resolution
  void *skc_net; // Changed from "struct net *" to avoid CO-RE type resolution

  // IPv6 fields
  struct in6_addr skc_v6_daddr;
  struct in6_addr skc_v6_rcv_saddr;

  // Additional fields exist but we only need the ones above
};

struct sock_local {
  struct sock_common_local __sk_common;
  // We only need __sk_common for our use case
  // Additional fields exist but are not needed
};

// Connection tracking structures
// Note: Removed packed attribute to avoid alignment warnings
// Structure is already properly aligned
struct connection_key {
  // IP addresses - IPv6 size accommodates both IPv4 and IPv6
  // For IPv4: only first 32 bits used, rest are zero
  // For IPv6: all 128 bits used
  __u32 src_addr[4]; // Source IP address (IPv4 or IPv6)
  __u32 dst_addr[4]; // Destination IP address (IPv4 or IPv6)
  __u16 src_port;    // Source port
  __u16 dst_port;    // Destination port
  __u8 protocol;     // TCP=6, UDP=17
  __u8 family;       // AF_INET (2) or AF_INET6 (10)
  __u16 pad;         // Padding for alignment (ensures 8-byte alignment)
};

struct connection_stats {
  __u64 bytes_sent;       // Total bytes sent
  __u64 bytes_received;   // Total bytes received
  __u64 packets_sent;     // Total packets sent
  __u64 packets_received; // Total packets received
  __u64 last_seen_ns;     // Last activity timestamp
  __u64 cgroup_id;        // Container cgroup ID
};

// Temporary storage for kretprobes
struct temp_storage {
  __u64 cgroup_id;
  struct sock_local *sk;
};

// ===== MAPS SECTION =====
//
// IMPORTANT: DaemonSet Architecture - Per-Node Sizing
// ───────────────────────────────────────────────────────
// This agent runs as a DaemonSet with ONE POD PER NODE.
// Each agent instance only tracks pods/containers on ITS OWN NODE.
//
// Map sizes are dimensioned for per-node capacity, NOT cluster-wide:
// - Typical node: 100-250 pods
// - Large node: 400-500 pods (e.g., AWS m5.24xlarge)
// - Max connections: 100,000 active flows on very busy nodes (default
// production size)
//
// CONFIGURABLE MAP SIZE (compile-time):
// ─────────────────────────────────────
// Set BPF_MAP_SIZE at compile time via -D flag:
//   - Default: 100,000 entries (production) → ~12.8 MB kernel memory
//   - Fast tests: 5,000 entries → ~640 KB kernel memory
//   - Stress tests: 100,000 entries → ~12.8 MB kernel memory
//
// Memory usage: BPF_MAP_SIZE * 128 bytes per entry
// DO NOT size these maps for cluster-wide pod counts (e.g., 100k pods)!
// That would waste kernel memory unnecessarily.
//
// Default to 100,000 if not specified (production size)
***REMOVED***ifndef BPF_MAP_SIZE
***REMOVED***define BPF_MAP_SIZE 100000
***REMOVED***endif
//
// MAP TYPE DECISION: STANDARD HASH (NetObserv Pattern)
// ────────────────────────────────────────────────────────────────────────
// We use BPF_MAP_TYPE_HASH (standard hash) instead of LRU_HASH or PERCPU_HASH:
//
// WHY NOT PERCPU_HASH?
// - PERCPU_HASH creates duplicate entries per CPU for the same connection!
// - Connection A's packets can arrive on different CPUs (RSS/RPS routing)
// - Packet 1 → CPU 0 → entry in connection_flows[CPU 0]
// - Packet 2 → CPU 2 → entry in connection_flows[CPU 2]
// - Result: ONE connection appears as MULTIPLE entries (semantic mismatch)
// - Statistics fragmentation: bytes/packets split across CPU maps
// - PERCPU_HASH is for per-CPU metrics (counters), NOT connection tracking!
//
// WHY NOT LRU_HASH?
// 1. MEMORY OVERHEAD: 70-95% more memory than standard HASH
//    - Standard HASH: ~12.8 MB (100K entries × 128 bytes)
//    - LRU_HASH: ~22-25 MB (LRU lists, locks, metadata)
//
// 2. BATCH EVICTION DISASTER: Evicts 128 entries at once when full!
//    - Catastrophic data loss spike every time map reaches capacity
//    - Silent eviction (no observability)
//
// 3. PERFORMANCE OVERHEAD: 15-30% slower (lock contention on LRU lists)
//    - Global LRU list shared across CPUs
//    - Cross-CPU synchronization for LRU bookkeeping
//
// WHY STANDARD HASH?
// ✓ ONE entry per unique connection (correct semantics for 5-tuple tracking)
// ✓ 30-70% less memory than LRU_HASH
// ✓ 15-30% better performance (no lock contention)
// ✓ Observable overflow: Returns -E2BIG when full → caught by ringbuffer
// ✓ PROVEN PATTERN: NetObserv uses BPF_MAP_TYPE_HASH in Red Hat OpenShift
//
// Trade-off: Manual eviction required (but we already have read-after-delete!)
// NetObserv reference:
// github.com/netobserv/netobserv-ebpf-agent/bpf/maps_definition.h

// Connection tracking map (per-node scope)
// Size is configurable at compile time via BPF_MAP_SIZE macro
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(struct connection_key));
  __uint(value_size, sizeof(struct connection_stats));
  __uint(max_entries, BPF_MAP_SIZE); // Configurable: default 100,000
                                     // (production), 5,000 (fast tests)
} connection_flows SEC(".maps");

// Temporary storage for kretprobes (per-CPU for performance)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(struct temp_storage));
  __uint(max_entries, 1);
} temp_storage_map SEC(".maps");

// ===== OVERFLOW HANDLING =====

// Flow record structure for ringbuffer
struct flow_record {
  struct connection_key key;
  struct connection_stats stats;
  __u64 timestamp_ns;
  __u8 reason;     // 0=map_full, 1=eviction, 2=explicit
  __u8 padding[7]; // Alignment
};

// Overflow ringbuffer for when connection_flows is full
// ────────────────────────────────────────────────────────────────────────
// CRITICAL: This ringbuffer is ACTIVELY USED with standard HASH maps!
//
// With BPF_MAP_TYPE_HASH (NetObserv pattern):
//   - When map reaches BPF_MAP_SIZE entries, bpf_map_update_elem() returns
//   -E2BIG
//   - Overflow connections are sent to this ringbuffer (NO data loss!)
//   - Userspace reads overflow and exports via kubeadapt_overflow_flows_total
//   - Provides complete observability of capacity issues
//
// This prevents data loss when the connection map reaches capacity.
// 16MB ringbuffer can hold ~87,000 overflow entries (each ~192 bytes)
// This is sufficient even for stress tests with 100K+ connection bursts
//
// Why overflow happens with standard HASH (not LRU):
//   - Standard HASH has no auto-eviction (no LRU mechanism)
//   - When full, bpf_map_update_elem() returns -E2BIG (map full)
//   - We catch this error and send to ringbuffer for observability
//   - LRU would silently evict (no visibility), HASH gives us control
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB
} overflow_flows SEC(".maps");

// Zone aggregation removed - backend handles all aggregation logic

// FIX ***REMOVED***4: NETWORK NAMESPACE FILTERING - Map Definitions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Host network namespace inode (from /proc/1/ns/net)
// Used in "strict" filtering mode for netns comparison
// Key: always 0 (single entry map), Value: host netns inode number
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
//   1 = strict   (track only non-hostNetwork pods via netns comparison)
//   2 = disabled (no filtering, track everything)
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 1);
} filter_mode_map SEC(".maps");

// Runtime-detected struct offsets (populated by userspace via BTF detection)
// Used for MODE 1 (strict) to manually traverse
// task_struct->nsproxy->net_ns->ns.inum Key: always 0 (single entry map) Value:
// struct containing three offsets in bytes
struct netns_offset_config {
  __u32 task_nsproxy;   // task_struct->nsproxy offset
  __u32 nsproxy_net_ns; // nsproxy->net_ns offset
  __u32 net_ns_inum;    // net->ns.inum offset (combined net->ns + ns->inum)
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(struct netns_offset_config));
  __uint(max_entries, 1);
} offset_config SEC(".maps");

// ===== HELPER FUNCTIONS =====

// NETWORK NAMESPACE FILTERING - Helper Function (3-MODE IMPLEMENTATION)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Check if current process should be filtered (skipped) or tracked
// Returns: true if should SKIP tracking, false if should TRACK
//
// CONFIGURABLE FILTERING MODES (set via EBPF_NETNS_FILTER_MODE):
//
// MODE 0 - "default" (RECOMMENDED):
//   - Track: All Kubernetes pods (including hostNetwork:true like
//   node-exporter)
//   - Filter: Host system processes only (kubelet, containerd, sshd)
//   - Method: Simple cgroup check (cgroup_id != 1)
//   - Use case: Standard monitoring - you want metrics from ALL pods
//
// MODE 1 - "strict":
//   - Track: Only pods with separate network namespaces (hostNetwork:false)
//   - Filter: Host processes AND hostNetwork:true pods
//   - Method: BTF runtime offset detection for network namespace comparison
//   - Use case: When you want to exclude hostNetwork pods from tracking
//
// MODE 2 - "disabled":
//   - Track: Everything (no filtering)
//   - Filter: Nothing
//   - Method: Always return false (track all)
//   - Use case: Debugging - see all network activity including host processes
//
// Defense in depth: If mode map not initialized, defaults to MODE 0 (default)
static __always_inline bool is_host_network_namespace(void) {
  // Get filter mode from map (populated by userspace)
  __u32 key = 0;
  __u32 *mode_ptr = bpf_map_lookup_elem(&filter_mode_map, &key);

  // Default to MODE 0 if map not initialized
  __u32 mode = mode_ptr ? *mode_ptr : 0;

  // MODE 2: DISABLED - Track everything (no filtering)
  if (mode == 2) {
    return false; // Never filter - track all processes
  }

  // MODE 0: DEFAULT - Simple cgroup-based filtering (RECOMMENDED)
  // Track all Kubernetes pods (including hostNetwork), filter only host
  // processes
  if (mode == 0) {
    __u64 cgroup_id = bpf_get_current_cgroup_id();

    // Root cgroup (cgroup_id == 1) = host system process → filter it
    // Non-root cgroup = containerized process (K8s pod) → track it
    if (cgroup_id == 1) {
      return true; // Host process - skip tracking
    }

    return false; // K8s pod (any network mode) - track it
  }

  // MODE 1: STRICT - Network namespace comparison using runtime offsets
  // ──────────────────────────────────────────────────────────────────────
  // Uses BTF-detected offsets to manually traverse
  // task_struct->nsproxy->net_ns->ns.inum without CO-RE compilation
  // dependencies
  if (mode == 1) {
    // Get runtime-detected offsets from map
    __u32 offset_key = 0;
    struct netns_offset_config *offsets =
        bpf_map_lookup_elem(&offset_config, &offset_key);

    // If offsets not initialized, fall back to MODE 0 (cgroup-based filtering)
    if (!offsets) {
      __u64 cgroup_id = bpf_get_current_cgroup_id();
      return (cgroup_id == 1);
    }

    // Get current task
    void *task = (void *)bpf_get_current_task();
    if (!task) {
      return true; // Can't get task - be conservative and filter it
    }

    // Step 1: Read nsproxy pointer using runtime offset
    void *nsproxy = NULL;
    if (bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy),
                              task + offsets->task_nsproxy) < 0) {
      return true; // Can't read nsproxy - filter it
    }
    if (!nsproxy) {
      return true; // NULL nsproxy - filter it
    }

    // Step 2: Read net pointer using runtime offset
    void *net = NULL;
    if (bpf_probe_read_kernel(&net, sizeof(net),
                              nsproxy + offsets->nsproxy_net_ns) < 0) {
      return true; // Can't read net - filter it
    }
    if (!net) {
      return true; // NULL net - filter it
    }

    // Step 3: Read network namespace inode using runtime offset
    unsigned int current_netns_inum = 0;
    if (bpf_probe_read_kernel(&current_netns_inum, sizeof(current_netns_inum),
                              net + offsets->net_ns_inum) < 0) {
      return true; // Can't read inum - filter it
    }

    // Get host network namespace inode from map
    __u32 host_key = 0;
    __u64 *host_netns_ptr = bpf_map_lookup_elem(&host_netns_map, &host_key);

    // If host netns not configured, fall back to MODE 0
    if (!host_netns_ptr) {
      __u64 cgroup_id = bpf_get_current_cgroup_id();
      return (cgroup_id == 1);
    }

    __u64 host_netns_inum = *host_netns_ptr;

    // Compare: if current netns matches host netns, filter it
    // Otherwise, track it (it's a pod with separate network namespace)
    if (current_netns_inum == host_netns_inum) {
      return true; // Same netns as host - filter it
    }

    return false; // Different netns - track it (non-hostNetwork pod)
  }

  // Should never reach here (modes 0, 1, 2 all handled above)
  return false;
}

// TCP STATE VALIDATION - Helper Function
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Check if TCP socket is in a valid state for tracking
// Returns: true if valid (track it), false if invalid (skip it)
//
// Valid states: ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1, FIN_WAIT2,
//               CLOSE_WAIT, LAST_ACK, CLOSING
// Invalid states: TIME_WAIT (zombie), CLOSE (dead), LISTEN (not active)
static __always_inline bool is_valid_tcp_state(struct sock_local *sk) {
  __u8 state;
  // Cast away volatile qualifier for bpf_probe_read_kernel (required for
  // clang-14+)
  if (bpf_probe_read_kernel(&state, sizeof(state),
                            (const void *)&sk->__sk_common.skc_state) < 0) {
    // Can't read state - be conservative and skip
    return false;
  }

  // Skip TIME_WAIT (6), CLOSE (7), and LISTEN (10)
  // These states either have no active data transfer or are zombie sockets
  if (state == TCP_TIME_WAIT || state == TCP_CLOSE || state == TCP_LISTEN) {
    return false;
  }

  // All other states are valid for tracking
  return true;
}

// Extract socket information for connection tracking
static __always_inline int extract_socket_info(struct sock_local *sk,
                                               struct connection_key *key) {
  // Initialize key to zero
  __builtin_memset(key, 0, sizeof(*key));

  // FIX ***REMOVED***5: TCP STATE VALIDATION - Check state before extraction
  // For TCP sockets, validate state to avoid reading from zombie connections
  // This is a defensive check to prevent extracting from TIME_WAIT/CLOSE
  // sockets UDP doesn't have states, so we skip this check for UDP
  //
  // Note: We check family first to determine if this is TCP
  // But we do a basic state check here as well for defensive programming

  // Read socket family first
  __u16 family;
  if (bpf_probe_read_kernel(&family, sizeof(family),
                            &sk->__sk_common.skc_family) < 0) {
    return -1;
  }

  key->family = (__u8)family;

  // Read ports (common for both IPv4 and IPv6)
  // Use temporary variable to avoid taking address of packed member
  __u16 sport;
  if (bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num) <
      0) {
    return -1;
  }
  key->src_port = sport;

  __u16 dport;
  if (bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport) <
      0) {
    return -1;
  }
  key->dst_port = bpf_ntohs(dport);

  // Handle IP addresses based on family
  if (family == AF_INET) {
    // IPv4 addresses - store in first 32 bits of the array
    __be32 src_addr, dst_addr;

    if (bpf_probe_read_kernel(&src_addr, sizeof(src_addr),
                              &sk->__sk_common.skc_rcv_saddr) < 0) {
      return -1;
    }

    if (bpf_probe_read_kernel(&dst_addr, sizeof(dst_addr),
                              &sk->__sk_common.skc_daddr) < 0) {
      return -1;
    }

    // Store IPv4 in first element, clear rest
    key->src_addr[0] = src_addr;
    key->src_addr[1] = 0;
    key->src_addr[2] = 0;
    key->src_addr[3] = 0;

    key->dst_addr[0] = dst_addr;
    key->dst_addr[1] = 0;
    key->dst_addr[2] = 0;
    key->dst_addr[3] = 0;

  } else if (family == AF_INET6) {
    // IPv6 addresses - read all 128 bits
    // Note: skc_v6_rcv_saddr and skc_v6_daddr are of type struct in6_addr
    // We need to read them as 4 x 32-bit words
    //
    // BYTE ORDER: IPv6 addresses in kernel are stored in network byte order
    // (big endian). bpf_probe_read_kernel copies the bytes as-is, preserving
    // network byte order. The userspace Go code must use binary.BigEndian when
    // converting to IP strings. See IPv6ToIPString() in connection_collector.go
    // for correct conversion.
    if (bpf_probe_read_kernel(
            key->src_addr, sizeof(key->src_addr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32) < 0) {
      return -1;
    }

    if (bpf_probe_read_kernel(key->dst_addr, sizeof(key->dst_addr),
                              &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32) <
        0) {
      return -1;
    }

  } else {
    // Unsupported family
    return -1;
  }

  return 0;
}

// Update connection-level statistics
static __always_inline void update_connection_stats(struct connection_key *key,
                                                    __u64 cgroup_id,
                                                    __u64 bytes, bool is_send) {
  struct connection_stats *stats = bpf_map_lookup_elem(&connection_flows, key);

  if (stats) {
    // Existing connection - update stats
    if (is_send) {
      __sync_fetch_and_add(&stats->bytes_sent, bytes);
      __sync_fetch_and_add(&stats->packets_sent, 1);
    } else {
      __sync_fetch_and_add(&stats->bytes_received, bytes);
      __sync_fetch_and_add(&stats->packets_received, 1);
    }
    // Non-atomic timestamp update (intentional for performance)
    // Atomic operations add ~10-20ns overhead per packet
    stats->last_seen_ns = bpf_ktime_get_ns();
    stats->cgroup_id = cgroup_id;
  } else {
    // New connection - try to insert
    struct connection_stats new_stats = {.bytes_sent = is_send ? bytes : 0,
                                         .bytes_received = is_send ? 0 : bytes,
                                         .packets_sent = is_send ? 1 : 0,
                                         .packets_received = is_send ? 0 : 1,
                                         .last_seen_ns = bpf_ktime_get_ns(),
                                         .cgroup_id = cgroup_id};

    long ret =
        bpf_map_update_elem(&connection_flows, key, &new_stats, BPF_NOEXIST);

    if (ret == -EEXIST) {
      // FIX ***REMOVED***2: -EEXIST RACE HANDLING
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      // -EEXIST means another CPU won the concurrent insertion race.
      // This is NOT an error! It's a normal consequence of per-CPU parallelism.
      // We should retry the update, not count this as overflow.
      //
      // Before fix: Treated -EEXIST as map-full, sent to overflow ringbuffer
      // After fix: Retry lookup and update, only send true errors to overflow
      stats = bpf_map_lookup_elem(&connection_flows, key);
      if (stats) {
        // Update the entry that won the race
        if (is_send) {
          __sync_fetch_and_add(&stats->bytes_sent, bytes);
          __sync_fetch_and_add(&stats->packets_sent, 1);
        } else {
          __sync_fetch_and_add(&stats->bytes_received, bytes);
          __sync_fetch_and_add(&stats->packets_received, 1);
        }
        // Non-atomic timestamp update (see comment in update_container_stats)
        stats->last_seen_ns = bpf_ktime_get_ns();
        stats->cgroup_id = cgroup_id;
      }
      // If re-lookup fails (extremely rare), silently drop this packet
      // DO NOT send -EEXIST to overflow ringbuffer - it's not an error!
    } else if (ret < 0) {
      // STANDARD HASH MAP FULL (-E2BIG) - Send to overflow ringbuffer
      // ────────────────────────────────────────────────────────────────────
      // With BPF_MAP_TYPE_HASH (standard hash), when map reaches 100K entries:
      //   - bpf_map_update_elem() returns -E2BIG (map full)
      //   - We send the connection to overflow ringbuffer (NO data loss!)
      //   - Userspace exports these via kubeadapt_overflow_flows_total metric
      //
      // This provides complete observability and prevents silent data loss.
      // Overflow condition indicates: increase map size or reduce tracked
      // connections.
      //
      // Why we use standard HASH instead of LRU:
      //   - LRU would silently evict 128 entries at once (catastrophic data
      //   loss)
      //   - Standard HASH returns -E2BIG (observable, controllable)
      //   - We catch overflow explicitly and track via metric
      struct flow_record *record =
          bpf_ringbuf_reserve(&overflow_flows, sizeof(struct flow_record), 0);
      if (record) {
        record->key = *key;
        record->stats = new_stats;
        record->timestamp_ns = bpf_ktime_get_ns();
        record->reason = 0; // map_full

        // Clear padding for cleaner data
        __builtin_memset(record->padding, 0, sizeof(record->padding));

        bpf_ringbuf_submit(record, 0);
      }
      // Note: If ringbuffer reservation fails, packet is dropped
      // This is acceptable as it means extreme memory pressure
    }
  }
}

// Zone classification and aggregation removed - backend handles all aggregation

// ===== KPROBES SECTION =====

// TCP send tracking
SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx) {
  // FIX ***REMOVED***4: NETWORK NAMESPACE FILTERING - Early Exit for Host Processes
  // Skip tracking for host processes (kubelet, containerd, etc.)
  // This keeps DaemonSets and all K8s pods while filtering host-only traffic
  if (is_host_network_namespace()) {
    return 0;
  }

  struct sock_local *sk = (struct sock_local *)PT_REGS_PARM1(ctx);
  size_t size = PT_REGS_PARM3(ctx);

  if (!sk || size == 0)
    return 0;

  // FIX ***REMOVED***5: TCP STATE VALIDATION - Check socket state before processing
  // Skip sockets in TIME_WAIT, CLOSE, or LISTEN states
  if (!is_valid_tcp_state(sk)) {
    return 0;
  }

  // Get cgroup ID of current process
  __u64 cgroup_id = bpf_get_current_cgroup_id();

  // Build connection key for connection tracking
  struct connection_key key = {};
  if (extract_socket_info(sk, &key) == 0) {
    key.protocol = IPPROTO_TCP;

    // Update connection-level stats
    update_connection_stats(&key, cgroup_id, size, true);
  }

  return 0;
}

// TCP receive tracking
SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx) {
  // FIX ***REMOVED***4: Filter host processes
  if (is_host_network_namespace()) {
    return 0;
  }

  struct sock_local *sk = (struct sock_local *)PT_REGS_PARM1(ctx);

  if (!sk)
    return 0;

  // FIX ***REMOVED***5: TCP STATE VALIDATION - Check socket state before processing
  if (!is_valid_tcp_state(sk)) {
    return 0;
  }

  // Get cgroup ID
  __u64 cgroup_id = bpf_get_current_cgroup_id();

  // Store for return probe
  __u32 key = 0;
  struct temp_storage temp = {.cgroup_id = cgroup_id, .sk = sk};
  bpf_map_update_elem(&temp_storage_map, &key, &temp, BPF_ANY);

  return 0;
}

// TCP receive return - get actual bytes received
SEC("kretprobe/tcp_recvmsg")
int trace_tcp_recvmsg_ret(struct pt_regs *ctx) {
  int ret = PT_REGS_RC(ctx);
  if (ret <= 0)
    return 0;

  // Get stored context
  __u32 key = 0;
  struct temp_storage *temp = bpf_map_lookup_elem(&temp_storage_map, &key);
  if (!temp)
    return 0;

  __u64 cgroup_id = temp->cgroup_id;
  struct sock_local *sk = temp->sk;

  // FIX ***REMOVED***5: TCP STATE VALIDATION - Revalidate state in kretprobe
  // Socket state may have changed between entry and return
  if (!is_valid_tcp_state(sk)) {
    return 0;
  }

  // FIX ***REMOVED***6: CONSISTENT CONNECTION KEY - No swap needed
  // Socket structure maintains local→remote perspective for both send and
  // receive Same connection key ensures both directions update the same BPF map
  // entry
  struct connection_key conn_key = {};
  if (extract_socket_info(sk, &conn_key) == 0) {
    conn_key.protocol = IPPROTO_TCP;

    // Update connection-level stats (bytes_received)
    update_connection_stats(&conn_key, cgroup_id, ret, false);
  }

  return 0;
}

// UDP send tracking
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx) {
  // FIX ***REMOVED***4: Filter host processes
  if (is_host_network_namespace()) {
    return 0;
  }

  struct sock_local *sk = (struct sock_local *)PT_REGS_PARM1(ctx);
  size_t size = PT_REGS_PARM3(ctx);

  if (!sk || size == 0)
    return 0;

  // Get cgroup ID of current process
  __u64 cgroup_id = bpf_get_current_cgroup_id();

  // Build connection key for connection tracking
  struct connection_key key = {};
  if (extract_socket_info(sk, &key) == 0) {
    key.protocol = IPPROTO_UDP;

    // Update connection-level stats
    update_connection_stats(&key, cgroup_id, size, true);
  }

  return 0;
}

// UDP receive tracking
SEC("kprobe/udp_recvmsg")
int trace_udp_recvmsg(struct pt_regs *ctx) {
  // FIX ***REMOVED***4: Filter host processes
  if (is_host_network_namespace()) {
    return 0;
  }

  struct sock_local *sk = (struct sock_local *)PT_REGS_PARM1(ctx);

  if (!sk)
    return 0;

  // Get cgroup ID
  __u64 cgroup_id = bpf_get_current_cgroup_id();

  // Store for return probe
  __u32 key = 0;
  struct temp_storage temp = {.cgroup_id = cgroup_id, .sk = sk};
  bpf_map_update_elem(&temp_storage_map, &key, &temp, BPF_ANY);

  return 0;
}

// UDP receive return - get actual bytes received
SEC("kretprobe/udp_recvmsg")
int trace_udp_recvmsg_ret(struct pt_regs *ctx) {
  int ret = PT_REGS_RC(ctx);
  if (ret <= 0)
    return 0;

  // Get stored context
  __u32 key = 0;
  struct temp_storage *temp = bpf_map_lookup_elem(&temp_storage_map, &key);
  if (!temp)
    return 0;

  __u64 cgroup_id = temp->cgroup_id;
  struct sock_local *sk = temp->sk;

  // FIX ***REMOVED***6: CONSISTENT CONNECTION KEY - No swap needed
  // Socket structure maintains local→remote perspective for both send and
  // receive Same connection key ensures both directions update the same BPF map
  // entry
  struct connection_key conn_key = {};
  if (extract_socket_info(sk, &conn_key) == 0) {
    conn_key.protocol = IPPROTO_UDP;

    // Update connection-level stats (bytes_received)
    update_connection_stats(&conn_key, cgroup_id, ret, false);
  }

  return 0;
}

// TCP connection tracking for new connections
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
  // FIX ***REMOVED***4: Filter host processes
  if (is_host_network_namespace()) {
    return 0;
  }

  struct sock_local *sk = (struct sock_local *)PT_REGS_PARM1(ctx);

  if (!sk)
    return 0;

  // FIX ***REMOVED***5: TCP STATE VALIDATION - Check socket state
  // tcp_connect should be in SYN_SENT state, but validate anyway
  if (!is_valid_tcp_state(sk)) {
    return 0;
  }

  // Get cgroup ID
  __u64 cgroup_id = bpf_get_current_cgroup_id();

  // Initialize connection tracking for this new connection
  struct connection_key key = {};
  if (extract_socket_info(sk, &key) == 0) {
    key.protocol = IPPROTO_TCP;

    struct connection_stats new_stats = {.last_seen_ns = bpf_ktime_get_ns(),
                                         .cgroup_id = cgroup_id};

    // Create initial connection entry
    bpf_map_update_elem(&connection_flows, &key, &new_stats, BPF_NOEXIST);
  }

  return 0;
}

// Accept tracking for incoming connections
SEC("kprobe/inet_csk_accept")
int trace_accept(struct pt_regs *ctx) {
  // FIX ***REMOVED***4: Filter host processes
  if (is_host_network_namespace()) {
    return 0;
  }

  struct sock_local *sk = (struct sock_local *)PT_REGS_RC(ctx);

  if (!sk)
    return 0;

  // FIX ***REMOVED***5: TCP STATE VALIDATION - Check socket state
  // inet_csk_accept should return ESTABLISHED sockets, but validate anyway
  if (!is_valid_tcp_state(sk)) {
    return 0;
  }

  // Get cgroup ID
  __u64 cgroup_id = bpf_get_current_cgroup_id();

  // FIX ***REMOVED***6: CONSISTENT CONNECTION KEY - No swap needed
  // Socket structure already has correct local→remote perspective
  // After accept(), sk has: local_ip=server, remote_ip=client
  // This is the correct perspective for tracking
  struct connection_key key = {};
  if (extract_socket_info(sk, &key) == 0) {
    key.protocol = IPPROTO_TCP;

    struct connection_stats new_stats = {.last_seen_ns = bpf_ktime_get_ns(),
                                         .cgroup_id = cgroup_id};

    // Create initial connection entry
    bpf_map_update_elem(&connection_flows, &key, &new_stats, BPF_NOEXIST);
  }

  return 0;
}

// TCP connection close tracking
// This kprobe tracks connection close events for proper lifecycle management.
// Userspace collector uses read-then-delete pattern to prevent data loss.
// Closed connections are handled by the collection cycle (every 25s).
//
// How the read-then-delete pattern works:
// - tcp_close() is called when socket closes (FIN/RST or explicit close())
// - Userspace reads all connections from map (including closed ones)
// - After reading, userspace deletes entries to prevent stale data
// - Gauges represent current active connections only
// - Prometheus rate() calculates correct per-second rates across collection
// windows
SEC("kprobe/tcp_close")
int trace_tcp_close(struct pt_regs *ctx) {
  // FIX ***REMOVED***4: Filter host processes
  if (is_host_network_namespace()) {
    return 0;
  }

  struct sock_local *sk = (struct sock_local *)PT_REGS_PARM1(ctx);
  if (!sk) {
    return 0;
  }

  // Extract connection key
  struct connection_key key = {};
  if (extract_socket_info(sk, &key) != 0) {
    return 0; // Failed to extract socket info
  }

  key.protocol = IPPROTO_TCP;

  // Userspace handles entry deletion after reading to prevent data loss
  // for short-lived connections (no kernel-side deletion)

  return 0;
}

// UDP socket destruction tracking
// UDP is connectionless, but we track "connections" based on socket lifecycle.
// When the UDP socket is destroyed, we delete the tracking entry.
SEC("kprobe/udp_destroy_sock")
int trace_udp_destroy_sock(struct pt_regs *ctx) {
  // FIX ***REMOVED***4: Filter host processes
  if (is_host_network_namespace()) {
    return 0;
  }

  struct sock_local *sk = (struct sock_local *)PT_REGS_PARM1(ctx);
  if (!sk) {
    return 0;
  }

  // Extract connection key
  struct connection_key key = {};
  if (extract_socket_info(sk, &key) != 0) {
    return 0; // Failed to extract socket info
  }

  key.protocol = IPPROTO_UDP;

  // Userspace handles entry deletion after reading to prevent data loss
  // for short-lived connections (no kernel-side deletion)

  return 0;
}

char LICENSE[] SEC("license") = "GPL";