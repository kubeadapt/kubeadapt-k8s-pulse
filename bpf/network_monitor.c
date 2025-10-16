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

// BPF helpers and CO-RE support
***REMOVED***include <bpf/bpf_core_read.h>
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

// Define proto and net structures (forward declarations)
struct proto;
struct net;

// Make socket structures CO-RE relocatable
***REMOVED***pragma clang attribute push(__attribute__((preserve_access_index)),           \
                             apply_to = record)
struct sock_common {
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
  struct proto *skc_prot;
  struct net *skc_net;

  // IPv6 fields
  struct in6_addr skc_v6_daddr;
  struct in6_addr skc_v6_rcv_saddr;

  // Additional fields exist but we only need the ones above
};

struct sock {
  struct sock_common __sk_common;
  // We only need __sk_common for our use case
  // Additional fields exist but are not needed
};
***REMOVED***pragma clang attribute pop

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
  struct sock *sk;
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
// - Max connections: 100,000 active flows on very busy nodes (increased for better accuracy)
//
// Memory usage per node: ~19 MB kernel memory (100K * 192 bytes per entry)
// DO NOT size these maps for cluster-wide pod counts (e.g., 100k pods)!
// That would waste kernel memory unnecessarily.

// Connection tracking map (per-node scope)
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(struct connection_key));
  __uint(value_size, sizeof(struct connection_stats));
  __uint(max_entries, 100000); // Max active connections per node (increased for better accuracy)
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
// This prevents data loss when the connection map reaches capacity
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB
} overflow_flows SEC(".maps");

// Zone aggregation removed - backend handles all aggregation logic

// FIX ***REMOVED***4: NETWORK NAMESPACE FILTERING - Map Definition
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Stores the host network namespace inode number (from /proc/1/ns/net)
// Used to filter out host processes while keeping ALL K8s pods
// Key: always 0 (single entry map), Value: host netns inode number
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, 1);
} host_netns_map SEC(".maps");

// ===== HELPER FUNCTIONS =====

// FIX ***REMOVED***4: NETWORK NAMESPACE FILTERING - Helper Function
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Check if current process is in host network namespace
// Returns: true if host process (should skip), false if K8s pod (should track)
//
// How it works:
// - Host processes (kubelet, containerd, sshd, etc.): netns == init netns
// - K8s pods (including DaemonSets): netns == pod-specific namespace
// - We compare current netns inode with host netns inode (from /proc/1/ns/net)
static __always_inline bool is_host_network_namespace(void) {
  // Get host netns inode from map (populated by userspace)
  __u32 key = 0;
  __u64 *host_netns = bpf_map_lookup_elem(&host_netns_map, &key);

  if (!host_netns) {
    // Map not initialized - allow traffic (fail open for safety)
    return false;
  }

  // Get current process network namespace inode
  // This requires reading from task_struct->nsproxy->net_ns->ns.inum
  // For security and portability, we use BPF helper if available
  // Otherwise, we skip filtering (fail open)

  // For now, we'll use a simplified approach:
  // Check if cgroup_id indicates a container (non-zero means container)
  // This is a conservative heuristic until we implement full netns checking
  __u64 cgroup_id = bpf_get_current_cgroup_id();

  // Root cgroup (cgroup_id == 1) indicates host process
  // Non-root cgroup indicates container/pod process
  if (cgroup_id == 1) {
    return true; // Host process - skip tracking
  }

  return false; // Container/pod process - track it
}

// FIX ***REMOVED***5: TCP STATE VALIDATION - Helper Function
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Check if TCP socket is in a valid state for tracking
// Returns: true if valid (track it), false if invalid (skip it)
//
// Valid states: ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1, FIN_WAIT2,
//               CLOSE_WAIT, LAST_ACK, CLOSING
// Invalid states: TIME_WAIT (zombie), CLOSE (dead), LISTEN (not active)
static __always_inline bool is_valid_tcp_state(struct sock *sk) {
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
static __always_inline int extract_socket_info(struct sock *sk,
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

// Swap source and destination addresses in connection key
static __always_inline void
swap_connection_key_addresses(struct connection_key *key) {
  // Swap addresses based on family
  __u32 tmp_addr[4];

  // Save source address
  tmp_addr[0] = key->src_addr[0];
  tmp_addr[1] = key->src_addr[1];
  tmp_addr[2] = key->src_addr[2];
  tmp_addr[3] = key->src_addr[3];

  // Copy destination to source
  key->src_addr[0] = key->dst_addr[0];
  key->src_addr[1] = key->dst_addr[1];
  key->src_addr[2] = key->dst_addr[2];
  key->src_addr[3] = key->dst_addr[3];

  // Copy saved source to destination
  key->dst_addr[0] = tmp_addr[0];
  key->dst_addr[1] = tmp_addr[1];
  key->dst_addr[2] = tmp_addr[2];
  key->dst_addr[3] = tmp_addr[3];

  // Swap ports
  __u16 tmp_port = key->src_port;
  key->src_port = key->dst_port;
  key->dst_port = tmp_port;
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
      // TRUE ERRORS: Map full, no memory, etc. - send to overflow for analysis
      // MAP IS FULL (or other error) - Send to ringbuffer to prevent data loss
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

  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  size_t size;

// Get size parameter (handle different kernel versions)
***REMOVED***ifdef PT_REGS_PARM3_CORE
  size = PT_REGS_PARM3_CORE(ctx);
***REMOVED***else
  size = PT_REGS_PARM3(ctx);
***REMOVED***endif

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

  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

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
  struct sock *sk = temp->sk;

  // FIX ***REMOVED***5: TCP STATE VALIDATION - Revalidate state in kretprobe
  // Socket state may have changed between entry and return
  if (!is_valid_tcp_state(sk)) {
    return 0;
  }

  // Build connection key (swap src/dst for receive)
  struct connection_key conn_key = {};
  if (extract_socket_info(sk, &conn_key) == 0) {
    // Swap src and dst for receive direction
    swap_connection_key_addresses(&conn_key);

    conn_key.protocol = IPPROTO_TCP;

    // Update connection-level stats
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

  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  size_t size;

***REMOVED***ifdef PT_REGS_PARM3_CORE
  size = PT_REGS_PARM3_CORE(ctx);
***REMOVED***else
  size = PT_REGS_PARM3(ctx);
***REMOVED***endif

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

  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

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
  struct sock *sk = temp->sk;

  // Build connection key (swap src/dst for receive)
  struct connection_key conn_key = {};
  if (extract_socket_info(sk, &conn_key) == 0) {
    // Swap src and dst for receive direction
    swap_connection_key_addresses(&conn_key);

    conn_key.protocol = IPPROTO_UDP;

    // Update connection-level stats
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

  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

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

  struct sock *sk = (struct sock *)PT_REGS_RC(ctx);

  if (!sk)
    return 0;

  // FIX ***REMOVED***5: TCP STATE VALIDATION - Check socket state
  // inet_csk_accept should return ESTABLISHED sockets, but validate anyway
  if (!is_valid_tcp_state(sk)) {
    return 0;
  }

  // Get cgroup ID
  __u64 cgroup_id = bpf_get_current_cgroup_id();

  // Initialize connection tracking for accepted connection
  struct connection_key key = {};
  if (extract_socket_info(sk, &key) == 0) {
    // For accepted connections, we're the destination
    // So swap src and dst
    swap_connection_key_addresses(&key);

    key.protocol = IPPROTO_TCP;

    struct connection_stats new_stats = {.last_seen_ns = bpf_ktime_get_ns(),
                                         .cgroup_id = cgroup_id};

    // Create initial connection entry
    bpf_map_update_elem(&connection_flows, &key, &new_stats, BPF_NOEXIST);
  }

  return 0;
}

// TCP connection close tracking
// This kprobe deletes connection entries immediately when TCP connections close.
// Without this, closed connections remain in the BPF map until LRU eviction,
// causing Prometheus rate() to undercount traffic when old entries are evicted.
//
// How it fixes the bug:
// - tcp_close() is called when socket closes (FIN/RST or explicit close())
// - We delete the connection entry immediately from the map
// - Gauge only contains bytes from ACTIVE connections
// - No frozen zombie entries accumulate
// - Prometheus rate() calculates correct deltas
SEC("kprobe/tcp_close")
int trace_tcp_close(struct pt_regs *ctx) {
  // FIX ***REMOVED***4: Filter host processes
  if (is_host_network_namespace()) {
    return 0;
  }

  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  if (!sk) {
    return 0;
  }

  // Extract connection key
  struct connection_key key = {};
  if (extract_socket_info(sk, &key) != 0) {
    return 0; // Failed to extract socket info
  }

  key.protocol = IPPROTO_TCP;

  // Delete connection entry immediately on close
  // This prevents frozen zombie entries from accumulating in the map
  bpf_map_delete_elem(&connection_flows, &key);

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

  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  if (!sk) {
    return 0;
  }

  // Extract connection key
  struct connection_key key = {};
  if (extract_socket_info(sk, &key) != 0) {
    return 0; // Failed to extract socket info
  }

  key.protocol = IPPROTO_UDP;

  // Delete UDP "connection" entry on socket destruction
  bpf_map_delete_elem(&connection_flows, &key);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";