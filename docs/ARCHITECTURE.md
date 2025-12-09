***REMOVED*** Architecture Documentation

This document provides detailed technical architecture information for the KubeAdapt eBPF Network Metrics Agent.

***REMOVED******REMOVED*** High-Level Architecture

```mermaid
graph TB
    subgraph "Kubernetes Node"
        subgraph "Kernel Space (eBPF)"
            TC_HOOKS["TC Hooks (EGRESS ONLY)<br/>━━━━━━━━━━━━━━━━<br/>- tc_egress (packets out)<br/>- No ingress hooks<br/><br/>Prevents double-counting:<br/>- Same-node Pod-to-Pod<br/>- Cross-node traffic"]

            MAPS["BPF Maps<br/>━━━━━━━━━━━━━━━━<br/>connection_flows (HASH)<br/>overflow_events (RINGBUF)<br/>host_netns_map (filtering)"]

            OVERFLOW["Overflow Handling<br/>━━━━━━━━━━━━━━━━<br/>Ringbuffer at capacity"]
        end

        subgraph "User Space (Agent)"
            COLLECTOR["Connection Collector<br/>━━━━━━━━━━━━━━━━<br/>Reads map every 25s<br/>Aggregates by IP pair<br/>Deletes after read"]

            METRICS["Prometheus Exporter<br/>━━━━━━━━━━━━━━━━<br/>:9090/metrics<br/>Gauges (cumulative)<br/>rate() in Prometheus"]
        end

        POD1["Pod A<br/>10.244.1.5"]
        POD2["Pod B<br/>10.244.1.6"]
    end

    subgraph "Monitoring"
        PROM["Prometheus<br/>━━━━━━━━━━━━━━━━<br/>Scrapes every 30s<br/>Stores time series"]
    end

    POD1 -.->|"TCP/UDP traffic"| POD2
    POD1 --> TC_HOOKS
    POD2 --> TC_HOOKS

    TC_HOOKS -->|"Update stats"| MAPS
    MAPS -->|"Map full"| OVERFLOW

    MAPS -->|"Read (25s)"| COLLECTOR
    COLLECTOR -->|"Delete after read"| MAPS
    COLLECTOR -->|"Export Gauges"| METRICS
    METRICS -->|"Scrape (30s)"| PROM

    style TC_HOOKS fill:***REMOVED***c0392b,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
    style MAPS fill:***REMOVED***16a085,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
    style COLLECTOR fill:***REMOVED***2980b9,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
    style METRICS fill:***REMOVED***27ae60,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
    style PROM fill:***REMOVED***f39c12,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
```

***REMOVED******REMOVED*** Low-Level eBPF Architecture

```mermaid
graph TB
    subgraph "Network Traffic Flow"
        NET_IF["Network Interface<br/>(veth*, eth0)"]
    end

    subgraph "Kernel Space - TC eBPF Programs"
        direction TB

        subgraph "TC Hook Points (EGRESS ONLY)"
            TC_OUT["tc_egress<br/>━━━━━━━━━━<br/>Packets leaving interface<br/>Parse headers<br/>Update connection stats<br/><br/>- No ingress hook<br/>- Prevents double-count"]
        end

        subgraph "BPF Maps"
            direction LR
            CONN_MAP["connection_flows<br/>━━━━━━━━━━<br/>HASH"]

            OVERFLOW["overflow_events<br/>━━━━━━━━━━<br/>RINGBUF"]

            NETNS["host_netns_map<br/>━━━━━━━━━━<br/>ARRAY<br/>1 entry"]

            FILTER["filter_mode_map<br/>━━━━━━━━━━<br/>ARRAY<br/>1 entry"]
        end
    end

    subgraph "Userspace Collector"
        READ["Read map (25s)"]
        AGG["Aggregate by IP"]
        EXPORT["Export Gauges"]
    end

    NET_IF -->|"Egress Only"| TC_OUT

    TC_OUT --> CONN_MAP

    CONN_MAP -->|"Map full"| OVERFLOW

    CONN_MAP --> READ
    READ --> AGG
    AGG --> EXPORT

    style TC_OUT fill:***REMOVED***c0392b,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
    style CONN_MAP fill:***REMOVED***16a085,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
    style OVERFLOW fill:***REMOVED***8e44ad,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
    style READ fill:***REMOVED***2980b9,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
    style AGG fill:***REMOVED***2980b9,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
    style EXPORT fill:***REMOVED***27ae60,stroke:***REMOVED***333,stroke-width:2px,color:***REMOVED***fff
```

***REMOVED******REMOVED*** Data Flow & Metric Export

***REMOVED******REMOVED******REMOVED*** Metrics Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        METRICS ARCHITECTURE                     │
└─────────────────────────────────────────────────────────────────┘

BPF Kernel Maps         Userspace Collector      Prometheus Server
─────────────────       ───────────────────      ─────────────────

┌──────────────┐        ┌───────────────┐        ┌──────────────┐
│ connection_  │        │ Connection    │        │ Prometheus   │
│ flows        │───────>│ Collector     │        │ Server       │
│ (HASH map)   │  Read  │               │        │              │
│              │  Every │ - Reads map   │        │ HTTP GET     │
│ Cumulative   │  25s   │ - Aggregates  │<───────┤ /metrics     │
│ byte/packet  │        │ - Deletes     │ Scrape │ Every 30s    │
│ counters     │        │               │        │              │
└──────────────┘        │ Updates       │        └──────────────┘
                        │ Prometheus    │               │
┌──────────────┐        │ Registry      │               │
│ overflow_    │        │ (in-memory)   │               │
│ events       │───────>│               │               ▼
│ (ringbuffer) │ Events │ Gauges/       │        ┌──────────────┐
│              │        │ Counters      │        │ Time Series  │
└──────────────┘        └───────┬───────┘        │ Database     │
                                │                │ (TSDB)       │
                                │                └──────────────┘
                                ▼
                        ┌───────────────┐
                        │ /metrics      │
                        │ HTTP Endpoint │
                        │               │
                        │ Exposes text  │
                        │ format for    │
                        │ scraping      │
                        └───────────────┘
```

***REMOVED******REMOVED******REMOVED*** Connection Tracking Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: Packet Arrives at Network Interface                 │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│ TC hook (tc_egress ONLY) attached to interface             │
│ → Parse Ethernet + IP + TCP/UDP headers                    │
│ → Extract 5-tuple: src_ip, dst_ip, src_port, dst_port, proto│
│ → Get packet size (IP header + payload)                    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 2: Traffic Tracked (Kernel Accumulation - EGRESS ONLY) │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│ tc_egress: Packet leaving interface (1000 bytes)           │
│ → Lookup connection in map                                  │
│ → Check if same interface (IfIndexFirstSeen dedup)         │
│ → __sync_fetch_and_add(&stats->bytes, 1000)               │
│ → __sync_fetch_and_add(&stats->packets, 1)                │
│ → stats->last_seen_ns = now()                              │
│                                                             │
│ NOTE: Kernel maintains cumulative counters (never reset)   │
│ NOTE: Egress-only prevents same-node & cross-node 2x count │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 3: Userspace Collection (Every 25s)                    │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│ Iterate connection_flows map:                               │
│   Key: {10.244.1.5:45678 → 10.244.1.6:80, TCP}            │
│   Stats: {bytes: 5000, packets: 5} (egress only)           │
│                                                             │
│ Aggregate by (src_ip, dst_ip, protocol):                   │
│   Remove ports → (10.244.1.5, 10.244.1.6, TCP)            │
│   Sum all connections with same IPs                        │
│                                                             │
│ Export Counter (cumulative - egress only):                 │
│   kubeadapt_connection_traffic_bytes_total{                │
│     src_ip="10.244.1.5",                                   │
│     dst_ip="10.244.1.6",                                   │
│     protocol="tcp",                                        │
│     daemonset_pod_uid="abc-123-def",                       │
│     daemonset_node_name="worker-1"                         │
│   } = 5000                                                  │
│                                                             │
│ DELETE entry from BPF map (read-then-delete pattern)       │
│ → Prevents data loss for short-lived connections           │
│ → Map cleared every 25s (fresh window)                     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Step 4: Next Window (25s Later)                             │
│ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│ If connection still active:                                 │
│ → New accumulation starts (bytes reset to 0 in map)        │
│ → Prometheus sees new window with fresh byte counts        │
│                                                             │
│ If connection closed before collection:                     │
│ → Entry was already in map during last collection          │
│ → Data was captured (no loss)                              │
│ → Next collection: entry not present (window ended)        │
│                                                             │
│ Prometheus rate() calculation:                             │
│ → Calculates per-second rate across windows                │
│ → Handles window transitions automatically                 │
└─────────────────────────────────────────────────────────────┘
```

***REMOVED******REMOVED*** Counter Metrics with Read-Then-Delete Pattern

The agent uses **Prometheus Counters** to export cumulative byte/packet metrics. This design combines kernel-side accumulation with userspace delta reporting.

***REMOVED******REMOVED******REMOVED*** Kernel-Side Accounting (Cumulative Counters)

- eBPF programs maintain **cumulative counters** in kernel space using atomic operations (`__sync_fetch_and_add`)
- Each connection tracks total bytes/packets sent since connection creation
- Kernel state accumulates until entry is read and deleted (read-then-delete pattern)

***REMOVED******REMOVED******REMOVED*** Userspace Exports Deltas (Counters)

- The collector reads BPF maps every 25 seconds and extracts **delta values** for each connection
- After reading, entries are **deleted from the map** (read-then-delete pattern)
- Deltas are added to Prometheus Counters using `.Add(delta)`
- Prometheus Counter maintains cumulative state automatically

***REMOVED******REMOVED******REMOVED*** Why Counters (Not Gauges)?

```go
// Counter approach (current implementation):
delta := kernelCumulativeValue  // Read from BPF map
counterMetric.Add(delta)        // Prometheus maintains cumulative state
// Delete entry from BPF map (map cleared every 25s)
```

**Advantages of Counters:**
- **Correct semantics**: Counters are monotonically increasing (matches intent)
- **Built-in reset handling**: Prometheus automatically handles Counter resets
- **No userspace state**: BPF map is cleared each cycle (no persistent state)
- **PromQL compatibility**: `rate()` and `increase()` functions designed for Counters

***REMOVED******REMOVED******REMOVED*** Prometheus Rate Calculation

```
Time Series Example (25s Collection Windows):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
t=0s:   Collection ***REMOVED***1 reads map
        Connection active, accumulated 5000 bytes → Gauge = 5000
        Entry DELETED from map after read

t=25s:  Collection ***REMOVED***2 reads map
        Connection still active, accumulated 4000 bytes (new window) → Gauge = 4000
        Entry DELETED from map after read

t=50s:  Collection ***REMOVED***3 reads map
        Connection closed before this collection
        Entry not in map → Gauge drops (no value exported)

t=75s:  Collection ***REMOVED***4 reads map
        No connection → No metric exported

Prometheus Query: rate(kubeadapt_connection_traffic_bytes_total[1m])
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
t=0-25s:  5000 bytes / 25s = 200 bytes/sec
t=25-50s: 4000 bytes / 25s = 160 bytes/sec
t=50s+:   Connection ended, rate drops to 0

✅ Windowed collection - each window is independent
✅ No data loss for short-lived connections (captured in window)
✅ Read-then-delete pattern prevents race conditions
✅ Prometheus handles window transitions automatically
```

***REMOVED******REMOVED******REMOVED*** Real-World Example

```
Kernel BPF Map (cumulative within window):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
t=0-25s:  Connection active
          BPF map: bytes = 5000 (accumulated over 25s)
          Collection reads 5000 → Counter.Add(5000)
          Entry DELETED from map

t=25-50s: Connection still active
          BPF map: bytes = 3000 (new window, fresh accumulation)
          Collection reads 3000 → Counter.Add(3000)
          Entry DELETED from map

t=50s+:   Connection closed
          Entry not in map → No update

Prometheus Counter State:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
After t=25s:  counter_total = 5000
After t=50s:  counter_total = 8000 (5000 + 3000)
After t=75s:  counter_total = 8000 (no change)

PromQL rate() Calculation:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
rate(counter_total[1m]) at t=50s = (8000 - 5000) / 25s = 120 bytes/sec
```

***REMOVED******REMOVED*** References

- [Linux Kernel TC Documentation](https://www.kernel.org/doc/html/latest/networking/filter.html)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [Cilium eBPF Library Documentation](https://pkg.go.dev/github.com/cilium/ebpf)
