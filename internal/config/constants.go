package config

import "time"

// Network namespace filter modes
// These constants define how the eBPF agent filters network traffic
const (
	// NetnsFilterModeDefault tracks all Kubernetes pods (including hostNetwork:true)
	// Filters only host system processes (kubelet, containerd, sshd)
	// Uses simple cgroup check (cgroup_id != 1)
	// RECOMMENDED for most use cases
	NetnsFilterModeDefault = "default"

	// NetnsFilterModeStrict tracks only pods with separate network namespaces
	// Filters host processes AND hostNetwork:true pods
	// Uses BTF runtime offset detection for network namespace comparison
	// Use when you want to exclude hostNetwork pods from tracking
	NetnsFilterModeStrict = "strict"

	// NetnsFilterModeDisabled tracks everything (no filtering at all)
	// Useful for debugging - shows all network activity including host processes
	NetnsFilterModeDisabled = "disabled"
)

// Default port configurations
const (
	// DefaultMetricsPort is the HTTP port for Prometheus metrics and health checks
	DefaultMetricsPort = 9090

	// DefaultProfilingPort is the HTTP port for pprof profiling endpoints
	DefaultProfilingPort = 6060
)

// Collection timing configuration
const (
	// DefaultCollectionInterval is the interval between BPF map reads
	// CRITICAL: Must be SHORTER than Prometheus scrape interval to ensure
	// only ONE collection happens between scrapes (prevents gauge overwrites)
	//
	// Default 25s assumes 30s Prometheus scrape interval (5s safety buffer)
	// Adjust based on your Prometheus configuration:
	//   - For 60s scrapes: use 55s
	//   - For 15s scrapes: use 12s
	//
	// Rule: collection_interval = scrape_interval - 5s buffer
	DefaultCollectionInterval = 25 * time.Second

	// DefaultDumpMapInterval is the interval for dumping BPF maps (debug mode)
	// CRITICAL: Must be < CollectionInterval to see data before deletion
	// 15s allows 1-2 dumps per 25s collection cycle, showing live data
	//
	// Timeline example:
	//   - Collection at: 0s, 25s, 50s (reads + deletes map)
	//   - Dumps at: 0s, 15s, 30s, 45s (dumps at 15s/45s show data)
	DefaultDumpMapInterval = 15 * time.Second
)

// Log format constants
const (
	// LogFormatJSON outputs structured JSON logs for production
	LogFormatJSON = "json"

	// LogFormatConsole outputs human-readable console logs for development
	LogFormatConsole = "console"
)

// Boolean string representations for environment variable parsing
const (
	BoolStringTrue = "true"
	BoolStringOne  = "1"
)

// BPF verifier configuration
const (
	// BPFVerifierLogLevel sets the eBPF verifier log verbosity
	// Level 2 = Info (shows program loading details without excessive output)
	// Used by cilium/ebpf when loading BPF programs
	BPFVerifierLogLevel = 2

	// BPFVerifierLogSize is the buffer size for eBPF verifier logs
	// 64KB is sufficient for most programs (verifier outputs detailed info)
	// Increase if you see truncated verifier errors during development
	BPFVerifierLogSize = 64 * 1024 // 64KB
)

// Default paths
const (
	// DefaultProcPath is the path to host /proc filesystem
	// In DaemonSet: host /proc is mounted at /host/proc
	// In development: direct /proc access
	DefaultProcPath = "/host/proc"
)
