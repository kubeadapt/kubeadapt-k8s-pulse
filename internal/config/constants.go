package config

import "time"

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
	DefaultCollectionInterval = 25 * time.Second
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
