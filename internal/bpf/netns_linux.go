//go:build linux

package bpf

// NOTE: Network namespace filtering has been removed from the eBPF agent.
// The eBPF agent collects ALL network traffic without filtering.
// Filtering is needs to be performed in external integration
