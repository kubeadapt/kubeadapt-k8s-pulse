// Package bpf contains the eBPF program generation setup
package bpf

// This file contains go:generate directives to compile eBPF programs
// The bpf2go tool will generate Go bindings from the C source files

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.11.0 -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 -type container_net_stats,connection_key,connection_stats network ../../bpf/network_monitor.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.11.0 -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 -type connection_key,connection_stats connection ../../bpf/connection_tracker.c

// The above directives will generate:
// - network_bpfel.go and network_bpfeb.go for network_monitor.c
// - connection_bpfel.go and connection_bpfeb.go for connection_tracker.c
//
// These files contain:
// - Go structs matching the C structs defined in the BPF programs
// - Functions to load the compiled BPF bytecode
// - Type-safe accessors for BPF maps and programs
//
// The generated files are architecture-specific:
// - *_bpfel.go for little-endian architectures (amd64, arm64)
// - *_bpfeb.go for big-endian architectures (if needed)
//
// Usage:
// Run `make generate` to compile the BPF programs and generate Go bindings.
// On macOS, this will automatically use Docker for compilation.
// On Linux, it will use the native clang compiler.