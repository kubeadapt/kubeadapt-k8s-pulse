// Package bpf contains the eBPF program generation setup
package bpf

// This file contains go:generate directives to compile eBPF programs
// The bpf2go tool will generate Go bindings from the C source files
//
// IMPORTANT: This directive is ONLY used when you manually run `make generate`
// It is NOT automatically triggered during normal builds to avoid slow compilation
//
// Production compilation flags (optimized for performance):
// - O2: Optimize for performance
// - Wall: Enable all warnings
// - Werror: Treat warnings as errors
// - NO debug symbols (-g): Faster compilation, smaller binaries
// - NO -no-strip: Allow stripping for smaller binaries

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.19.0 -cc clang -cflags "-O2 -Wall -Werror" -target amd64,arm64 network ../../bpf/network_monitor_tc.c -- -I../../bpf/headers

// The above directive will generate:
// - network_x86_bpfel.go and network_x86_bpfel.o (amd64 little-endian)
// - network_arm64_bpfel.go and network_arm64_bpfel.o (arm64 little-endian)
//
// These files contain:
// - Go structs matching the C structs defined in the BPF programs
// - Functions to load the compiled BPF bytecode (embedded .o files)
// - Type-safe accessors for BPF maps and programs
//
// The .o files are embedded in the Go binary via go:embed directives
// This means you DON'T need to recompile BPF on every build - only when C code changes
//
// Usage:
// Run `make generate` to compile the BPF programs and generate Go bindings.
// On macOS, this will automatically use Docker for compilation.
// On Linux, it will use the native clang compiler.
//
// NEVER run `go generate ./...` directly - use `make generate` instead
